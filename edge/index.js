// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Ryan Wallace
// This file is part of the TokenDNA edge layer and is separately licensed
// under the MIT License (see edge/LICENSE-MIT).  The core TokenDNA platform
// (../LICENSE) is licensed under the Business Source License 1.1.
/**
 * TokenDNA — Cloudflare Worker: Edge Authentication Layer
 *
 * Validates every inbound request at the CDN edge before it reaches the
 * backend.  Enforces:
 *
 *   1. JWT signature verification  (RS256 via JWKS endpoint)
 *   2. JWT expiry check
 *   3. Token revocation check      (Cloudflare KV)
 *   4. DPoP proof validation       (RFC 9449)
 *      - Verifies DPoP JWT signature using the embedded public key
 *      - Checks htm  (HTTP method) matches current request
 *      - Checks htu  (HTTP URI)    matches current request
 *      - Checks iat  (issued-at)   within ±30 second window
 *      - Checks ath  (access token hash) = BASE64URL(SHA-256(access_token))
 *      - Prevents replay via jti uniqueness (KV-backed nonce store)
 *   5. ML risk score check         (calls backend /ml-score)
 *   6. Token auto-revocation       (if backend says mlScore.revoke=true)
 *
 * Environment bindings (set via wrangler.toml / wrangler secret put):
 *   TOKEN_CACHE           KV namespace   — revocation list + DPoP nonces
 *   BACKEND_API           var            — base URL of TokenDNA backend
 *   JWKS_URL              var            — OIDC JWKS endpoint
 */

const TOKEN_KV = TOKEN_CACHE;

// ── Crypto helpers ────────────────────────────────────────────────────────────

/**
 * Decode a base64url string to an ArrayBuffer.
 */
function b64url_decode(str) {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/');
  const binary  = atob(padded);
  const bytes   = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

/**
 * Encode an ArrayBuffer to a base64url string.
 */
function b64url_encode(buf) {
  const bytes = new Uint8Array(buf);
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Safely parse a JWT without verification. Returns {header, payload} or null.
 */
function parse_jwt(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const header  = JSON.parse(new TextDecoder().decode(b64url_decode(parts[0])));
    const payload = JSON.parse(new TextDecoder().decode(b64url_decode(parts[1])));
    return { header, payload, parts };
  } catch {
    return null;
  }
}

/**
 * Import an RSA public key from a JWK object for RS256 verification.
 */
async function import_rsa_key(jwk) {
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify'],
  );
}

/**
 * Import an EC public key from a JWK (for DPoP — typically ES256).
 */
async function import_ec_key(jwk) {
  const algo = jwk.crv === 'P-384'
    ? { name: 'ECDSA', namedCurve: 'P-384' }
    : { name: 'ECDSA', namedCurve: 'P-256' };
  return crypto.subtle.importKey('jwk', jwk, algo, false, ['verify']);
}

/**
 * Verify a JWT's RS256 signature given a JWK public key.
 * Returns the payload if valid, null otherwise.
 */
async function verify_rs256(token, jwk) {
  try {
    const parsed = parse_jwt(token);
    if (!parsed) return null;
    const { parts } = parsed;
    const key = await import_rsa_key(jwk);
    const data = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
    const sig  = b64url_decode(parts[2]);
    const ok   = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sig, data);
    return ok ? parsed.payload : null;
  } catch {
    return null;
  }
}

/**
 * Verify a DPoP JWT's ECDSA or RSA signature using the JWK embedded
 * in the DPoP header's `jwk` field.
 * Returns the payload if valid, null otherwise.
 */
async function verify_dpop_sig(dpop_token) {
  try {
    const parsed = parse_jwt(dpop_token);
    if (!parsed) return null;
    const { header, parts } = parsed;

    const jwk = header.jwk;
    if (!jwk) return null;

    let key;
    if (jwk.kty === 'EC') {
      key = await import_ec_key(jwk);
    } else if (jwk.kty === 'RSA') {
      key = await import_rsa_key(jwk);
    } else {
      return null;
    }

    const hash_name = header.alg === 'ES384' ? 'SHA-384' : 'SHA-256';
    const algo      = jwk.kty === 'EC'
      ? { name: 'ECDSA', hash: hash_name }
      : 'RSASSA-PKCS1-v1_5';

    const data = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
    const sig  = b64url_decode(parts[2]);
    const ok   = await crypto.subtle.verify(algo, key, sig, data);
    return ok ? parsed.payload : null;
  } catch {
    return null;
  }
}

/**
 * Compute BASE64URL(SHA-256(ascii_string)).
 */
async function sha256_b64url(str) {
  const data   = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return b64url_encode(digest);
}

// ── JWKS cache ────────────────────────────────────────────────────────────────

let _jwks_cache = null;
let _jwks_fetched_at = 0;
const JWKS_TTL_MS = 3_600_000; // 1 hour

async function get_jwks() {
  const now = Date.now();
  if (_jwks_cache && (now - _jwks_fetched_at) < JWKS_TTL_MS) return _jwks_cache;
  const resp = await fetch(JWKS_URL, { cf: { cacheTtl: 3600, cacheEverything: true } });
  if (!resp.ok) throw new Error(`JWKS fetch failed: ${resp.status}`);
  _jwks_cache = await resp.json();
  _jwks_fetched_at = now;
  return _jwks_cache;
}

async function find_jwk(kid) {
  const jwks = await get_jwks();
  return (jwks.keys || []).find(k => k.kid === kid) || null;
}

// ── Token validation ──────────────────────────────────────────────────────────

async function validate_jwt(token) {
  const parsed = parse_jwt(token);
  if (!parsed) return null;
  const { header, payload } = parsed;

  // Expiry
  if (Date.now() / 1000 > (payload.exp || 0)) return null;

  // Revocation
  const revoked = await TOKEN_KV.get(`revoked:${payload.jti}`);
  if (revoked) return null;

  // Signature
  const jwk = await find_jwk(header.kid);
  if (!jwk) return null;
  const verified_payload = await verify_rs256(token, jwk);
  if (!verified_payload) return null;

  return verified_payload;
}

/**
 * Full RFC 9449 DPoP validation.
 *
 * @param dpop_token  The DPoP header value
 * @param access_token  The Bearer access token (for ath binding)
 * @param method   HTTP method of the current request (uppercase)
 * @param url      Full URL of the current request (scheme + host + path)
 */
async function validate_dpop(dpop_token, access_token, method, url) {
  // 1. Verify signature
  const payload = await verify_dpop_sig(dpop_token);
  if (!payload) return { valid: false, reason: 'dpop_signature_invalid' };

  // 2. Check typ header
  const parsed = parse_jwt(dpop_token);
  if (parsed.header.typ !== 'dpop+jwt') {
    return { valid: false, reason: 'dpop_wrong_typ' };
  }

  // 3. htm must match HTTP method
  if ((payload.htm || '').toUpperCase() !== method.toUpperCase()) {
    return { valid: false, reason: 'dpop_htm_mismatch' };
  }

  // 4. htu must match request URL (scheme + host + path, no query string)
  const expected_htu = new URL(url);
  const actual_htu   = payload.htu || '';
  const htu_match    = actual_htu === `${expected_htu.origin}${expected_htu.pathname}`;
  if (!htu_match) {
    return { valid: false, reason: 'dpop_htu_mismatch' };
  }

  // 5. iat within ±30 second window
  const now_s  = Date.now() / 1000;
  const iat    = payload.iat || 0;
  if (Math.abs(now_s - iat) > 30) {
    return { valid: false, reason: 'dpop_iat_out_of_window' };
  }

  // 6. ath must equal BASE64URL(SHA-256(access_token))
  const expected_ath = await sha256_b64url(access_token);
  if (payload.ath !== expected_ath) {
    return { valid: false, reason: 'dpop_ath_mismatch' };
  }

  // 7. jti replay prevention (nonce uniqueness via KV)
  const jti = payload.jti;
  if (!jti) return { valid: false, reason: 'dpop_missing_jti' };
  const seen = await TOKEN_KV.get(`dpop_nonce:${jti}`);
  if (seen) return { valid: false, reason: 'dpop_replay_detected' };
  // Store jti for 90 seconds (well past the ±30s window)
  await TOKEN_KV.put(`dpop_nonce:${jti}`, '1', { expirationTtl: 90 });

  return { valid: true };
}

// ── Backend helpers ───────────────────────────────────────────────────────────

async function fetch_with_retry(url, options = {}, retries = 2) {
  for (let i = 0; i <= retries; i++) {
    try {
      const res = await fetch(url, options);
      if (!res.ok && i < retries) throw new Error(`HTTP ${res.status}`);
      return res;
    } catch (err) {
      if (i === retries) throw err;
      await new Promise(r => setTimeout(r, 100 * (i + 1)));
    }
  }
}

async function get_ml_score(user_id, session_data) {
  try {
    const res = await fetch_with_retry(`${BACKEND_API}/ml-score`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id, ...session_data }),
    });
    if (!res.ok) return { score: 0, revoke: false };
    return res.json();
  } catch {
    return { score: 0, revoke: false };
  }
}

async function revoke_token(jti, ttl = 3600) {
  await TOKEN_KV.put(`revoked:${jti}`, '1', { expirationTtl: ttl });
}

async function trigger_alert(alert_type, user_id, jti) {
  try {
    await fetch_with_retry(`${BACKEND_API}/alerts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        source:     'edge-worker',
        alert_type,
        user_id,
        jti,
        timestamp:  Date.now(),
      }),
    });
  } catch { /* non-fatal */ }
}

// ── Main handler ──────────────────────────────────────────────────────────────

export default {
  async fetch(request) {
    try {
      const auth_header  = request.headers.get('Authorization');
      const dpop_header  = request.headers.get('DPoP');

      if (!auth_header || !dpop_header) {
        return new Response(JSON.stringify({ error: 'Unauthorized: missing Authorization or DPoP header' }), {
          status: 401, headers: { 'Content-Type': 'application/json' },
        });
      }

      const token = auth_header.replace(/^Bearer\s+/i, '');

      // ── JWT validation ──────────────────────────────────────────────────────
      const jwt_payload = await validate_jwt(token);
      if (!jwt_payload) {
        await trigger_alert('invalid_token', null, null);
        return new Response(JSON.stringify({ error: 'Invalid or expired token' }), {
          status: 401, headers: { 'Content-Type': 'application/json' },
        });
      }

      // ── DPoP validation ─────────────────────────────────────────────────────
      const dpop_result = await validate_dpop(
        dpop_header,
        token,
        request.method,
        request.url,
      );
      if (!dpop_result.valid) {
        await trigger_alert('dpop_failure', jwt_payload.sub, jwt_payload.jti);
        return new Response(JSON.stringify({ error: 'DPoP proof invalid', reason: dpop_result.reason }), {
          status: 401, headers: { 'Content-Type': 'application/json' },
        });
      }

      // ── Attestation certificate revocation ──────────────────────────────────
      // The JWT carries the issuing cert id in the `cid` claim; if missing the
      // request is not bound to a TokenDNA-issued certificate and we skip the
      // check. The KV is populated by the scheduled() handler below; entries
      // are written with a 1-hour TTL so they survive worker restarts and
      // self-expire if the backend snapshot pipeline goes silent.
      const cert_id = jwt_payload.cid;
      if (cert_id) {
        const revoked_cert = await TOKEN_KV.get(`cert_revoked:${cert_id}`);
        if (revoked_cert) {
          await trigger_alert('cert_revoked_at_edge', jwt_payload.sub, jwt_payload.jti);
          return new Response(JSON.stringify({
            error: 'Attestation certificate revoked',
            cert_id,
            risk_tier: 'BLOCK',
            reason: revoked_cert,
          }), { status: 401, headers: { 'Content-Type': 'application/json' } });
        }
      }

      // ── Drift score gating ──────────────────────────────────────────────────
      // The scheduled() handler refreshes the per-agent drift snapshot every
      // 60s. We block requests where the agent's drift score crosses the BLOCK
      // threshold instead of letting them consume backend resources first.
      const agent_id = jwt_payload.sub;
      const drift_raw = agent_id ? await TOKEN_KV.get(`drift:${agent_id}`) : null;
      if (drift_raw) {
        try {
          const drift = JSON.parse(drift_raw);
          if (drift.tier === 'BLOCK' || (typeof drift.score === 'number' && drift.score >= 0.9)) {
            await trigger_alert('drift_block_at_edge', agent_id, jwt_payload.jti);
            return new Response(JSON.stringify({
              error: 'Agent permission drift exceeds BLOCK threshold',
              agent_id,
              risk_tier: 'BLOCK',
              drift_score: drift.score,
              reason: drift.reason || 'permission_scope_growth',
            }), { status: 403, headers: { 'Content-Type': 'application/json' } });
          }
        } catch { /* malformed entry — fall through, backend will re-evaluate */ }
      }

      // ── ML risk score ───────────────────────────────────────────────────────
      const ml = await get_ml_score(jwt_payload.sub, {
        country: request.cf?.country || 'XX',
        asn:     String(request.cf?.asn || ''),
        city:    request.cf?.city || '',
      });

      if (ml.revoke) {
        await revoke_token(jwt_payload.jti, 3600);
        await trigger_alert('revoke_by_ml', jwt_payload.sub, jwt_payload.jti);
        return new Response(JSON.stringify({ error: 'Token revoked by risk engine' }), {
          status: 401, headers: { 'Content-Type': 'application/json' },
        });
      }

      if (ml.score > 0.9) {
        await trigger_alert('high_risk_session', jwt_payload.sub, jwt_payload.jti);
      }

      // ── Proxy to backend ────────────────────────────────────────────────────
      const backend_url = new URL(request.url);
      backend_url.hostname = new URL(BACKEND_API).hostname;

      const backend_resp = await fetch_with_retry(backend_url.toString(), {
        method:  request.method,
        headers: request.headers,
        body:    ['GET', 'HEAD'].includes(request.method) ? undefined : request.body,
      });

      return new Response(backend_resp.body, {
        status:  backend_resp.status,
        headers: backend_resp.headers,
      });

    } catch (err) {
      console.error('Worker error:', err);
      return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
        status: 500, headers: { 'Content-Type': 'application/json' },
      });
    }
  },

  // ── Scheduled handler — KV cache refresh ──────────────────────────────────
  //
  // Triggered by the cron schedule in wrangler.toml. Pulls the current
  // revocation list and per-agent drift snapshot from the backend and writes
  // each entry to KV with a 1h TTL. KV reads in the request path are O(1)
  // and never block on the backend.
  //
  // Backend endpoints (added in api.py):
  //   GET /api/edge/revoked-certs   → { certs: [{cert_id, reason, revoked_at}, ...] }
  //   GET /api/edge/drift-snapshot  → { agents: [{agent_id, score, tier, reason}, ...] }
  //
  // Both endpoints require X-Edge-Sync-Token (set as a worker secret) so the
  // refresh path can't be probed by arbitrary clients.
  async scheduled(_event, env, _ctx) {
    const sync_token = env.EDGE_SYNC_TOKEN;
    if (!sync_token) {
      console.warn('EDGE_SYNC_TOKEN secret not set; skipping snapshot refresh');
      return;
    }
    const headers = { 'X-Edge-Sync-Token': sync_token };

    // Revoked certs — write each cert_id; TTL keeps stale entries from
    // pinning forever if the backend silently stops shipping them.
    try {
      const r = await fetch(`${BACKEND_API}/api/edge/revoked-certs`, { headers });
      if (r.ok) {
        const body = await r.json();
        for (const c of (body.certs || [])) {
          await TOKEN_KV.put(`cert_revoked:${c.cert_id}`, c.reason || 'revoked',
            { expirationTtl: 3600 });
        }
      } else {
        console.warn(`revoked-certs sync HTTP ${r.status}`);
      }
    } catch (err) { console.error('revoked-certs sync failed', err); }

    // Drift snapshot — write per-agent scores/tier as a single JSON blob.
    try {
      const r = await fetch(`${BACKEND_API}/api/edge/drift-snapshot`, { headers });
      if (r.ok) {
        const body = await r.json();
        for (const a of (body.agents || [])) {
          await TOKEN_KV.put(`drift:${a.agent_id}`, JSON.stringify({
            score: a.score, tier: a.tier, reason: a.reason || '',
          }), { expirationTtl: 3600 });
        }
      } else {
        console.warn(`drift-snapshot sync HTTP ${r.status}`);
      }
    } catch (err) { console.error('drift-snapshot sync failed', err); }
  },
};
