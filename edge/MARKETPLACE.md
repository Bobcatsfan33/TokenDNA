# TokenDNA — Cloudflare Workers Marketplace Listing

## Listing metadata (submit via Cloudflare Developer Portal)

**Integration name:** TokenDNA Zero-Trust Token Integrity  
**Category:** Security  
**Type:** Worker Integration  
**Developer:** Aegis Security  
**Website:** https://aegis.security  
**Support email:** support@aegis.security  
**Source repo:** https://github.com/Bobcatsfan33/TokenDNA  

---

## Short description (≤ 120 chars)

Detect stolen JWT tokens in real time using behavioral fingerprinting, impossible travel detection, and DPoP proof-of-possession.

## Long description

TokenDNA sits at the Cloudflare edge and evaluates every authenticated API request against a behavioral fingerprint built from the user's device, IP, geolocation, ASN, browser, and OS. Requests that deviate from the baseline — impossible travel, Tor exit nodes, session branching across devices, datacenter IPs — are blocked or challenged before they ever reach your origin.

**How it works**

1. The Worker intercepts every request with a `Bearer` JWT or `DPoP` proof header.
2. It verifies the JWT signature against your OIDC JWKS endpoint.
3. It checks the KV-backed revocation list (updated in real time by your backend).
4. It validates full RFC 9449 DPoP proof-of-possession (typ, htm, htu, iat, ath, jti nonce).
5. It forwards a risk pre-check score from your TokenDNA backend.
6. Requests passing all checks are proxied to your origin with an `X-TokenDNA-Score` header.

**What gets blocked at the edge (before your servers see it)**
- Revoked tokens (KV lookup, < 1ms)
- Expired or malformed JWTs
- DPoP replay attacks (nonce uniqueness enforced in KV)
- Requests scoring below your configured risk threshold

**What gets evaluated at the origin**
- Impossible travel (requires geolocation from full backend)
- Adaptive ML scoring vs user behavioral profile
- Threat intelligence (Tor exits, datacenter ASNs, AbuseIPDB)
- Session branching detection

## Setup guide (5 minutes)

### Prerequisites
- Cloudflare account with Workers enabled
- A running TokenDNA backend (self-hosted or managed)
- An OIDC provider (Auth0, Okta, Cognito, Keycloak, etc.)

### Step 1 — Create KV namespace

```bash
cd edge
npm install
npm run kv:create
# Copy the returned ID into wrangler.toml → kv_namespaces[0].id
```

### Step 2 — Set secrets (never in source control)

```bash
wrangler secret put JWKS_URL
# Paste: https://your-idp.com/.well-known/jwks.json

wrangler secret put BACKEND_API
# Paste: https://your-tokendna-backend.com
```

### Step 3 — Configure wrangler.toml

Edit `wrangler.toml`:
- Replace `REPLACE_WITH_YOUR_KV_NAMESPACE_ID` with the ID from Step 1
- Set `routes` in `[env.production]` to your domain pattern

### Step 4 — Deploy

```bash
npm run deploy:production
```

### Step 5 — Verify

```bash
# Should return 200 with X-TokenDNA-Score header
curl -H "Authorization: Bearer <your-jwt>" https://api.your-domain.com/secure
```

## Environment variables

| Variable     | Type   | Required | Description |
|-------------|--------|----------|-------------|
| `JWKS_URL`  | Secret | Yes      | OIDC JWKS endpoint URL |
| `BACKEND_API` | Secret | Yes    | TokenDNA backend base URL |
| `TOKEN_CACHE` | KV binding | Yes | KV namespace for revocation list + DPoP nonces |

## KV key schema

| Key pattern            | Value  | TTL     | Purpose |
|------------------------|--------|---------|---------|
| `revoked:{jti}`        | `"1"`  | 1 hour  | Revoked token registry |
| `dpop_nonce:{jti}`     | `"1"`  | 90 sec  | DPoP replay prevention |

## Pricing

TokenDNA edge requests are billed at standard Cloudflare Workers pricing (included in Workers Paid plan). The TokenDNA backend is a separate subscription — see aegis.security/pricing.

---

## Submission checklist (Cloudflare Integration Partners Program)

- [ ] Worker deployed and tested on workers.dev subdomain
- [ ] `wrangler.toml` configured with correct KV bindings
- [ ] All secrets set via `wrangler secret put` (not in code)
- [ ] Privacy policy published at aegis.security/privacy
- [ ] Terms of service published at aegis.security/terms
- [ ] Support contact configured
- [ ] Demo video recorded (2–3 min, screen share of setup flow)
- [ ] Submit at: https://www.cloudflare.com/partners/technology-partners/

### How Cloudflare Integration Partners works

1. Apply at cloudflare.com/partners/technology-partners
2. Complete the technical review (they test your Worker for security and performance)
3. Provide marketing assets: logo (SVG), screenshots (1280×800), description copy
4. Cloudflare lists you in the Integrations Catalog at developers.cloudflare.com/integrations
5. Optionally pursue Cloudflare for SaaS (custom hostnames) for a fully managed offering
