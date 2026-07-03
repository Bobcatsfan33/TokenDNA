# TokenDNA Commercial Licensing

TokenDNA is source-available under BUSL-1.1. The core runtime (UIS
normalization, attestation, basic policy bundles, token integrity) is free to
use. The enterprise capabilities — the `ent.*` gates: Blast Radius, the
Real-Time Enforcement Plane, Intent Correlation, the MCP Security Gateway,
Behavioral DNA drift, and Federated Agent Trust — require a commercial
license key tied to an active subscription.

## How it works

A license key is an Ed25519-signed payload issued by the TokenDNA license
service when a Stripe subscription is created:

    TDNA1.<base64url payload>.<base64url signature>

Only the public key ships in this repository
(`modules/product/licensing.py`). Verification is offline; TokenDNA never
phones home. The payload carries your Stripe customer id, granted tier,
optional à-la-carte features, and expiry (subscription period end plus a
grace window).

## Activating a license

Any one of:

1. Environment: `TOKENDNA_LICENSE_KEY=TDNA1...`
2. File: write the key to the path in `TOKENDNA_LICENSE_FILE`
   (default `./license.key`)
3. API: `POST /api/license/activate` with `{"license_key": "TDNA1..."}`
   (admin/owner role)

Check state at any time: `GET /api/license/status`.

## Enforcement modes (`TOKENDNA_LICENSE_ENFORCEMENT`)

| Mode | Behavior |
|---|---|
| `off` (default) | Plan-based gating only. Dev, CI, and demos are unaffected. |
| `warn` | Logs when the tenant plan exceeds the license, but allows. |
| `enforce` | The license caps the effective commercial tier. Use in production. |

Production deployments should set `TOKENDNA_LICENSE_ENFORCEMENT=enforce`.

## FAQ

**Can't a self-hoster just patch the check out?** Technically yes — the repo
is public. The gate is a compliance boundary, not DRM. Commercial use of the
enterprise features without a license violates the BUSL-1.1 terms; the
signed key is what makes honest commercial use frictionless and auditable.

**Does the license expire when my subscription lapses?** Keys are issued
with an expiry of your current billing period end plus a grace window, and
re-issued on renewal. If your subscription cancels, the current key simply
expires.

**Trials?** `DEV_MODE=true` (which additionally requires
`TOKENDNA_ENV=dev` or another recognized development environment — DEV_MODE
is deny-by-default outside dev contexts) runs everything unrestricted for
local evaluation, and time-boxed trial keys can be issued on request.
