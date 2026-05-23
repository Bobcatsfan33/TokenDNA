# TokenDNA SAML SSO and SCIM 2.0

This is the enterprise IdP integration runbook for TokenDNA local control-plane deployments. The implementation is intended to run where the customer's identities and agents already live: on the customer's network, appliance, cluster, or tenant-owned cloud account.

## Status

The SAML and SCIM surfaces are production-gated by code, storage migrations, and preflight checks.

GA readiness still requires a customer-specific live validation run because every IdP tenant has different certificate rotation, attribute mapping, group push, and app assignment settings. Do not mark a customer environment complete until the validation matrix at the end of this page has a green report for that customer's Okta, Microsoft Entra ID, OneLogin, or equivalent tenant.

## SAML 2.0 SSO

### Endpoints

| Path | Verb | Purpose |
|------|------|---------|
| `/saml/metadata` | GET | TokenDNA SP metadata XML to upload to the IdP. |
| `/saml/login` | GET | Starts SP-initiated SSO and returns the IdP redirect URL plus RelayState. |
| `/saml/acs` | POST | Assertion Consumer Service. Validates the signed SAMLResponse. |

### Required environment

```bash
SAML_SP_ENTITY_ID=https://tokendna.customer.example/sp
SAML_SP_ACS_URL=https://tokendna.customer.example/saml/acs
SAML_IDP_SSO_URL=https://customer-idp.example/sso
SAML_IDP_X509_CERT="-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
SAML_ALLOWED_RELAY_STATE_HOSTS=tokendna.customer.example
```

Optional controls:

```bash
SAML_NAME_ID_FORMAT=urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
SAML_REQUEST_TTL_SECONDS=300
SAML_CLOCK_SKEW_SECONDS=180
SAML_ALLOW_IDP_INITIATED=false
```

### Security behavior

TokenDNA requires signed assertions and refuses SAML assertion parsing when `python3-saml` is unavailable. The production preflight fails if SAML is configured without the IdP signing certificate, IdP SSO URL, HTTPS SP URLs, RelayState host allowlist, or runtime SAML dependency.

SP-initiated login stores AuthnRequest state durably in the shared SQLite/Postgres backend. `/saml/acs` consumes `InResponseTo` exactly once, validates RelayState binding, checks Destination and Recipient against the configured ACS URL, records assertion IDs for replay defense, and audits both SAML successes and failures.

IdP-initiated SAML is disabled by default. Enable it only by explicit customer exception and keep RelayState constrained to approved HTTPS return hosts.

### IdP setup

1. Load `/saml/metadata` in TokenDNA and upload the XML into the IdP SAML application.
2. Configure the IdP ACS URL to `SAML_SP_ACS_URL`.
3. Configure the IdP audience/entity ID to `SAML_SP_ENTITY_ID`.
4. Require signed assertions. Signed responses are acceptable, but signed assertions are mandatory.
5. Map NameID to the customer identity key, usually email or immutable user principal name.
6. Add attribute mappings for email, display name, groups, and any customer-required role claims.
7. Copy the IdP SSO URL and active signing certificate into TokenDNA secrets.
8. Run `python3 scripts/preflight_prod.py --environment production` before live user testing.

## SCIM 2.0 Provisioning

### Endpoints

| Path | Verb | Purpose |
|------|------|---------|
| `/scim/v2/ServiceProviderConfig` | GET | Capability advertisement. |
| `/scim/v2/ResourceTypes` | GET | User and Group resource declarations. |
| `/scim/v2/Users` | POST / GET | Create users and list users with pagination/filtering. |
| `/scim/v2/Users/{id}` | GET / PUT / PATCH / DELETE | User lookup, replace, patch, and delete. |
| `/scim/v2/Groups` | POST / GET | Create groups and list groups with filtering. |
| `/scim/v2/Groups/{id}` | GET / PATCH / DELETE | Group lookup, patch, and delete. |

### Auth and tenant isolation

SCIM calls use the normal TokenDNA tenant boundary. For Okta, Microsoft
Entra ID, OneLogin, and most SCIM clients, configure bearer-token auth with
the tenant API key value:

```http
Authorization: Bearer <tenant-api-key>
```

Direct API callers can also send the same key with:

```http
X-API-Key: <tenant-api-key>
```

OIDC JWT bearer auth remains supported for non-SCIM API callers.

Every SCIM read and write is tenant-scoped. Users and groups are stored durably in the shared backend, have weak ETag-style versions, and emit audit events for create, update, patch, and delete actions.

### Supported SCIM behavior

| Capability | Status |
|------------|--------|
| User CRUD | Supported. |
| Group CRUD | Supported. |
| Pagination | Supported for users. |
| Filtering | Supported for core scalar paths and dotted paths. |
| PatchOp | Supported for simple `add`, `replace`, and `remove` operations. |
| ETag advertisement | Supported via `ServiceProviderConfig`. |
| Bulk | Not supported; advertised as disabled. |
| Sort | Not supported; advertised as disabled. |
| Value-filtered multi-valued paths | Returns `501` until a customer IdP requires it. |

## Provider Validation Matrix

Run this matrix for every customer IdP tenant before declaring the integration complete.

| Provider | Required validation |
|----------|---------------------|
| Okta | SP metadata import, SP-initiated login, assertion signature validation, bad RelayState rejection, replay rejection, user create/update/deactivate/delete, group create/member update/delete. |
| Microsoft Entra ID | Enterprise app SAML setup, certificate rollover check, assigned user login, group claim mapping, provisioning job create/update/disable/delete, group push where licensed. |
| OneLogin | SAML connector import, signed assertion enforcement, NameID and attribute mappings, SCIM bearer auth, user lifecycle, group membership patch. |

Evidence to retain for GA:

1. Preflight JSON report with `passed=true`.
2. Migration status showing the SAML and SCIM schemas applied.
3. SAML login trace with success audit event and no unsigned assertion acceptance.
4. Replay test showing a second POST of the same assertion is rejected.
5. SCIM provisioning transcript for create, update, deactivate, group membership patch, and delete.
6. IdP screenshots or exported app configuration with ACS URL, entity ID, signing requirement, and certificate fingerprint.

The repeatable TokenDNA-side harness is:

```bash
python3 scripts/idp_ga_validation.py \
  --provider okta \
  --base-url https://tokendna.customer.example \
  --api-key "$TOKENDNA_TENANT_API_KEY"
```

Use `--provider entra` or `--provider onelogin` for those customer tenants. The script verifies metadata, SP-initiated SAML request generation, SCIM discovery, user lifecycle, group lifecycle, and group membership patching, then emits a JSON evidence report. The browser login, assertion replay, and certificate-fingerprint evidence remain customer-tenant manual checks because they require the live IdP admin console and a real assigned user.

## Local Deployment Flow

```bash
set -a
. ./.env
set +a

python3 scripts/preflight_prod.py --environment production
python3 scripts/migrate_storage.py apply
python3 scripts/postgres_smoke.py
```

For Docker Compose appliance deployments:

```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d postgres
docker compose -f docker-compose.yml -f docker-compose.production.yml run --rm tokendna-deployment-gate
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d tokendna
```
