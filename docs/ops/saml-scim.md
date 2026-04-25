# TokenDNA — SAML SSO + SCIM 2.0 (alpha)

Enterprise customers expect both SAML SSO and SCIM provisioning before
they will sign procurement. This page is the integration playbook.

> **Status: alpha.** The API surface is stable, but signature
> verification still requires the `python3-saml` optional dependency to
> be installed (a follow-up sprint replaces this with a vendored,
> tighter implementation).

---

## 1. SAML 2.0

### 1.1 Endpoints

| Path | Verb | Purpose |
|------|------|---------|
| `/saml/metadata` | GET | TokenDNA SP metadata XML — upload to your IdP. |
| `/saml/login` | GET | Returns redirect URL + RelayState for SP-initiated SSO. |
| `/saml/acs` | POST | Assertion Consumer Service. Validates SAMLResponse. |

### 1.2 Configuration env vars

```
SAML_SP_ENTITY_ID=https://app.tokendna.io/sp
SAML_SP_ACS_URL=https://app.tokendna.io/saml/acs
SAML_IDP_SSO_URL=https://idp.example.com/sso
SAML_IDP_X509_CERT="-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----"
SAML_NAME_ID_FORMAT=urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
```

### 1.3 Setup steps

1. Operator visits `https://app.tokendna.io/saml/metadata`, downloads
   the XML, and uploads it to the IdP (Okta, Azure AD, OneLogin, etc.).
2. Operator copies the IdP's SSO URL and signing certificate into the
   TokenDNA env (or secret manager).
3. End user hits `/saml/login`, is redirected to the IdP, signs in, and
   the IdP POSTs a SAMLResponse to `/saml/acs`.
4. TokenDNA verifies the assertion and issues an internal session.

### 1.4 Hardening checklist

* `WantAssertionsSigned="true"` — set in metadata; do not relax.
* `python3-saml` installed in production. Without it, `/saml/acs`
  refuses to parse and returns `503` rather than trusting an unsigned
  assertion.
* IdP-initiated flows: also accept `SAMLResponse` POST without prior
  AuthnRequest. RelayState is required and must be validated against
  the customer's allowed return URLs.
* Replay protection: every `InResponseTo` is consumed once.

---

## 2. SCIM 2.0

### 2.1 Endpoints

| Path | Verb | Purpose |
|------|------|---------|
| `/scim/v2/ServiceProviderConfig` | GET | Capability advertisement. |
| `/scim/v2/ResourceTypes` | GET | Schemas exposed (User, Group). |
| `/scim/v2/Users` | POST | Create user. |
| `/scim/v2/Users/{id}` | GET / PUT / PATCH / DELETE | User CRUD + RFC 7644 PatchOp. |
| `/scim/v2/Users` | GET | List with `startIndex` / `count` pagination + `filter=`. |
| `/scim/v2/Groups` | POST / GET | Group create / list (with `filter=`). |
| `/scim/v2/Groups/{id}` | GET / PATCH / DELETE | Group lookup / patch / delete. |

### 2.2 Auth

Bearer-token auth (`Authorization: Bearer <token>`). Tokens are scoped
per tenant and rotated by the operator via the admin console. SCIM
requests carry the same tenant context as the rest of the TokenDNA API.

### 2.3 Schemas

* User — `urn:ietf:params:scim:schemas:core:2.0:User`
* Group — `urn:ietf:params:scim:schemas:core:2.0:Group`

Custom enterprise extension schema (`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`) is not yet supported. Most IdPs degrade
gracefully when the extension is absent.

### 2.4 What is intentionally NOT supported (yet)

| Feature | Status |
|---------|--------|
| `PATCH` operations (simple paths) | **Supported.** `add` / `replace` / `remove` on top-level scalars and dotted sub-attributes (`name.givenName`). |
| `PATCH` value-filtered paths | Returns `501`. e.g. `path = emails[type eq "work"].value` — added after observing real customer traffic. |
| `bulk` operations | `bulk.supported = false`. |
| `sort` parameter | Not honored. |
| `filter` expressions | **Supported.** `eq`, `ne`, `sw`, `ew`, `co`, `gt`, `lt`, `ge`, `le`, `pr`; `and` / `or` / `not`; parens. Dotted paths (`name.givenName`, `meta.lastModified`). Multi-valued bracketed filters (`emails[...]`) return 501. |
| ETag / `If-Match` | Not honored. |

ETag and bulk are the remaining gaps before GA. The two we just shipped
— PATCH and filter — close the largest customer-blocking surface from
the original alpha scope.

---

## 3. Integration test plan

For each new IdP:

1. Apply the chart with the IdP's SSO URL + signing cert.
2. Run a single end-to-end SAML login from a real user.
3. Provision a user via SCIM `POST /scim/v2/Users` and verify it shows
   up in the admin console.
4. Suspend the user via `PUT /scim/v2/Users/{id}` (`active: false`)
   and verify the user can no longer authenticate.
5. Delete the user via SCIM and verify cleanup.

A green run on Okta + Azure AD + OneLogin is the gate before this
module flips from alpha to GA.
