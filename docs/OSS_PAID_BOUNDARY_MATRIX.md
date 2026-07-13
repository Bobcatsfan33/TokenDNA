# TokenDNA OSS vs Paid Boundary Matrix

This matrix formalizes commercialization boundaries for the current feature set.

## Packaging Principles

- **OSS Core**: protocol/schema normalization, baseline attestation primitives, and local-store observability.
- **Paid (Cloud/Enterprise)**: cross-tenant intelligence hardening, managed policy orchestration, compliance automation at scale, and operator governance.

## Tier Matrix

| Capability | OSS Core | Cloud Pro | Enterprise |
|---|---|---|---|
| UIS schema + adapters | Yes | Yes | Yes |
| Local attestation issue/verify | Yes | Yes | Yes |
| Policy bundles (draft + simulation) | Limited (single active bundle) | Yes | Yes |
| Cross-tenant intel suppression/allowlist APIs | No | Yes | Yes |
| Managed intel decay jobs + controls | No | Yes | Yes |
| Signed compliance snapshots | No | Yes | Yes |
| Scheduled compliance exports | No | Yes | Yes |
| Operator status + SLO dashboards | Basic | Yes | Yes |
| Advanced runtime SLO gating actions | No | Yes | Yes |
| Multi-tenant key rotation governance | No | Yes | Yes |

## Recommended Gate Keys

- `intel.suppression_rules`
- `intel.decay_jobs`
- `policy.bundle.multi_version`
- `compliance.signed_snapshots`
- `compliance.scheduler`
- `operator.advanced_status`
- `trust.authority.rotation_governance`

## Runtime Contract

Feature gates are resolved by:

1. `TOKEN_PRODUCT_TIER` (`oss`, `cloud_pro`, `enterprise`)
2. optional overrides via `TOKEN_FEATURE_OVERRIDES_JSON`

Gate evaluation must fail-closed for premium features:

- return HTTP 402 (or 403 depending policy) with `{ "detail": "feature_not_enabled:<gate>" }`.

