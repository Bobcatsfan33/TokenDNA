# TokenDNA Platform

Proprietary backend of the TokenDNA AI runtime security project. Business Source License 1.1.

The platform is the **cloud half** of the open-core split. It receives the normalised event stream emitted by sibling `../collector/`, runs it through the intelligence engines, exposes a dashboard + APIs, integrates with the customer's downstream systems (SIEM, ticketing, paging), and delivers compliance evidence packages.

## Why source-available, not open-source

- The collector exists to drive **adoption**: every deployment is a future customer for this side.
- The platform exists to drive **revenue**: it is the value the customer is actually buying.
- The runtime-enforcement SDK that ships from this side is the high-margin moat — detection-mode findings make the case for it, prevention-mode hardens it.

BUSL-1.1 keeps the source readable while restricting production use until the Change Date — at which point it auto-relicenses to Apache 2.0. See `LICENSE` for the exact terms.

## What lives here vs. in `../collector/`

See the boundary table in `../collector/README.md`. Same line, drawn from the other side.

## Status

This directory landed as **scaffolding only** in PR `#sprint/1-2-collector-platform-split`. **Nothing was moved in yet.** Existing modules at the repository root (`modules/identity/`, `modules/security/`, `api.py`, `dashboard/`, `tokendna_sdk/`, etc.) are untouched.

Subsequent sprints (per `~/Desktop/tokendna/TOKENDNA-DEPLOYMENT-REDESIGN.md`) will MOVE existing modules into `tokendna_platform/` per the disposition map below. Each move is a focused PR — no big-bang relocation.

## Disposition map (from the redesign doc)

This is the contract for what eventually lives under `tokendna_platform/`. Lifted from the redesign doc's "Module Disposition Map" and reproduced here so anyone reading this directory can see the destination shape without leaving the repo.

### Elevated (core of the paid moat)

| Source location                          | Future location under platform/                |
|------------------------------------------|-------------------------------------------------|
| `tokendna_sdk/`                           | `platform/tokendna_platform/sdk/`               |
| `modules/identity/policy_guard.py`        | `platform/tokendna_platform/policy_guard.py`    |
| `modules/identity/behavioral_dna.py`      | `platform/tokendna_platform/behavioral_dna.py`  |
| `modules/identity/mcp_inspector.py`       | `platform/tokendna_platform/mcp_inspector.py`   |

### Kept (serves both detection-mode and SDK-mode customers)

| Source location                          | Future location under platform/                |
|------------------------------------------|-------------------------------------------------|
| `modules/identity/trust_graph.py`         | `platform/tokendna_platform/trust_graph.py`     |
| `modules/identity/permission_drift.py`    | `platform/tokendna_platform/permission_drift.py`|
| `modules/identity/blast_radius.py`        | `platform/tokendna_platform/blast_radius.py`    |
| `modules/identity/compliance_engine.py`   | `platform/tokendna_platform/compliance/`        |
| `modules/identity/clickhouse_client.py`   | `platform/tokendna_platform/storage/clickhouse.py` |
| `modules/security/*`                      | `platform/tokendna_platform/security/`          |
| `modules/tenants/*`                       | `platform/tokendna_platform/tenants/`           |
| `modules/observability/*`                 | `platform/tokendna_platform/observability/`     |

### SDK-exclusive (premium tier only)

| Source location                              | Future location under platform/                |
|----------------------------------------------|-------------------------------------------------|
| `modules/identity/edge_enforcement.py`        | `platform/tokendna_platform/sdk/edge.py`        |
| `modules/identity/dpop.py`                    | `platform/tokendna_platform/sdk/dpop.py`        |
| `modules/identity/hvip.py`                    | `platform/tokendna_platform/sdk/hvip.py`        |
| `modules/identity/proof_of_control.py`        | `platform/tokendna_platform/sdk/proof_of_control.py` |
| `modules/identity/passport.py`                | `platform/tokendna_platform/sdk/passport.py`    |
| `modules/identity/attestation*.py`            | `platform/tokendna_platform/sdk/attestation/`   |
| `edge/`                                       | `platform/tokendna_platform/sdk/edge_worker/`   |

### Repurposed (different role in the overlay model)

| Source location                  | Repurpose                                                           |
|----------------------------------|---------------------------------------------------------------------|
| `auth.py` (root)                  | Auth for collector→cloud + dashboard users (not end-user agents)    |
| `modules/auth/saml.py`            | (1) Parses SAML from customer IDP logs in collector mode (2) Provides SSO for the dashboard in cloud mode |
| `modules/auth/scim.py`            | (1) Reads customer SCIM provisioning events (2) Accepts SCIM for platform user provisioning |

## License

Business Source License 1.1, with `Change Date = 2030-05-08` and `Change License = Apache License, Version 2.0`. See `LICENSE`.

For commercial licensing before the Change Date, contact TokenDNA Inc.
