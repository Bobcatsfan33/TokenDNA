# TokenDNA DoD ATO Readiness Package

This folder contains assessor-facing artifacts for deploying TokenDNA into a
customer-owned DoD or Defense Industrial Base environment. These files do not
grant an Authorization to Operate by themselves; they make the product easier to
authorize inside a named system boundary with a customer Authorizing Official,
inherited enclave controls, and assessment evidence.

## Artifacts

| File | Purpose |
|------|---------|
| `system-security-plan.md` | SSP starter narrative: boundary, data flows, roles, and control implementation story. |
| `customer-responsibility-matrix.md` | Separates TokenDNA product controls from customer/inherited controls. |
| `continuous-monitoring-plan.md` | Defines recurring evidence, scan cadence, and POA&M flow. |
| `poam-template.csv` | Lightweight POA&M import template for unresolved gaps. |

## Machine-readable Evidence

The source control mapping lives at `compliance/dod/control_matrix.json`.

Generate assessor artifacts:

```bash
python scripts/generate_oscal.py
python scripts/stig_evidence.py
python scripts/collect_ato_evidence.py
```

Default outputs are written under `dist/ato/`.
