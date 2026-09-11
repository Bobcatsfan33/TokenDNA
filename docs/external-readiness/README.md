# External Enterprise Readiness Gates

TokenDNA's repository gates can prove build integrity, automated security
checks, and repeatable test behavior. They cannot prove an independent security
assessment, production operations, customer interoperability, organizational
separation of duties, or legal/compliance acceptance.

The machine-readable gate register is `docs/enterprise-readiness.json`. Each
open external gate below has a handoff packet with scope, required evidence,
and objective acceptance criteria:

- `independent-security-assessment.md`
- `identity-interoperability.md`
- `production-operations-validation.md`
- `repository-governance.md`
- `compliance-commercial-approval.md`
- `production-pilot.md`

Run `python scripts/ci/verify_enterprise_readiness.py` to validate the register.
On pull requests, the verifier also requires `assessedCommit` to be an ancestor of the target
branch. Pin the assessment to the reviewed base commit, not the feature-branch tip, so the evidence
chain remains valid after GitHub creates a squash-merge commit.
Production promotion must run it with `--require-approved`; that command fails
while any required gate remains open.
