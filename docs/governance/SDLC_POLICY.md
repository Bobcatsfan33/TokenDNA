# Secure SDLC Policy (one page)

> Input to the NIST SSDF (SP 800-218) self-attestation required by EO 14028 /
> OMB M-22-18. Records the AI-assisted development workflow and its **enforced**
> gates. "Enforced" means a machine blocks the merge — not a convention. This
> document distinguishes repository CI from GitHub organization controls.

## 1. Roles & separation of duties (SA-11, SR-3)

- **Current maintainer**: `@Bobcatsfan33`. A named independent second maintainer
  is an open deployment gate (see `CODEOWNERS`).
- GitHub currently requires one approval and resolved conversations, but the
  independent code-owner and last-push controls below are not active yet.
- The target state makes code-owner review mandatory on security-sensitive paths: `auth.py`,
  `modules/security/**`, `modules/tenants/**`, `modules/auth/**`,
  `compliance/**`, `.github/**`, `api_routers/**`.

## 2. Branch protection

As verified on 2026-08-10, `main` requires a pull request, one approval, a
strict but stale aggregate status context (`TokenDNA — CI Pipeline`), and
resolved conversations. Force-push and deletion are disabled. Code-owner
review, last-push approval, signed commits, and admin enforcement are not yet
enabled. Therefore the organization-governance gate is **open**.

`scripts/org/protect.sh` defines the target state using the actual CI job
contexts. It fails before making changes unless an independent second
maintainer is a repository collaborator and appears on every `CODEOWNERS`
rule. It then enables code-owner review, last-push approval, signed commits,
linear history, admin enforcement, and all blocking CI jobs.

## 3. AI-assisted development workflow

1. **Research & reuse** before net-new code (existing modules, libraries).
2. **Plan** the change; **TDD** — tests first, ≥80% coverage on touched modules.
3. **Author** the change on a branch (AI-assisted; a human maintainer owns the PR).
4. **Automated review gates** run in CI (below). Once the organization gate is
   closed, an independent human code-owner reviews and
   approves. AI-generated code receives the same review as human-written code —
   the same-model-writes-and-reviews blind spot is mitigated by an independent
   human approval plus the automated gates.
5. **Squash-merge** only after all required checks are green.

## 4. Enforced CI gates (every PR)

- **Tests**: full `pytest` suite (`tests/`).
- **Lint/type**: `ruff`.
- **SAST**: CodeQL (`security-extended`).
- **Secrets**: TruffleHog OSS; production secret-gate preflight.
- **Dependency scan**: `pip-audit`; Dependabot weekly.
- **Container**: Trivy blocks fixable HIGH/CRITICAL findings; digest-pinned
  distroless runtime. Tagged image releases are cosign-signed and emit SBOM and
  provenance attestations.
- **Workflow supply chain**: every third-party action is pinned to a full commit
  SHA and `workflow_action_pin_guard.py` blocks mutable refs.
- **Monolith ratchet**: `scripts/ci/api_monolith_ratchet.py` — `api.py` may only
  shrink (T-1).

## 5. Provenance & supply chain (EO 14028 / M-22-18)

Every published image is digest-addressed, cosign-signed (Fulcio/OIDC identity
= the building workflow), SBOM-attested (CycloneDX), and carries SLSA v1
build provenance verifiable with `slsa-verifier`. SBOM artifacts retained 90
days and attached to releases.

## 6. Vulnerability response

See `SECURITY.md` — coordinated disclosure to `ryanwallac33@gmail.com`; fix
SLAs by CVSS (Critical 24–72h … Low 90d).

_Last reviewed and reconciled with live GitHub settings: 2026-08-10._
