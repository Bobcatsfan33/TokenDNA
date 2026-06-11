# Secure SDLC Policy (one page)

> Input to the NIST SSDF (SP 800-218) self-attestation required by EO 14028 /
> OMB M-22-18. Records the AI-assisted development workflow and its **enforced**
> gates. "Enforced" means a machine blocks the merge — not a convention.

## 1. Roles & separation of duties (SA-11, SR-3)

- **Maintainers**: `@Bobcatsfan33` + a named second maintainer (see `CODEOWNERS`).
- No author may approve or merge their own change to `main`. Enforced by
  branch protection (`require_last_push_approval`, 1 approving review that is
  not the author) — see `scripts/org/protect.sh`.
- Code-owner review is mandatory on security-sensitive paths: `auth.py`,
  `modules/security/**`, `modules/tenants/**`, `modules/auth/**`,
  `compliance/**`, `.github/**`, `api_routers/**`.

## 2. Branch protection (enforced on `main`)

PR required · ≥1 non-author approval · required status checks (`ci`,
`security-suite / build-scan-sign`) · code-owner review · no force-push ·
no branch deletion · signed commits required. Applied as code via
`scripts/org/protect.sh`; `enforce_admins=true` so admins are not exempt.

## 3. AI-assisted development workflow

1. **Research & reuse** before net-new code (existing modules, libraries).
2. **Plan** the change; **TDD** — tests first, ≥80% coverage on touched modules.
3. **Author** the change on a branch (AI-assisted; a human maintainer owns the PR).
4. **Automated review gates** run in CI (below). A human code-owner reviews and
   approves. AI-generated code receives the same review as human-written code —
   the same-model-writes-and-reviews blind spot is mitigated by an independent
   human approval plus the automated gates.
5. **Squash-merge** only after all required checks are green.

## 4. Enforced CI gates (every PR)

- **Tests**: full `pytest` suite (`tests/`, `platform/tests/`, `collector/tests/`).
- **Lint/type**: `ruff`.
- **SAST**: CodeQL (`security-extended`).
- **Secrets**: TruffleHog OSS; production secret-gate preflight.
- **Dependency scan**: `pip-audit`; Dependabot weekly.
- **Container**: Trivy gate on HIGH/CRITICAL (`.trivyignore` is the only waiver
  path); distroless runtime; image signed (cosign keyless) + SLSA v1 provenance
  + CycloneDX SBOM via the shared `security-suite` workflow (SH-1).
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

_Last reviewed: 2026-06-11._
