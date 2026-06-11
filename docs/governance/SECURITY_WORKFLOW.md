# Shared security workflow (SH-1)

This repo consumes one org-level reusable workflow that gives every repo:
CodeQL, Trivy image gating, CycloneDX SBOMs, cosign keyless signing, and SLSA
v1 provenance. It is **maintained once** in `Bobcatsfan33/.github` and called
from `.github/workflows/security.yml` here (~12 lines).

## Consuming it

`.github/workflows/security.yml` calls:

```yaml
uses: Bobcatsfan33/.github/.github/workflows/security-reusable.yml@main
with:
  image: ghcr.io/bobcatsfan33/tokendna
  languages: '["python"]'
  dockerfile: Dockerfile
```

## Maintaining the reusable workflow

The canonical source for `security-reusable.yml` lives in the org repo
`Bobcatsfan33/.github` under `.github/workflows/`. A copy is kept here at
`docs/governance/security-reusable.yml` for reference / bootstrapping so this
document stands alone; the org repo is the source of truth.

To bootstrap the org repo (one time):

```bash
gh repo create Bobcatsfan33/.github --public \
  --description "Org-level reusable workflows" || true
# add .github/workflows/security-reusable.yml (see the reference copy),
# commit, and push to main.
```

## Verifying signed artifacts

```bash
# Image signature (keyless, OIDC identity = the building workflow)
cosign verify ghcr.io/bobcatsfan33/tokendna@<digest> \
  --certificate-identity-regexp 'github.com/Bobcatsfan33' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# SLSA v1 provenance
slsa-verifier verify-image ghcr.io/bobcatsfan33/tokendna@<digest> \
  --source-uri github.com/Bobcatsfan33/TokenDNA
```

## Definition of done (SH-1)

- Workflow green on `main`; `cosign verify` succeeds for every published image.
- `slsa-verifier` validates provenance.
- SBOM artifacts retained 90 days and attached to releases.
- Trivy gate fails on HIGH/CRITICAL; `.trivyignore` is the only waiver path.
