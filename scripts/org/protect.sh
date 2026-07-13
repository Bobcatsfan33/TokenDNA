#!/usr/bin/env bash
# scripts/org/protect.sh — SH-2 branch protection as code (requires admin PAT).
#
# One-time per repo. Enforces: PR required, 1 approving review (not the author),
# required status checks, code-owner review, no force-push, no deletion, signed
# commits. Run via:  bash scripts/org/protect.sh TokenDNA
#
# Idempotent: re-run after adding the second maintainer to CODEOWNERS.
set -euo pipefail

REPO="${1:?usage: protect.sh <repo-name> (e.g. TokenDNA)}"
OWNER="${PROTECT_OWNER:-Bobcatsfan33}"

gh api -X PUT "repos/${OWNER}/${REPO}/branches/main/protection" \
  -H "Accept: application/vnd.github+json" \
  --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["security-suite / build-scan-sign", "ci"]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "require_code_owner_reviews": true,
    "require_last_push_approval": true
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_signatures": true
}
JSON

echo "branch protection applied to ${OWNER}/${REPO}:main"
