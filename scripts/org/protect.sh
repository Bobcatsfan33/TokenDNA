#!/usr/bin/env bash
# Apply TokenDNA's main-branch protection after a second maintainer is active.
#
# Usage:
#   bash scripts/org/protect.sh TokenDNA <second-maintainer-github-login>
#
# Requires an authenticated gh identity with repository administration rights.
# The script fails before changing GitHub unless the second maintainer is a
# collaborator and is present on every CODEOWNERS rule.
set -euo pipefail

REPO="${1:?usage: protect.sh <repo-name> <second-maintainer-github-login>}"
SECOND_MAINTAINER="${2:?usage: protect.sh <repo-name> <second-maintainer-github-login>}"
OWNER="${PROTECT_OWNER:-Bobcatsfan33}"
export SECOND_MAINTAINER

if [[ "${SECOND_MAINTAINER}" == "${OWNER}" ]]; then
  echo "second maintainer must be independent from ${OWNER}" >&2
  exit 1
fi

python3 - <<'PY'
import os
from pathlib import Path

second = "@" + os.environ["SECOND_MAINTAINER"].lstrip("@")
rules = []
for raw in Path("CODEOWNERS").read_text(encoding="utf-8").splitlines():
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    pattern, *owners = line.split()
    rules.append((pattern, owners))

missing = [pattern for pattern, owners in rules if second not in owners]
if missing:
    raise SystemExit(
        f"CODEOWNERS must include {second} on every rule; missing: " + ", ".join(missing)
    )
PY

permission="$(gh api "repos/${OWNER}/${REPO}/collaborators/${SECOND_MAINTAINER}/permission" --jq .permission)"
case "${permission}" in
  admin|maintain|write) ;;
  *)
    echo "${SECOND_MAINTAINER} must have write, maintain, or admin permission (found: ${permission})" >&2
    exit 1
    ;;
esac

gh api -X PUT "repos/${OWNER}/${REPO}/branches/main/protection" \
  -H "Accept: application/vnd.github+json" \
  --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "DCO sign-off check",
      "Orphan module guard",
      "Demo smoke paths",
      "Zero-dependency boot (no Redis, no Postgres, no ClickHouse)",
      "Lint & Import Verification",
      "Full Test Suite",
      "DoD ATO Evidence Gate",
      "Dependency Security Scan",
      "CodeQL Security Analysis",
      "Secret Detection",
      "Docker Build Check",
      "Runtime Readiness Gates",
      "Adversarial Security Harness",
      "Policy Regression Gate",
      "Production Secret Gate",
      "Live Postgres Deployment Gate",
      "Helm Chart Lint",
      "Stress Harness (smoke)",
      "Detection Efficacy Benchmark"
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "required_approving_review_count": 1,
    "require_code_owner_reviews": true,
    "require_last_push_approval": true
  },
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": true,
  "lock_branch": false,
  "allow_fork_syncing": true
}
JSON

gh api -X POST "repos/${OWNER}/${REPO}/branches/main/protection/required_signatures" \
  -H "Accept: application/vnd.github+json" >/dev/null

echo "branch protection applied to ${OWNER}/${REPO}:main with independent maintainer ${SECOND_MAINTAINER}"
