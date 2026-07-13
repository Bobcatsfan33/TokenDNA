#!/usr/bin/env bash
# TokenDNA interactive demo — one command.
#
#   ./scripts/demo.sh                 # seed + start on :8000
#   ./scripts/demo.sh --port 8088     # custom port
#   ./scripts/demo.sh --no-seed       # skip (re)seeding
#   ./scripts/demo.sh --db /tmp/x.db  # custom demo DB
#
# Then open:
#   http://127.0.0.1:8000/demo       interactive console (every feature)
#   http://127.0.0.1:8000/console    kill-switch workflow graph
#   http://127.0.0.1:8000/dashboard  legacy dashboard
set -euo pipefail

cd "$(dirname "$0")/.."
PORT=8000
DB=/tmp/tokendna-demo.db
SEED=1
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2;;
    --db) DB="$2"; shift 2;;
    --no-seed) SEED=0; shift;;
    *) echo "unknown arg: $1"; exit 1;;
  esac
done

PY=python3
[ -x ".venv/bin/python" ] && PY=".venv/bin/python"

# One demo DB shared by every module (data store, MCP gateway, behavioral DNA).
export DATA_DB_PATH="$DB"
export TOKENDNA_MCP_GATEWAY_DB="$DB"
export TOKENDNA_BEHAVIORAL_DB="$DB"
export DEV_MODE=true
export DEV_TENANT_ID=acme
export TOKENDNA_DEMO=acme
export ENVIRONMENT=dev
export ATTESTATION_CA_SECRET="demo-secret-for-attestation-bundle-32bytes"

if [ "$SEED" = "1" ]; then
  echo "→ seeding demo data into $DB (base + gap features)…"
  rm -f "$DB"
  "$PY" scripts/demo_seed_gap.py --with-base
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  TokenDNA demo ready on http://127.0.0.1:$PORT"
echo "    /demo       interactive console — every feature, real API"
echo "    /console    kill-switch workflow graph (click a node → rip)"
echo "    /dashboard  legacy dashboard"
echo "  DEV_MODE on (auth bypassed, ENTERPRISE tier). Ctrl-C to stop."
echo "════════════════════════════════════════════════════════════════"
echo ""
exec "$PY" -m uvicorn api:app --host 127.0.0.1 --port "$PORT" --log-level info
