#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# TokenDNA Runtime Risk Engine — Demo Launcher
#
# Usage:
#   ./scripts/demo_launch.sh          # Start server + seed + open browser
#   ./scripts/demo_launch.sh --no-seed  # Start server only
#   ./scripts/demo_launch.sh --dry-run  # Show what would be seeded
#
# Requires: Python 3.9+, pip packages from requirements.txt
# ─────────────────────────────────────────────────────────────────────────────
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
PORT=8088
DB_PATH="/tmp/tokendna-demo.db"
SEED=true
DRY_RUN=false

for arg in "$@"; do
  case $arg in
    --no-seed)   SEED=false ;;
    --dry-run)   DRY_RUN=true ;;
    --port=*)    PORT="${arg#*=}" ;;
    --db=*)      DB_PATH="${arg#*=}" ;;
  esac
done

cd "$REPO_DIR"

echo ""
echo "╔════════════════════════════════════════════════╗"
echo "║   TokenDNA Runtime Risk Engine — Demo Mode    ║"
echo "╚════════════════════════════════════════════════╝"
echo ""

# Kill any existing instance
pkill -f "uvicorn api:app.*$PORT" 2>/dev/null || true
sleep 0.5

if [ "$DRY_RUN" = "true" ]; then
  echo "DRY RUN — showing seed plan:"
  DEV_MODE=true DATA_DB_PATH="$DB_PATH" python3 scripts/demo_seed.py --dry-run
  exit 0
fi

# Start API server
echo "Starting API on :$PORT ..."
DEV_MODE=true \
  DEV_TENANT_ID="${DEV_TENANT_ID:-acme}" \
  DATA_DB_PATH="$DB_PATH" \
  AUDIT_LOG_PATH="/tmp/tokendna-demo-audit.jsonl" \
  python3 -m uvicorn api:app --host 127.0.0.1 --port "$PORT" \
  --log-level warning > /tmp/tokendna-demo-api.log 2>&1 &

API_PID=$!
echo "  API PID: $API_PID"

# Wait for API
echo -n "  Waiting for API to be ready"
for i in $(seq 1 30); do
  if python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:$PORT/', timeout=1)" >/dev/null 2>&1; then
    echo " ✓"
    break
  fi
  echo -n "."
  sleep 1
  if [ $i -eq 30 ]; then
    echo " FAILED"
    cat /tmp/tokendna-demo-api.log
    exit 1
  fi
done

if [ "$SEED" = "true" ]; then
  echo ""
  python3 scripts/demo_seed.py --base-url "http://127.0.0.1:$PORT"
fi

# Open browser
DASHBOARD_URL="http://127.0.0.1:$PORT/dashboard"
echo ""
echo "  Dashboard: $DASHBOARD_URL"
echo "  API docs:  http://127.0.0.1:$PORT/docs"
echo "  DB:        $DB_PATH"
echo ""
echo "  Press Ctrl+C to stop."
echo ""

# Open browser (macOS / Linux)
if command -v open >/dev/null 2>&1; then
  sleep 0.5 && open "$DASHBOARD_URL" &
elif command -v xdg-open >/dev/null 2>&1; then
  sleep 0.5 && xdg-open "$DASHBOARD_URL" &
fi

# Tail log
wait $API_PID
