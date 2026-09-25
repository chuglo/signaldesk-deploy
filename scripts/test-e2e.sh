#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
COMPOSE="docker compose --env-file .env.example -f compose.yaml -f compose.e2e.yaml"
RUN_ID=$(date -u +%Y%m%dT%H%M%SZ)-$$
ARTIFACT_DIR="$ROOT/test-artifacts"
RAW_LOG="$ARTIFACT_DIR/task14-$RUN_ID.raw.log"
SAFE_LOG="$ARTIFACT_DIR/task14-$RUN_ID.compose.log"
mkdir -p "$ARTIFACT_DIR"

cleanup() {
  status=$?
  $COMPOSE logs --no-color >"$RAW_LOG" 2>&1 || true
  python3 - "$ROOT/.env.example" "$RAW_LOG" "$SAFE_LOG" <<'PY' || status=1
from pathlib import Path
import sys

env_path, source_path, destination_path = map(Path, sys.argv[1:])
text = source_path.read_text(encoding="utf-8", errors="replace") if source_path.exists() else ""
for line in env_path.read_text(encoding="utf-8").splitlines():
    if not line or line.startswith("#") or "=" not in line:
        continue
    name, value = line.split("=", 1)
    if any(token in name for token in ("PASSWORD", "CREDENTIAL", "SECRET", "SIGNING_KEY")):
        text = text.replace(value, f"<redacted:{name}>")
destination_path.write_text(text, encoding="utf-8")
PY
  rm -f "$RAW_LOG"
  $COMPOSE down --volumes --remove-orphans --timeout 20 >/dev/null 2>&1 || status=1
  if [ -n "$($COMPOSE ps -q 2>/dev/null)" ]; then
    echo "cleanup failed: Task 14 containers remain" >&2
    status=1
  fi
  if docker volume ls --quiet --filter label=com.signaldesk.fixture=synthetic | grep -q .; then
    echo "cleanup failed: synthetic SignalDesk volume remains" >&2
    status=1
  fi
  echo "Sanitized Compose log: $SAFE_LOG"
  exit "$status"
}
trap cleanup EXIT INT TERM HUP

# Static gate before runtime.
.venv/bin/pytest -q
python3 -m py_compile scripts/e2e-crash-worker.py scripts/verify-e2e.py scripts/verify-runtime.py
docker compose --env-file .env.example -f compose.yaml -f compose.e2e.yaml config --quiet

# Every run starts from empty synthetic volumes and disposable tmpfs state.
$COMPOSE down --volumes --remove-orphans --timeout 20 >/dev/null 2>&1 || true
$COMPOSE up --build -d --wait --wait-timeout 240
python3 scripts/verify-runtime.py
python3 scripts/verify-e2e.py
