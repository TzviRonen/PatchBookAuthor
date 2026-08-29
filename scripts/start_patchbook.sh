#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="${PYTHON:-/opt/venv/bin/python3}"

if [[ -z "${CONTAINER_PORTS:-}" ]]; then
  echo "[!] CONTAINER_PORTS is not set."
  exit 1
fi

PORT=""
for p in $CONTAINER_PORTS; do
  if ! ss -tlnp 2>/dev/null | awk '{print $4}' | grep -qE ":${p}$"; then
    PORT="$p"
    break
  fi
done

if [[ -z "$PORT" ]]; then
  echo "[!] All ports in CONTAINER_PORTS ($CONTAINER_PORTS) are in use."
  exit 1
fi

# ensure dependencies
if ! "$PYTHON" -c "import flask, markdown" 2>/dev/null; then
  echo "[*] Installing missing dependencies..."
  sudo "$PYTHON" -m pip install flask markdown -q
fi

echo "[*] Starting PatchBook on port $PORT  →  http://localhost:$PORT/"
exec "$PYTHON" "$WORKSPACE/patchbook/serve.py" "$PORT"
