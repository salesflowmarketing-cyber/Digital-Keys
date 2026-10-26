#!/usr/bin/env bash
# Digital Keys - Native Desktop Launcher
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

VENV="$HERE/digital-keys-venv"
if [ ! -f "$VENV/bin/activate" ]; then
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install --quiet -e . 2>&1 | tail -3
fi

source "$VENV/bin/activate"

# Launch the native desktop GUI
exec python -m digital_keys gui