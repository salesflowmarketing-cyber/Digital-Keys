#!/usr/bin/env bash
# Digital Keys - one-command bootstrap for Linux.
#
#   ./digital-keys.sh            -> create venv, install, run the full test suite
#   ./digital-keys.sh --test     -> same, but only run tests
#
set -euo pipefail

cd "$(dirname "$0")"

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mFAIL:\033[0m %s\n' "$*" >&2; exit 1; }

command -v python3 >/dev/null || die "python3 not found."
PYV=$(python3 -c 'import sys;print(1 if sys.version_info>=(3,11) else 0)')
[ "$PYV" = "1" ] || die "need Python 3.11+ (you have $(python3 -V 2>&1))"

say "python $(python3 -V 2>&1)"

VENV=./digital-keys-venv
if [ ! -x "$VENV/bin/python" ]; then
  say "creating virtualenv in $VENV"
  python3 -m venv "$VENV"
fi

say "installing Digital Keys"
"$VENV/bin/python" -m pip install --quiet --upgrade pip
"$VENV/bin/python" -m pip install --quiet -e . || die "pip install failed"

say "running the test suite"
echo
"$VENV/bin/python" -m unittest tests.test_crypto -q
"$VENV/bin/python" tests/redteam.py
"$VENV/bin/python" tests/e2e_live.py
"$VENV/bin/python" tests/test_agent_flow.py

say "all suites passed"
cat <<'NEXT'

Next steps:
  source digital-keys-venv/bin/activate
  dk init                 # create your vault
  dk add --label "OpenRouter" --provider openrouter --kind api_key
  dk gui                  # launch the desktop GUI

Or set DIGITAL_KEYS_PASSPHRASE=your-passphrase to skip prompts.
NEXT