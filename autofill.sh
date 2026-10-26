#!/usr/bin/env bash
# dk autofill helper
#
#   ./autofill.sh openrouter        # copy the first matching credential to clipboard
#   ./autofill.sh --list            # list all available credentials
#   ./autofill.sh --copy <id>       # copy a specific credential by id
#   ./autofill.sh --url https://... # find credentials for a URL
#
# Requires: curl, python3, and dk broker running

set -euo pipefail

BROKER="${DIGITAL_KEYS_BROKER_URL:-http://127.0.0.1:8787}"
UI="${DIGITAL_KEYS_UI_URL:-http://127.0.0.1:8989}"
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

say() { printf "${GREEN}==>${NC} %s\n" "$*"; }
warn() { printf "${RED}ERROR:${NC} %s\n" "$*" >&2; }
info() { printf "${CYAN}-->${NC} %s\n" "$*"; }

check_broker() {
    if ! curl -sf "$BROKER/v1/health" >/dev/null 2>&1; then
        warn "dk broker is not running at $BROKER"
        echo "  Start it with: dk serve"
        echo "  Or set: export DIGITAL_KEYS_BROKER_URL=..."
        exit 1
    fi
}

list_credentials() {
    check_broker
    say "Credentials available in the vault:"
    echo
    curl -sf "$UI/api/credentials" 2>/dev/null | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    creds = data.get('credentials', [])
    if not creds:
        print('  No credentials found.')
        print('  Add one with: dk add --label ... --provider ... --secret ...')
        sys.exit(0)
    for c in creds:
        print(f'  {c[\"id\"][:8]:10} {c[\"label\"]:<28} {c[\"provider_label\"] or c[\"provider_id\"]:<16} {c.get(\"username\", \"-\")}')
    print()
    print(f'  Total: {len(creds)} credential(s)')
except Exception as e:
    print(f'  Could not read from UI at $UI')
    print(f'  Error: {e}')
    print(f'  Try: dk list')
" || {
        # Fallback to CLI
        dk list 2>/dev/null || warn "Could not list credentials"
    }
}

copy_credential() {
    local id="$1"
    check_broker
    say "Copying credential $id to clipboard..."
    
    # Try via UI first
    SECRET=$(curl -sf -X POST "$UI/api/credentials/$id/reveal" \
        -H "Content-Type: application/json" \
        -d '{"passphrase":""}' 2>/dev/null | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('secret', ''))
except: print('')
" 2>/dev/null) || SECRET=""
    
    if [ -z "$SECRET" ]; then
        # Fall back to CLI - prompt for passphrase
        info "Opening vault to retrieve credential..."
        SECRET=$(dk show "$id" --reveal 2>/dev/null | grep "^secret" | cut -d: -f2- | sed 's/^ *//')
    fi
    
    if [ -n "$SECRET" ]; then
        echo -n "$SECRET" | xclip -selection clipboard 2>/dev/null || \
        echo -n "$SECRET" | xsel -b 2>/dev/null || \
        echo -n "$SECRET" | wl-copy 2>/dev/null || {
            warn "No clipboard tool found (install xclip, xsel, or wl-clipboard)"
            echo "$SECRET"
        }
        say "Copied to clipboard!"
    else
        warn "Could not retrieve credential. Check passphrase or UI server."
        info "Make sure dk UI is running: dk gui"
    fi
}

find_by_provider() {
    local provider="$1"
    check_broker
    say "Searching for $provider credentials..."
    
    curl -sf -X POST "$UI/api/autofill" \
        -H "Content-Type: application/json" \
        -d "{\"provider_id\":\"$provider\"}" 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
matches = data.get('matches', [])
if not matches:
    print('  No credentials found for $provider')
    print('  Add one with: dk add --label \"$provider Key\" --provider $provider --secret ...')
    sys.exit(0)
for m in matches:
    print(f'  {m[\"id\"][:8]:10} {m[\"label\"]:<28} {m.get(\"username\", \"-\")}')
print()
print('  To copy: autofill.sh --copy <id>')
" || {
        warn "Could not search; try dk list"
    }
}

find_by_url() {
    local url="$1"
    check_broker
    say "Searching for credentials matching $url..."
    
    curl -sf -X POST "$UI/api/autofill" \
        -H "Content-Type: application/json" \
        -d "{\"url\":\"$url\"}" 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
matches = data.get('matches', [])
if not matches:
    print('  No credentials found for this URL.')
    sys.exit(0)
for m in matches:
    print(f'  {m[\"id\"][:8]:10} {m[\"label\"]:<28} {m[\"provider_label\"]:<16} {m.get(\"username\", \"-\")}')
" || warn "Could not search"
}

# --- Main ---

# Check for help
if [ $# -eq 0 ] || [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "dk autofill helper"
    echo
    echo "Usage:"
    echo "  ./autofill.sh                    list all credentials"
    echo "  ./autofill.sh <provider>         find and copy credential for a provider"
    echo "  ./autofill.sh --list             list all credentials"
    echo "  ./autofill.sh --copy <id>        copy a credential to clipboard"
    echo "  ./autofill.sh --url <url>        find credentials for a URL"
    echo "  ./autofill.sh --help             this help"
    echo
    echo "Examples:"
    echo "  ./autofill.sh openrouter          # get your OpenRouter key"
    echo "  ./autofill.sh --url api.github.com # get GitHub credentials"
    echo "  ./autofill.sh --copy abc123        # copy by record id"
    exit 0
fi

case "$1" in
    --list|-l)
        list_credentials
        ;;
    --copy|-c)
        if [ -z "${2:-}" ]; then
            warn "Usage: autofill.sh --copy <record-id>"
            exit 1
        fi
        copy_credential "$2"
        ;;
    --url|-u)
        if [ -z "${2:-}" ]; then
            warn "Usage: autofill.sh --url <url>"
            exit 1
        fi
        find_by_url "$2"
        ;;
    *)
        # Assume it's a provider name
        find_by_provider "$1"
        ;;
esac