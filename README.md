# 🔑 Digital Keys

**A local-first encrypted credential vault that AI agents can _use_ without ever _seeing_.**

Digital Keys keeps your API keys, tokens and passwords in one encrypted file on your
own machine. When an agent needs a credential, it gets a **short-lived, single-use
capability token** — never the secret itself. The broker injects the key at the last
hop, scrubs it from the response, and revokes the token.

No cloud. No account. No telemetry. One program.

**153 passing checks** · **14 built-in providers** · **MIT licensed** · **native desktop GUI**

---

## ✨ Why it exists

Pasting an API key into an agent's config file means handing that key to:

- the agent's logs and crash dumps,
- any telemetry or debug endpoint it talks to,
- every future tool that reads the same config,
- whoever gets the laptop.

Digital Keys inverts that. The agent holds a capability token that expires in minutes
and is bound to one provider, one method and one path prefix. The real key never leaves
the vault.

> **Not affiliated with, endorsed by, or derived from any commercial credential-broker
> product.** Digital Keys is an independent MIT-licensed implementation. See
> [`THIRD-PARTY.md`](THIRD-PARTY.md) for dependency licences.

## ✨ Features

- **🔐 Encrypted local vault** — Argon2id (64 MiB, t=3, p=4) + AES-256-GCM, every record bound to its own ID as AAD
- **🖥️ Native desktop GUI** — CustomTkinter, dark theme, no browser needed
- **📋 Provider presets** — 14 hand-verified entries, plus fully custom providers
- **🔑 Capability tokens** — single-use, TTL-bounded, scoped to provider + method + path prefix
- **🛡️ Destination pinning** — DNS is resolved once, the validated IP is the IP that gets dialled (no rebinding)
- **🚫 SSRF guard** — loopback, link-local and private ranges refused unless explicitly allowed
- **📜 Audit trail** — every grant recorded; the secret never is
- **🛑 Emergency stop** — one command revokes every outstanding grant
- **🧹 Response scrubbing** — the secret is stripped from anything the agent receives
- **🔒 Authenticated control channel** — Unix socket with `SO_PEERCRED`, or loopback + bearer token on Windows

## 📦 Requirements

| Platform | Requirements |
|---|---|
| **Fedora / Linux** | Python 3.11+, `python3-tkinter` (**required for the GUI**), `python3-pip` |
| **Windows** | Python 3.11+ from python.org (includes Tk) |
| **macOS** | Python 3.11+ from python.org (includes Tk) |

Fedora, one line:

```bash
sudo dnf install python3 python3-pip python3-tkinter
```

Without `python3-tkinter` the CLI works, but `dk gui` fails with
`ModuleNotFoundError: No module named 'tkinter'`.

## 🚀 Quick Start

### One-command bootstrap

```bash
cd ~/repos/Digital-Keys
bash digital-keys.sh
```

Creates the virtualenv, installs the package, and runs the full test suite.

### Manual install

```bash
python3 -m venv digital-keys-venv
source digital-keys-venv/bin/activate
pip install -e .
```

### First vault

```bash
export DIGITAL_KEYS_PASSPHRASE="your-secure-passphrase"

dk init                    # creates ~/.local/share/digital-keys/vault.json (0600)
dk add --label "OpenAI" --provider openai --kind api_key --category llm --secret "sk-..."
dk list
dk show <record-id> --reveal
```

### Desktop GUI

```bash
dk gui
```

Or run `./install-desktop.sh` once to add **Digital Keys** to your app menu.

### Running the broker

```bash
dk serve                  # agent listener + control channel
dk grant <record-id>      # approve one single-use capability
dk audit                  # redacted audit tail
dk stop                   # revoke every outstanding grant
```

`dk serve` opens **two** listeners:

| Listener | Default bind | Routes | Proof required |
|---|---|---|---|
| Agent | `127.0.0.1:8787` | `/v1/health`, `/v1/providers`, `/v1/request` | short-lived capability token |
| Control | Unix socket `0600` (Linux/macOS) or `127.0.0.1` + bearer token (Windows) | `/v1/grant`, `/v1/pending`, `/v1/audit`, `/v1/emergency-stop`, `/v1/token/rotate` | peer UID, or bearer token |

The control routes are **not reachable from the agent listener** — an agent cannot
mint its own capability even if it knows the URL. On Linux and macOS the control
channel is a `0600` Unix socket whose peer is verified with `SO_PEERCRED`, so the
vault passphrase never crosses TCP. On Windows it falls back to a loopback port plus
a 32-byte token in `$XDG_RUNTIME_DIR/digital-keys/control.token` (mode `0600`).

```bash
dk serve --control-transport tcp   # force the token path
dk token show                      # print the control token
dk token rotate                    # replace it without restarting
```

Repeated passphrase failures lock the caller out (5 in 60 s → 30 s, doubling to 15
minutes). See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full model.

> **`--lockdown` is off by default, deliberately.** It also requires the control
> credential on `/v1/request`, which breaks the core guarantee that an agent holds
> exactly one short-lived token. Turning it on means giving every agent a long-lived
> secret. Only use it if you have a specific reason.

## 🔌 Agent integration

Agents (Goose, OpenCode, Claude Code, Cursor, or your own script) use capability
tokens that never reveal your keys. A minimal client is in
[`desktop/agent.py`](desktop/agent.py); the full contract is in
[`docs/AGENT_SKILL.md`](docs/AGENT_SKILL.md).

```python
import desktop.agent as dk

dk.health()                       # is the broker up?
dk.list_providers()               # what credentials exist (labels only)

token = dk.request_grant(record_id)          # the human approves in their terminal
status, body = dk.call(token, "POST", "/v1/chat/completions",
                        body={"model": "openai/gpt-4o", "messages": []})
```

The agent's config only ever contains:

```bash
DIGITAL_KEYS_BROKER_URL=http://127.0.0.1:8787
```

…and a token that expires. Never a provider key.

### The `/v1/request` contract

The agent posts the capability token plus the call it wants made:

```json
POST /v1/request
{
  "token": "cap_...",
  "method": "POST",
  "path": "/v1/chat/completions",
  "query": "",
  "headers": {},
  "body": {"model": "gpt-4o", "messages": []}
}
```

The broker then:

1. canonicalises `path` **before** checking scope (so `../` tricks cannot widen a grant),
2. redeems the token against its provider, method and path prefix,
3. resolves the destination once and dials the validated IP (no rebinding window),
4. injects the credential from the vault, inside the lease only,
5. scrubs the secret from the response before returning it.

Mint a token for a client with:

```bash
dk grant <record-id> --ttl 300          # prints JSON, including "token"
```

## 📋 Built-in providers

| Provider | CLI ID | Auth | Base URL |
|----------|--------|------|----------|
| Ollama | `ollama` | none (local) | http://localhost:11434 |
| OpenRouter | `openrouter` | Bearer | https://openrouter.ai/api/v1 |
| OpenAI | `openai` | Bearer | https://api.openai.com/v1 |
| Anthropic (Claude) | `anthropic` | Bearer + version | https://api.anthropic.com |
| Gemini (Google) | `gemini` | Query param | https://generativelanguage.googleapis.com |
| Cerebras | `cerebras` | Bearer | https://api.cerebras.ai |
| Mistral | `mistral` | Bearer | https://api.mistral.ai/v1 |
| Hugging Face | `huggingface` | Bearer | https://api-inference.huggingface.co |
| NanoGPT | `nanogpt` | Bearer | https://api.nano-gpt.com/api/v1 |
| OpenCode Zen | `opencode-zen` | Bearer | https://opencode.ai/zen/v1 |
| Tavily | `tavily` | Bearer | https://api.tavily.com |
| Firecrawl | `firecrawl` | Bearer | https://api.firecrawl.dev |
| Browserbase | `browserbase` | `x-bb-api-key` | https://api.browserbase.com/v1 |
| GitHub | `github` | Bearer | https://api.github.com |

### Custom providers

Anything not listed can be added through the **Custom Provider** tab in the GUI, or:

```bash
dk add --label "My Custom" --provider my-custom-api --kind api_key \
       --category custom --secret "key-123"
```

Custom providers get the same SSRF and destination-pinning rules as built-ins.

## 🧪 Tests

```bash
source digital-keys-venv/bin/activate
dk selftest

# Or individually:
python -m unittest tests.test_crypto        # 23 crypto / vault tests
python tests/redteam.py                     # 84 adversarial checks
python tests/e2e_live.py                    # 29 real-HTTP checks
python tests/test_agent_flow.py             # 17 agent-flow checks
```

153 checks total. The red-team suite covers SSRF, DNS rebinding, path traversal,
header injection, token replay, AAD swapping, and vault tampering.

## 📁 Project structure

```
Digital-Keys/
├── pyproject.toml            # packaging + entry points
├── digital_keys/             # the package
│   ├── gui.py                # native desktop GUI (CustomTkinter)
│   ├── cli.py                # command-line interface
│   ├── vault.py              # encrypted vault (Argon2id + AES-256-GCM)
│   ├── broker.py             # request broker: pinning, SSRF, injection, scrubbing
│   ├── providers.py          # built-in provider catalogue
│   ├── crypto.py             # key derivation and AEAD primitives
│   ├── records.py            # data model
│   ├── server.py             # HTTP listeners (agent + control)
│   ├── control.py            # control-channel authentication
│   ├── ratelimit.py          # lockout and throttling
│   └── static/               # app icons
├── desktop/agent.py          # agent-side client
├── tests/                    # 153 checks
├── docs/                     # threat model, agent skill, Android plan
├── digital-keys.sh           # bootstrap script
├── launch.sh                 # desktop launcher
├── install-desktop.sh        # app-menu integration
└── autofill.sh               # CLI autofill helper
```

## 🗺️ Status

Stable enough to use daily on a single machine.

| Area | State |
|---|---|
| Vault, broker, CLI, GUI | ✅ working |
| Control-channel authentication | ✅ Unix socket + peer UID, or bearer token |
| Streaming responses | ⚠️ buffered — SSE and token-by-token output not yet supported |
| Audit persistence | ⚠️ in-memory |
| Multi-device sync | ⏳ planned — copy `vault.json` today |
| Android | ⏳ design only ([`docs/ANDROID_PLAN.md`](docs/ANDROID_PLAN.md)) |

## 🔐 Security

Please read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) before trusting anything
important to this. Known limitations are listed there explicitly, including the ones
that are not yet solved.

To report a vulnerability, see [`SECURITY.md`](SECURITY.md).

## 📄 License

MIT © 2026 Highline Digital. See [`LICENSE`](LICENSE).

You may use, modify, redistribute and sell this software. Attribution is required
only in the sense the MIT licence specifies: keep the copyright notice.
