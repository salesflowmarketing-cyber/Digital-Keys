# Digital Keys agent skill

Paste this into opencode, goose, or any agent's system prompt / rules file.

---

You have access to a **Digital Keys** broker running on `http://127.0.0.1:8787`.

It holds API credentials for the user. **You will never see a credential.** You
ask the user to approve a credential, and the broker attaches the real key to
your request for you.

## Rules

1. **Never ask the user to paste an API key into the chat, a file, or your
   config.** If you need a credential, request it from Digital Keys. If Digital Keys
   cannot serve it, tell the user and stop.
2. **Only ever send a relative path**, like `/api/v1/chat/completions`. Never a
   full URL. The broker rejects full URLs on purpose — that rejection is the
   security model, not an inconvenience.
3. **Do not try to set `Authorization`, `Host`, `Cookie`, `X-Api-Key`, or any
   `X-Forwarded-*` header.** They will be dropped, and trying is a sign you are
   about to do something you should not.
4. **One request, one approval.** Tokens are single-use. If you need two
   requests, ask the user twice. Do not batch a retry loop.
5. **Never log, print, echo, or save a response that might contain a key.**
6. If a request fails, report the error to the user. Do not retry with a
   different destination or attempt to route around the broker.
7. **You do not have, and must never ask for, the control credential.** The
   routes that mint capabilities (`/v1/grant`), read the audit log, or revoke
   grants live on a separate control channel. They are not reachable from the
   agent listener, and they are not your business. If you need a credential,
   ask the human; they will run `dk grant` themselves.

## How to use it

```python
import desktop.agent as dk

dk.health()                      # is the broker up?
dk.list_providers()              # what credentials are available
# -> [{"id": "openrouter", "base_url": ..., "records": [{"id": "...", "label": "..."}]}]

token = dk.request_grant(record_id)          # user approves in their terminal
status, body = dk.call(token, "POST", "/api/v1/chat/completions",
                       body={"model": "...", "messages": [...]})
```

`request_grant` prompts the human to type their vault passphrase. That is the
only time a human is involved, and it is the only thing standing between you
and their credentials.

Other helpers:

- `dk.audit(50)` — recent broker activity (contains no secrets). This is a
  control-channel route; in a real deployment the agent cannot reach it.
- `dk.emergency_stop()` — kill every live grant immediately. Also a
  control-channel route. A real agent should ask the human to run `dk stop`.

## If the broker is unreachable

Tell the user to run `Digital Keys serve` in a terminal. Do not ask them for the
passphrase and do not suggest they paste keys into the conversation.

## OpenAI-compatible note

For `openai`, `openrouter`, `cerebras`, `mistral`, `nanogpt` the shapes are
familiar. `anthropic` is not OpenAI-compatible: it is `POST /v1/messages` with
`{"model": ..., "max_tokens": ..., "messages": [...]}`, and the required
`anthropic-version` header is already set by the provider config. `browserbase`
authenticates with `x-bb-api-key`, which the broker handles for you.
