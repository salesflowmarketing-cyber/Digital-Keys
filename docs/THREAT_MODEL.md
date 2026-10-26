# Threat model

Written before the code, and meant to be corrected when the code teaches you
something new. If you find a way around a claim here, that is a bug report, not
a clever user.

## What Digital Keys is for

An AI coding agent (opencode, goose, Claude Code, anything) needs an API key to
call a provider. The usual options are both bad:

1. Put the real key in the agent's config or environment. The agent can read
   it, print it, include it in a request to a server you do not control, or
   write it into a file it later uploads.
2. Use a hosted broker. That broker now holds your key in plaintext, and you
   are trusting a stranger's server and their operator's access controls.

Digital Keys is a third option: the key lives only in an encrypted file on your own
machine, and an agent can ask to *use* a credential without ever holding it.

## The one rule

> **The agent must never control where a secret is sent.**

If an agent can choose the destination, it can choose the destination to be a
server it runs, and your key walks out of the vault in a single request. This is
not theoretical. The first version of this project had exactly that bug, and a
red-team script exfiltrated the live key from it in one call.

Everything in `broker.py` exists to make that bug structurally impossible:

| Control | Where | What it stops |
| --- | --- | --- |
| Origin pinning | `provider_origin()` | Agent supplying a host, port, or scheme |
| Path canonicalisation | `sanitise_path()` | Absolute URLs, `//host`, userinfo, traversal, encoded traversal, CR/LF |
| Segment-boundary prefix match | `_path_within()` | `/v1/keys` matching a grant for `/v1/key` |
| Single-use capabilities | `CapabilityStore.redeem()` | Replay of a leaked token |
| Header allowlist | `sanitise_headers()` | `Authorization`, `Host`, `Cookie`, `X-Forwarded-*`, `X-Original-URL` |
| Non-public IP refusal | `resolve_destination()` | SSRF at `169.254.169.254`, RFC1918, loopback, CGNAT |
| Per-record AAD binding | `vault.py` | Moving a ciphertext between records |
| One-shot lease | `SecretLease` | Vault staying open after a request, a timeout, or a crash |
| Response scrubbing | `_scrub_response()` | A provider echoing your key back to the agent |
| Redacted audit | `AuditLog.redacted()` | The audit log becoming a leak |

## Adversary: a malicious agent

With a valid, human-approved grant for one credential. Can it get the key?

- Read the key out of a response? No — the broker never puts it in one, and
  scrubs echoes.
- Learn the key length or prefix? No.
- Redirect the request to a host it controls? No — origin is pinned to the
  provider, absolute URLs are rejected, redirects are not followed.
- Steal it via headers? No — auth-bearing and forwarding headers are dropped
  and the provider's own headers are applied last.
- Exfiltrate via DNS? No — the host comes from vault config; the agent cannot
  add a host.
- Replay the token? No — single use by default, short TTL, human can revoke
  everything instantly.
- Escalate to a different record or provider? No — the grant names one record
  and one provider.

**Residual risk:** an approved request's *response* is shown to the agent. If
you point a provider at an attacker-controlled endpoint on purpose, you have
granted them that. Custom providers are the user's responsibility, which is why
`resolve_destination` refuses internal addresses and the UI is expected to
print the destination at approval time.

## Adversary: malware running as your user

Out of scope, and no amount of crypto changes that. If something can read your
process memory, read your `~/.local/share/digital-keys/vault.json`, or keylog you,
it can get the key while you use it. Digital Keys does not claim to stop this.

What it does do is shrink the window: the vault key only exists in memory
between a successful authentication and the completion of one request.

## Adversary: someone with the encrypted file

Without the passphrase, they get Argon2id at 64 MiB / 3 passes and AES-256-GCM.
They get no metadata either — labels, usernames, URLs, and notes are inside the
ciphertext, not beside it.

A weak passphrase is still a weak passphrase. Digital Keys requires 12+ characters
at creation and says so; it cannot stop you choosing `password1234`.

## Adversary: another local process, or a web page

Two different attackers, two different answers.

**A browser page.** Loopback is reachable from JavaScript, so an unauthenticated
local API is a real attack surface: any site could POST `/v1/grant` and grind
the passphrase. The control API is now split off the agent listener entirely,
and the TCP form demands a bearer token that a page cannot read (it is a file
outside the browser's reach, and the response headers forbid CORS). A page can
still reach `/v1/health` and `/v1/providers`, which are metadata-only.

**Another process running as your user.** It can read `control.token` and can
connect to the control socket, because it is you. The Unix socket's
`SO_PEERCRED` check confirms *which user* connected, not *which program*. This
is the same boundary as `ssh-agent`: a same-user process can use the agent.
Digital Keys narrows the window and keeps the passphrase out of the loop, but
it does not claim to survive malware running as you — see the section above.

**A different user on the same machine.** Cannot connect to the socket (mode
`0600`, parent directory `0700`) and cannot read the token (`0600`). Both are
enforced by the kernel, and both are asserted in the test suite.

## Adversary: cloud metadata services

A custom provider pointing at `169.254.169.254` turns the broker into an SSRF
gun aimed at your instance credentials. Refused: `resolve_destination` resolves
the host itself and rejects loopback, private, link-local, CGNAT, and
IPv4-mapped equivalents. Local providers like Ollama need an explicit
`--allow-private`, which is a decision the operator makes out loud.

## Honest limitations

These are real, and none of them are papered over:

1. **Linux autofill does not hide the secret from the OS.** A target app has to
   receive the value, and synthetic input (XTEST, uinput, virtual keyboard)
   passes through the input stack. Digital Keys can remove Android's Autofill
   Service from the path; it cannot create a channel where the destination app
   receives plaintext and nothing else does. Earlier drafts of this project
   claimed otherwise. They were wrong, and the claim was removed.

2. **Wayland blocks global input by design.** Generic desktop autofill on
   Wayland requires the compositor's cooperation, and modern Fedora defaults to
   Wayland. A browser extension is the honest primary path; synthetic typing is
   a labelled fallback.

3. **No memory zeroisation.** Python strings are garbage collected, not wiped.
   The vault key is dropped when a handle seals, and the reference
   implementation is careful, but "the bytes are gone" is not something this
   codebase can promise. A native client should use mlock and explicit
   overwrites.

4. **The reference broker holds a passphrase in memory for its lifetime.**
   `dk serve` reads it once and reuses it per request. That is *not* the
   per-request authentication the final product requires. The final desktop
   client prompts every time and keeps no long-lived secret. The `unlock_fn`
   seam is where that prompt lives.

5. **Recovery is not implemented.** A lost passphrase means a lost vault. There
   is no escrow and there will not be one.

6. **Single-process, no multi-user support.** The capability store is in memory
   and shared across all callers, so it is one-user by construction.

7. **Provider requests are proxied verbatim.** Digital Keys injects auth; it does
   not rewrite request bodies. A provider that needs a transformed body is not
   supported yet (OAuth refresh in particular).

8. **Timing side channels on unlock are not fully mitigated.** Argon2id makes
   the work constant, but a local attacker able to time the full HTTP request
   may distinguish "wrong passphrase" from "no such provider".

## Control channel

Agents and the human talk to two different listeners. This is the single most
important structural decision in the broker: an agent that can reach
`/v1/request` has no route at all to `/v1/grant`.

| | Agent listener | Control listener |
|---|---|---|
| Bind | `127.0.0.1:<port>` | Unix socket, or `127.0.0.1:<random>` |
| Routes | `/v1/health`, `/v1/providers`, `/v1/request` | `/v1/grant`, `/v1/pending`, `/v1/audit`, `/v1/emergency-stop`, `/v1/token/rotate` |
| Proof | short-lived capability token | peer UID, or 32-byte bearer token |
| Holds a secret | no | no |

**Transport choice.** `dk serve --control-transport auto` (the default) uses
the Unix socket when the platform has `SO_PEERCRED`, and TCP + token otherwise.
That is Linux and macOS on one side, Windows on the other. Windows has
`AF_UNIX` but no peer credentials, so a socket there would be no stronger than
an open port; the token path is used instead. Force it with `unix` or `tcp`.

**Token lifetime.** The token is minted at `dk serve`, written `0600` to
`$XDG_RUNTIME_DIR/digital-keys/control.token`, and deleted on clean shutdown.
A token from a previous run is worthless. `dk token rotate` replaces it
without restarting the broker.

**Guessing.** `/v1/grant` still takes the vault passphrase, because the broker
must decrypt the vault to mint a capability. Failures are counted per peer in a
sliding window: five in sixty seconds locks the caller out for thirty seconds,
then sixty, then two minutes, up to fifteen. Transport auth and passphrase
guesses are counted in **separate** buckets — otherwise a correct token would
clear the guess counter on every attempt.

**Lockdown mode is opt-in.** `dk serve --lockdown` also demands the control
credential on `/v1/request`. It is off by default because it destroys the
product's central promise: that an agent holds exactly one short-lived token
and nothing else. Turning it on means handing every agent a long-lived secret,
which is strictly worse than the default for the threat the broker exists to
address. Use it only if you have a specific reason.

## Not yet implemented

- Desktop tray app, global hotkey, credential picker
- Browser extension
- Windows Credential Provider
- Android AutofillService with per-dataset authentication
- OAuth refresh-token flows
- Vault migration and format versioning beyond `generation`
- Rate limiting on the broker

## Test coverage for the claims above

- `tests/redteam.py` — 57 checks, including 20 hostile paths, header smuggling,
  scope boundaries, and live end-to-end exfiltration attempts
- `tests/e2e_live.py` — 29 checks over real HTTP against a real server
- `tests/test_agent_flow.py` — 17 checks simulating what an agent actually does
- `tests/test_crypto.py` — 23 unit tests on nonce uniqueness, AAD binding, tamper
  detection, and reseal-on-exception

## Fixed in 0.1.1 (each has a regression test)

**Path scope bypass (HIGH).** `handle_request()` scope-checked the capability
against the raw, un-canonicalised path and sanitised it afterwards. A grant
scoped to `/v1/keys` was therefore usable for `/v1/keys/../../admin`, which
canonicalises to `/admin`. Dot-segments are now rejected outright rather than
resolved, percent-encoded dot-segments are caught, decoded `?`/`#` are
re-encoded so a query boundary cannot be smuggled, and the scope check runs on
the canonical path. Tests: `test_path_scope_bypass`,
`test_dot_segments_rejected_not_cleaned`, `test_reserved_chars_stay_encoded`,
`test_ordinary_paths_still_work`.

**DNS rebinding (HIGH).** `resolve_destination()` resolved the hostname,
validated every returned address, and stored one as `Destination.pinned_ip`.
`_send()` then constructed `http.client.HTTPSConnection(parts.hostname, ...)`,
which performs its own DNS lookup at connect time. The validated IP was never
used, so a hostname could resolve to a public address during validation and to
`127.0.0.1` when the socket was opened — the entire SSRF check was bypassable
by any name the agent could get a provider to point at. Connections now dial
the validated IP directly via `_PinnedHTTPConnection` /
`_PinnedHTTPSConnection`, which override `connect()` to call
`socket.create_connection((pinned_ip, port))` while passing the real hostname to
TLS as `server_hostname`, so SNI and certificate validation are unchanged. Test:
`test_pinned_ip_reaches_the_socket`.

**Secret lifetime (MEDIUM).** `_scrub_response()` ran *after* the
`SecretLease` context had exited, so the plaintext `record` object stayed
reachable during scrubbing. Scrubbing now runs inside the lease and references
are dropped immediately afterwards. Python still offers no true zeroisation;
see the limitations section. Test: `test_scrub_runs_inside_the_lease`.

**Capability reuse flag (LOW).** `--reuse` was parsed but the payload always
sent `single_use: true`, so the flag was inert.

**Dangling record on bad provider id (LOW).** `dk add` wrote the record and
then validated the provider reference; a typo like `--provider openrower`
reported an error but left a record persisted with a broken provider link. The
provider is now resolved before the write.

**Agent helper ignored a custom broker port (LOW).** `request_grant()` did not
forward the port to `dk grant`, so it only ever worked on the default 8787.

## Still open — why this is alpha

These are unchanged and are the reason the README says do not use real keys:

1. ~~The local control API has no authentication.~~ **Fixed in 1.2.0.** The
   privileged routes (`/v1/grant`, `/v1/pending`, `/v1/audit`,
   `/v1/emergency-stop`) are no longer served on the agent listener at all.
   They live on a separate control listener: a `0600` Unix socket under
   `$XDG_RUNTIME_DIR` whose peer is verified with `SO_PEERCRED` on Linux, or
   loopback TCP guarded by a 32-byte bearer token where the kernel cannot
   report a peer identity. Repeated passphrase failures trip an escalating
   lockout (5 failures in 60 s → 30 s, doubling to 15 min). See
   "Control channel" below for what this does *not* protect against.
2. `dk serve` captures the passphrase in a closure and holds it for the
   process lifetime. The vault *file* is resealed per request, but the
   passphrase is not re-verified per request, which is not the product's
   required state machine. A desktop approval process must own per-use
   authentication.
3. `--allow-private` is one global flag that simultaneously permits private
   destinations, permits plain HTTP, and can be combined with a non-loopback
   bind. It must be split into per-provider policy, and the broker must refuse
   to bind anywhere but loopback regardless.
4. No streaming. `_send()` reads the whole response before parsing it, so SSE
   and token-by-token LLM output do not work. A real model agent will fail
   even though the test suite passes.
5. The audit log is in-memory only; `AuditLog.path` is unused. No persistence,
   no integrity protection, no rotation.
6. Vault concurrency and migration are unimplemented: no file locking, no
   generation counter, no migration path, `DIR_MODE` is never applied, and
   `is_open()` is misleading.
7. No OAuth refresh, no recovery key, no custom-provider UI, no record
   edit/delete.
8. Python cannot guarantee memory zeroisation; a swapped-out process image or
   core dump can contain plaintext.

Test-suite weaknesses are also recorded in the README's own history: a
`test_record_aad_binding` case mutated in-memory state without flushing, one
agent-flow assertion ended in `or True` (making it tautological), and there are
no real streaming, concurrency, or DNS-rebinding *end-to-end* tests — the
rebinding test is currently a structural assertion about the call graph.
