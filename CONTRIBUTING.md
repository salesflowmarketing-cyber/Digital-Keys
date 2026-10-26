# Contributing to Digital Keys

Thanks for taking a look. This is a security tool, so the review bar is higher than
usual and the rules are deliberately explicit.

## Before you start

- **Security bugs go to [`SECURITY.md`](SECURITY.md), never to a public issue.**
- For anything larger than a typo, open an issue first. It is cheaper than a rejected PR.
- By contributing you agree your work is licensed under the project's MIT licence
  (inbound = outbound). No CLA is required.

## Development setup

```bash
sudo dnf install python3 python3-pip python3-tkinter   # Fedora
git clone https://github.com/salesflowmarketing-cyber/Digital-Keys.git
cd Digital-Keys
python3 -m venv digital-keys-venv
source digital-keys-venv/bin/activate
pip install -e .
```

Run everything:

```bash
dk selftest
```

Or one suite at a time:

```bash
python -m unittest tests.test_crypto     # 23 crypto / vault checks
python tests/redteam.py                  # 84 adversarial checks
python tests/e2e_live.py                 # 29 real-HTTP checks
python tests/test_agent_flow.py          # 17 agent-flow checks
```

**All 153 checks must pass.** A PR that reduces coverage is not accepted.

## What a good PR looks like

1. **One concern per PR.** A rename plus a refactor plus a feature is three PRs.
2. **Tests come with the change.** If it touches the broker, the vault, or the control
   channel, add a red-team case proving the attack you are blocking now fails.
3. **Explain the threat.** In the description, state what an attacker could do before
   your change and what they cannot do after.
4. **No new dependencies without justification.** Every dependency is attack surface in
   a credential store. Prefer the standard library.
5. **No secrets, ever.** Not in tests, not in fixtures, not in commit messages. Use
   obviously fake values like `sk-test-not-a-real-key`.

## Code style

- Python 3.11+, standard library typing.
- Format with `ruff format` if available; `black` otherwise. Consistency inside a file
  matters more than a global style war.
- Keep functions small and named for what they *guarantee*, not what they do.
- Comments should explain *why*, especially for security decisions. `# FIX:` markers
  are used in-tree to record a past vulnerability; keep that convention.

## Security review checklist

A change touching any of these gets extra scrutiny:

| Area | Questions |
|---|---|
| Vault / crypto | Does plaintext escape a `with` block? Is AAD binding preserved? Does the passphrase verifier still leak? |
| Broker | Is the path canonicalised **before** the scope check? Is the dialled IP the validated IP? Can a header inject a newline? |
| Credential handling | Can the secret reach a log, an exception, a response body, or the audit trail? |
| Control channel | Is authentication checked *before* any state change? Can an agent reach a control route? |
| Files | Is the vault written `0600` atomically? Are temp files cleaned up on failure? |

## Commit messages

Conventional-ish, imperative, and specific:

```
broker: reject requests whose query string contains the secret

Previously a token scoped to /v1/search could echo the injected key back
through a reflected `q` parameter. The scrubber now also scans the query
string before the response leaves the lease.
```

## Reviewing

- Be direct about technical problems; assume good faith about the person.
- "This is wrong because X" is welcome. Credentials are at stake.
- Disagreement is fine. Unstated assumptions are not.

## Licence

MIT. See [`LICENSE`](LICENSE). By submitting a contribution you confirm you have the
right to license it under these terms.
