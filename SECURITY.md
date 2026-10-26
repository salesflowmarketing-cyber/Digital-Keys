# Security Policy

Digital Keys stores credentials. A vulnerability here can expose the user's entire
account portfolio, so reports are taken seriously and answered quickly.

## Supported versions

| Version | Supported |
|---|---|
| 2.x | ✅ active |
| 1.x | ❌ no longer maintained (pre-rename format, cannot read 2.x vaults) |

## Reporting a vulnerability

**Please do not open a public issue for a security bug.**

Use GitHub's private reporting channel:

1. Go to <https://github.com/salesflowmarketing-cyber/Digital-Keys/security/advisories/new>
2. Describe the issue, the version, and the steps to reproduce.
3. If you prefer email, open a *non-sensitive* issue asking for a contact address —
   do not include the details there.

### What to include

- Digital Keys version (`dk --version`, or the commit hash)
- Platform and Python version
- The smallest reproduction you can manage
- What an attacker gains (secret disclosure, code execution, auth bypass, …)

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement | within 72 hours |
| Initial assessment | within 7 days |
| Fix or mitigation | depends on severity; critical issues first |
| Credit | offered in `CHANGELOG.md` unless you prefer to stay anonymous |

Please give a reasonable window to ship a fix before public disclosure. Ninety days
is the usual norm; sooner if a fix is already released.

## Scope

**In scope**

- Vault cryptography: key derivation, AEAD use, AAD binding, passphrase verification
- Broker: SSRF, DNS rebinding, destination pinning, path canonicalisation, header
  injection, credential leakage in responses, token replay or scope escape
- Control channel: authentication bypass, token theft, peer-UID confusion
- GUI/CLI: local privilege boundaries, unsafe file permissions, shell injection
- Supply chain: anything that would let a dependency compromise a vault

**Out of scope**

- Attacks that require the attacker to already have your user account, your unlocked
  vault, or root on the machine. At that point the vault is inside the trust boundary
  and no local password manager survives it.
- Physical attacks, cold-boot attacks, and memory scraping of a *running* process.
  Python cannot reliably zeroise memory; this is documented in
  [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) rather than hidden.
- Missing features (streaming, sync, audit persistence). These are known gaps, listed
  in the README status table — not vulnerabilities.
- Social engineering of the user.

## Design commitments

These are promises the project tries to keep. A bug that breaks one is in scope:

1. **The secret never reaches the agent.** Only a capability token crosses the wire.
2. **The vault is sealed outside a lease.** Plaintext exists only inside a `with` block.
3. **The control channel is authenticated before it can mint anything.**
4. **The validated IP is the dialled IP.** Resolution and connection are the same step.
5. **Fail closed.** Denial beats a permissive guess.
6. **No secret in logs, audit entries, traces, or error messages.**

## Known limitations

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). It is kept current, including the
items that are not yet fixed.

## Safe harbour

Good-faith research that follows this policy will not be pursued or reported. Do not
test against infrastructure you do not own, and do not access other people's vaults.
