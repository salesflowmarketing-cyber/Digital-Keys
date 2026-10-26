# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] — 2026-10-26

The **Digital Keys** release. A full rename from Highline Vault, with a deliberate
format break so the on-disk identifiers stop carrying the old name.

### Changed — breaking

- **Project name:** Highline Vault → **Digital Keys**.
- **Python package:** `highline_vault` → `digital_keys`.
- **Primary command:** `hlv` → **`dk`**. `hlv`, `hs`, `digital-keys` remain as
  aliases so existing scripts keep working.
- **Environment variables:** `HIGHLINE_VAULT_*` → `DIGITAL_KEYS_*`
  (`PATH`, `PASSPHRASE`, `BROKER_URL`, `BROKER_PORT`, `DIR`, `UI_URL`).
  The old names are still read as a fallback.
- **Default vault path:** `~/.local/share/highline-vault/vault.json` →
  `~/.local/share/digital-keys/vault.json`.
- **Vault format identifier:** `highline-vault` → `digital-keys`.
- **Key-derivation labels:** `hlv/v1/*` → `digital-keys/v1/*`.
- **AAD prefix and passphrase sentinel:** `highline-vault-*` → `digital-keys-*`.

> Because the HKDF labels and AAD prefix changed, **a 1.x vault cannot be opened by
> 2.0**. Opening one now raises a specific `UnsupportedVault` message instead of a
> confusing "wrong passphrase". Create a new vault and re-add your credentials.

### Added

- `SECURITY.md` with a private disclosure channel, scope, and design commitments.
- `CONTRIBUTING.md` with the security review checklist.
- `THIRD-PARTY.md` listing every dependency licence; confirms no GPL/AGPL code.
- `CHANGELOG.md` (this file).
- `Pillow` is now declared in `pyproject.toml` (it was in `requirements.txt` only,
  so `pip install -e .` produced a GUI without icon support).
- Packaging metadata: authors, classifiers, keywords, project URLs.
- README documents the `python3-tkinter` system requirement; without it `dk gui`
  fails on a fresh Fedora install.

### Fixed

- `_get_passphrase()` looked up the same environment variable twice, so the
  documented legacy fallback never worked.
- GUI launcher and desktop-entry names were inconsistent with the CLI name.

---

## [1.2.0] — 2026-10-25

### Added

- **Authenticated control channel.** `dk grant`, `dk stop`, `dk audit` and
  `dk token rotate` now require proof of identity:
  - POSIX: a `0600` Unix socket under `$XDG_RUNTIME_DIR`, peer verified with
    `SO_PEERCRED` (same UID only).
  - Windows: loopback port plus a 32-byte bearer token stored `0600`.
- **Rate limiting and lockout** (`ratelimit.py`): repeated passphrase failures
  back off 5-in-60 s → 30 s, doubling to 15 minutes.
- `dk token show` / `dk token rotate`.
- `--control-transport {auto,unix,tcp}` on `dk serve`.

### Changed

- The control routes are not routable from the agent listener at all; an agent
  cannot mint its own capability even with the URL.

---

## [1.1.0] — 2026-10-25

### Changed

- Renamed the project from Highline Shield to Highline Vault.
- Package `highline_shield` → `highline_vault`; CLI `hs` → `hlv` (`hs` kept).
- Unified the vault path. The CLI and GUI previously used **different** default
  paths and silently opened different vaults.

### Fixed

- `os.fchmod` was called unconditionally and crashed on Windows; it is now guarded
  and falls back to `os.chmod` after close.
- `install-desktop.sh` invoked a `ui` command that did not exist and referenced SVG
  icons that were never shipped.
- `docs/AGENT_SKILL.md` contained an import statement that was not valid Python.

---

## [1.0.0] — 2026-10-02

### Added

- Encrypted vault: Argon2id (64 MiB, t=3, p=4) + AES-256-GCM, per-record AAD.
- Broker with destination pinning, SSRF refusal, path canonicalisation, header
  allowlisting, and response scrubbing.
- Single-use capability tokens with TTL, provider, method and path-prefix scoping.
- Native CustomTkinter desktop GUI.
- CLI: `init`, `providers`, `add`, `list`, `show`, `grant`, `serve`, `stop`,
  `audit`, `delete`, `gui`, `selftest`.
- 14-entry provider catalogue with hand-verified auth quirks.
- 153 automated checks: crypto, red-team, live end-to-end, agent flow.
