# Third-party notices

Digital Keys is MIT licensed. It depends on the following projects at runtime.
All are permissive and compatible with MIT redistribution. **No GPL or AGPL code is
linked, vendored, or required.**

## Runtime dependencies

| Package | Licence | Used for |
|---|---|---|
| [argon2-cffi](https://github.com/hynek/argon2-cffi) | MIT | Argon2id key derivation (via `argon2.low_level`) |
| [cryptography](https://github.com/pyca/cryptography) | Apache-2.0 OR BSD-3-Clause | AES-256-GCM and HKDF |
| [customtkinter](https://github.com/TomSchimansky/CustomTkinter) | MIT | Native desktop GUI |
| [Pillow](https://github.com/python-pillow/Pillow) | HPND (MIT-CMU) | Window icon loading |
| [Tk / Tcl](https://www.tcl.tk/) | Tcl/Tk licence (BSD-style) | GUI toolkit, installed with Python |

Apache-2.0 is compatible with MIT for distribution provided the Apache notice and
`NOTICE` obligations are met for the `cryptography` package; those obligations are
satisfied by shipping its own licence and notices, which pip installs alongside it.

## Development-only

| Package | Licence | Used for |
|---|---|---|
| [setuptools](https://github.com/pypa/setuptools) | MIT | Build backend |

## Prior art and inspiration

Digital Keys is an **independent implementation**. It did not copy source code,
documentation, or UI from any commercial product. The general architecture —
"agent holds a short-lived token instead of a credential" — is a common pattern in
credential brokers and password managers; patterns are not copyrightable.

Ideas that informed the design (no code taken):

- Capability-token delegation rather than secret sharing
- Hash-chained audit logs
- Provider preset catalogues

If you believe something in this repository is misattributed, open an issue and it
will be corrected or removed.

## Icons

The icons in `digital_keys/static/` were generated for this project.
