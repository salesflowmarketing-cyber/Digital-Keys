"""
digital_keys.crypto - primitive layer.

Everything below is deliberately boring: Argon2id for key stretching, AES-256-GCM
for authenticated encryption, HKDF for subkey separation. No home-rolled
anything.

Design notes that matter for the rest of the codebase:

* Subkeys are *always* derived from the master key via HKDF with an explicit
  purpose string. We never reuse the raw stretched key as an AES key and never
  derive a second key by "just hashing" something ad hoc.
* Every encrypt() call takes an `aad` argument. Callers MUST bind identity into
  it (record id, vault generation, provider id) so a ciphertext cannot be moved
  between records or replayed against a different slot.
* Nonces are 96-bit random, never counters, never reused across processes
  under the same key. That is the single hardest rule in AEAD and we keep it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass
from hashlib import sha256

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Bumped whenever the derivation scheme changes in a non-compatible way.
# A vault records the id it was created with and refuses to open otherwise
# rather than silently guessing.
KDF_ID = "argon2id-v1"
CIPHER_ID = "aes-256-gcm-v1"

# OWASP-aligned Argon2id parameters. 64 MiB / 3 passes is the current
# recommendation for interactive use; the id is stored per-vault so we can
# raise it later without breaking existing files.
DEFAULT_KDF = {
    "id": KDF_ID,
    "time_cost": 3,
    "memory_kib": 65536,
    "parallelism": 4,
    "salt_len": 16,
    "key_len": 32,
}

SALT_LEN = 16
NONCE_LEN = 12  # 96-bit, the size AES-GCM is actually specified for
KEY_LEN = 32
TAG_LEN = 16


class CryptoError(Exception):
    """Base class so callers can catch all dk crypto failures at once."""


class InvalidTag(CryptoError):
    """Authentication failed: wrong key, or the data was tampered with."""


class VaultCorrupt(CryptoError):
    """The file is structurally wrong - bad magic, bad version, truncated."""


class UnsupportedVault(CryptoError):
    """The vault was made by a newer/different version of dk."""


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def random_bytes(n: int) -> bytes:
    return os.urandom(n)


def constant_time_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


# --------------------------------------------------------------------------
# Key derivation
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class KdfParams:
    time_cost: int
    memory_kib: int
    parallelism: int
    salt_len: int = SALT_LEN
    key_len: int = KEY_LEN

    @classmethod
    def default(cls) -> "KdfParams":
        return cls(
            time_cost=DEFAULT_KDF["time_cost"],
            memory_kib=DEFAULT_KDF["memory_kib"],
            parallelism=DEFAULT_KDF["parallelism"],
        )

    def to_dict(self) -> dict:
        return {
            "id": KDF_ID,
            "time_cost": self.time_cost,
            "memory_kib": self.memory_kib,
            "parallelism": self.parallelism,
            "salt_len": self.salt_len,
            "key_len": self.key_len,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "KdfParams":
        if d.get("id") != KDF_ID:
            raise UnsupportedVault(f"unknown kdf id: {d.get('id')!r}")
        return cls(
            time_cost=int(d["time_cost"]),
            memory_kib=int(d["memory_kib"]),
            parallelism=int(d["parallelism"]),
            salt_len=int(d.get("salt_len", SALT_LEN)),
            key_len=int(d.get("key_len", KEY_LEN)),
        )


def stretch(passphrase: str, salt: bytes, params: KdfParams) -> bytes:
    """
    Argon2id -> 32 byte master key.

    We pass the passphrase as raw bytes to hash_secret_raw so no platform
    string-encoding surprises (and no accidental NUL truncation) can change the
    derived key between Linux / Windows / Android.
    """
    if not isinstance(params, KdfParams):
        raise TypeError("params must be KdfParams")
    raw = hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_kib,
        parallelism=params.parallelism,
        hash_len=params.key_len,
        type=Type.ID,
    )
    return raw


# --------------------------------------------------------------------------
# Subkey separation
# --------------------------------------------------------------------------

# Changing any of these strings silently breaks every existing vault, so they
# are versioned constants. Never edit one in place - add a new one.
INFO_VAULT_DATA = b"digital-keys/v1/vault-data"
INFO_RECOVERY = b"digital-keys/v1/recovery"
INFO_TOKEN = b"digital-keys/v1/broker-token"
INFO_PIN_GATE = b"digital-keys/v1/pin-gate"
INFO_HANDLE = b"digital-keys/v1/agent-handle"


def hkdf_sha512(ikm: bytes, info: bytes, length: int = 32, salt: bytes = b"") -> bytes:
    """RFC 5869 HKDF. Used instead of a bare hash so subkeys are domain-separated."""
    if salt == b"":
        salt = bytes([0x00]) * 32  # RFC 5869: absent salt == HashLen zeros
    prk = hmac.new(salt, ikm, hashlib.sha512).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha512).digest()
        okm += block
        counter += 1
    return okm[:length]


def derive_subkey(master: bytes, info: bytes) -> bytes:
    return hkdf_sha512(master, info, length=KEY_LEN)


# --------------------------------------------------------------------------
# AEAD
# --------------------------------------------------------------------------


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """
    AES-256-GCM. Returns (ciphertext_including_tag, nonce).

    The caller is responsible for supplying non-varying `aad` for any given
    plaintext. In this codebase aad always includes the record's identity.
    """
    if len(key) != KEY_LEN:
        raise CryptoError(f"key must be {KEY_LEN} bytes, got {len(key)}")
    nonce = random_bytes(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return ct, nonce


def decrypt(key: bytes, ciphertext: bytes, nonce: bytes, aad: bytes) -> bytes:
    if len(key) != KEY_LEN:
        raise CryptoError(f"key must be {KEY_LEN} bytes, got {len(key)}")
    if len(nonce) != NONCE_LEN:
        raise InvalidTag("bad nonce length")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:  # cryptography raises InvalidTag
        raise InvalidTag(str(exc)) from exc


def sha256_hex(data: bytes) -> str:
    return sha256(data).hexdigest()
