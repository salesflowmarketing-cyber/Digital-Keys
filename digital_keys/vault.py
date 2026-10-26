"""
digital_keys.vault - the encrypted store.

Two ideas drive this file.

1. The vault is SEALED by default. Creating an object does not decrypt
   anything. You must call `unlock(passphrase)` and it hands back an *open*
   handle; that handle is a context manager and it seals itself on exit, no
   matter how you leave. There is no "unlocked vault" variable that outlives a
   function call by accident, and no `session_timeout` knob. That was an
   explicit product decision: one authentication, one credential, sealed again.

2. A failed unlock tells you nothing. The only thing an attacker learns from a
   wrong passphrase is that a guess was wrong, same as a correct one would have
   been. Unlock cost is real Argon2id work either way, and the verification tag
   is checked before any record is touched.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterator

from .crypto import (
    INFO_VAULT_DATA,
    KdfParams,
    UnsupportedVault,
    VaultCorrupt,
    b64d,
    b64e,
    decrypt,
    derive_subkey,
    encrypt,
    random_bytes,
    SALT_LEN,
    stretch,
)
from .records import Category, Provider, Record, SecretKind

FORMAT_VERSION = 1
FILE_MODE = 0o600
DIR_MODE = 0o700

VAULT_AAD_PREFIX = b"digital-keys/v1/vault"


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class VaultSealed(Exception):
    """Raised when something tries to read a record while sealed."""


class VaultLocked(Exception):
    """Raised when a caller uses a handle after its context manager exited."""


@dataclass
class VaultFile:
    """The on-disk document. Everything here is safe to look at."""

    version: int
    kdf: dict
    salt: str
    # Each slot is encrypted under a distinct nonce. Both hold AES-GCM output.
    data_nonce: str
    data_ct: str
    check_nonce: str
    check_ct: str
    generation: int

    def to_json(self) -> str:
        import json

        return json.dumps(
            {
                "format": "digital-keys",
                "version": self.version,
                "kdf": self.kdf,
                "salt": self.salt,
                "generation": self.generation,
                "slots": {
                    "data": {"nonce": self.data_nonce, "ct": self.data_ct},
                    "check": {"nonce": self.check_nonce, "ct": self.check_ct},
                },
            },
            indent=2,
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, text: str) -> "VaultFile":
        import json

        try:
            d = json.loads(text)
        except Exception as exc:
            raise VaultCorrupt("vault file is not valid JSON") from exc
        if d.get("format") in ("highline-vault", "hlv-vault"):
            raise UnsupportedVault(
                "this vault was written by Highline Vault 1.x. Digital Keys 2.0 changed "
                "the key-derivation labels, so the old file cannot be opened. Create a "
                "new vault and re-add your credentials."
            )
        if d.get("format") != "digital-keys":
            raise VaultCorrupt("not a digital-keys vault file")
        version = d.get("version")
        if not isinstance(version, int):
            raise VaultCorrupt("missing or invalid version")
        if version > FORMAT_VERSION:
            raise UnsupportedVault(
                f"vault is version {version}, this build understands {FORMAT_VERSION}"
            )
        try:
            slots = d["slots"]
            return cls(
                version=version,
                kdf=d["kdf"],
                salt=d["salt"],
                generation=int(d.get("generation", 0)),
                data_nonce=slots["data"]["nonce"],
                data_ct=slots["data"]["ct"],
                check_nonce=slots["check"]["nonce"],
                check_ct=slots["check"]["ct"],
            )
        except KeyError as exc:
            raise VaultCorrupt(f"vault is missing slot {exc}") from exc


def _atomic_write(path: str, text: str) -> None:
    """
    Write via temp file + fsync + rename so a crash can never leave a
    half-written vault behind. The old file is still intact until the rename
    lands.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".digital-keys-", suffix=".tmp")
    try:
        # os.fchmod does not exist on Windows; restrict after close there instead.
        if hasattr(os, "fchmod"):
            os.fchmod(fd, FILE_MODE)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        if not hasattr(os, "fchmod"):
            os.chmod(tmp, FILE_MODE)  # Windows: best effort, only clears read-only
        os.replace(tmp, path)
        # fsync the directory too, so the rename itself is durable.
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


class _OpenVault:
    """
    A decrypted vault that exists only inside a `with` block.

    Holds the data subkey, not the passphrase. When the block exits, the
    attribute is overwritten with None so a later attribute access raises
    instead of silently returning plaintext.
    """

    __slots__ = ("_parent", "_data_key", "_docs", "_providers", "_generation")

    def __init__(self, parent: "Vault", data_key: bytes, docs: dict, providers: list, generation: int):
        self._parent = parent
        self._data_key = data_key
        self._docs = docs
        self._providers = providers
        self._generation = generation

    # -- lifecycle --------------------------------------------------------

    def seal(self) -> None:
        self._data_key = None  # type: ignore[assignment]
        self._docs = None  # type: ignore[assignment]
        self._providers = None  # type: ignore[assignment]

    def _key(self) -> bytes:
        if self._data_key is None:
            raise VaultLocked("this vault handle has been sealed")
        return self._data_key

    # -- reading ----------------------------------------------------------

    def records(self) -> list[Record]:
        key = self._key()
        out: list[Record] = []
        for rid, entry in self._docs.get("records", {}).items():
            plain = decrypt(key, b64d(entry["ct"]), b64d(entry["nonce"]), _record_aad(rid))
            import json

            raw = json.loads(plain.decode("utf-8"))
            out.append(
                Record(
                    id=rid,
                    category=Category(raw["category"]),
                    kind=SecretKind(raw["kind"]),
                    label=raw.get("label", ""),
                    secret=raw.get("secret", ""),
                    username=raw.get("username", ""),
                    provider_id=raw.get("provider_id"),
                    notes=raw.get("notes", ""),
                    url=raw.get("url", ""),
                    created_at=raw.get("created_at", ""),
                    updated_at=raw.get("updated_at", ""),
                    agent_capable=bool(raw.get("agent_capable", True)),
                    favourite=bool(raw.get("favourite", False)),
                )
            )
        out.sort(key=lambda r: (not r.favourite, r.label.lower()))
        return out

    def get(self, record_id: str) -> Record:
        for r in self.records():
            if r.id == record_id:
                return r
        raise KeyError(f"no record with id {record_id!r}")

    def providers(self) -> list[Provider]:
        self._key()
        return list(self._providers)

    def provider(self, provider_id: str) -> Provider:
        for p in self._providers:
            if p.id == provider_id:
                return p
        raise KeyError(f"no provider with id {provider_id!r}")

    # -- writing ----------------------------------------------------------

    def put(self, record: Record) -> Record:
        key = self._key()
        if not record.id:
            record.id = uuid.uuid4().hex
        if not record.created_at:
            record.created_at = _utcnow()
        record.updated_at = _utcnow()
        import json

        payload = json.dumps(
            {
                "label": record.label,
                "secret": record.secret,
                "username": record.username,
                "provider_id": record.provider_id,
                "notes": record.notes,
                "url": record.url,
                "created_at": record.created_at,
                "updated_at": record.updated_at,
                "agent_capable": record.agent_capable,
                "favourite": record.favourite,
                "category": record.category.value,
                "kind": record.kind.value,
            },
            sort_keys=True,
        ).encode("utf-8")
        ct, nonce = encrypt(key, payload, _record_aad(record.id))
        self._docs.setdefault("records", {})[record.id] = {
            "ct": b64e(ct),
            "nonce": b64e(nonce),
        }
        self._flush()
        return record

    def delete(self, record_id: str) -> None:
        key = self._key()
        if record_id in self._docs.get("records", {}):
            del self._docs["records"][record_id]
            self._flush()

    def add_provider(self, provider: Provider) -> None:
        self._key()
        self._providers = [p for p in self._providers if p.id != provider.id] + [provider]
        self._flush()

    def set_record_secret(self, record_id: str, secret: str) -> None:
        rec = self.get(record_id)
        rec.secret = secret
        self.put(rec)

    # -- persistence ------------------------------------------------------

    def _flush(self) -> None:
        key = self._key()
        import json

        docs = dict(self._docs)
        docs["providers"] = [_provider_to_dict(p) for p in (self._providers or [])]
        blob = json.dumps(docs, sort_keys=True).encode("utf-8")
        ct, nonce = encrypt(key, blob, VAULT_AAD_PREFIX + b"|data|" + str(self._generation).encode())
        self._parent._write_slots(data_ct=ct, data_nonce=nonce, generation=self._generation)


def _record_aad(record_id: str) -> bytes:
    # Binding the record id means a ciphertext lifted from record A cannot be
    # pasted into record B and still authenticate.
    return VAULT_AAD_PREFIX + b"|record|" + record_id.encode("utf-8")


class Vault:
    """
    The on-disk vault. Thread-safe; holds a lock around read-modify-write.
    """

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self._file: VaultFile | None = None

    # -- creation ---------------------------------------------------------

    @classmethod
    def create(cls, path: str, passphrase: str, kdf: KdfParams | None = None) -> "Vault":
        if os.path.exists(path):
            raise FileExistsError(f"{path} already exists; refusing to overwrite")
        kdf = kdf or KdfParams.default()
        vault = cls(path)
        salt = random_bytes(SALT_LEN)
        master = stretch(passphrase, salt, kdf)
        data_key = derive_subkey(master, INFO_VAULT_DATA)
        check_plain = b"digital-keys-ok|" + sha_like(master)
        check_ct, check_nonce = encrypt(data_key, check_plain, VAULT_AAD_PREFIX + b"|check")
        docs = {"records": {}}
        import json

        docs_bytes = json.dumps(docs, sort_keys=True).encode("utf-8")
        data_ct, data_nonce = encrypt(data_key, docs_bytes, VAULT_AAD_PREFIX + b"|data|0")
        vault._file = VaultFile(
            version=FORMAT_VERSION,
            kdf=kdf.to_dict(),
            salt=b64e(salt),
            generation=0,
            data_nonce=b64e(data_nonce),
            data_ct=b64e(data_ct),
            check_nonce=b64e(check_nonce),
            check_ct=b64e(check_ct),
        )
        vault.save()
        return vault

    # -- persistence ------------------------------------------------------

    def save(self) -> None:
        with self._lock:
            if self._file is None:
                raise VaultSealed("vault not initialised")
            _atomic_write(self.path, self._file.to_json())
            with contextlib.suppress(OSError):
                os.chmod(self.path, FILE_MODE)

    def _write_slots(self, data_ct: bytes, data_nonce: bytes, generation: int) -> None:
        with self._lock:
            if self._file is None:
                raise VaultSealed("vault not initialised")
            self._file.data_ct = b64e(data_ct)
            self._file.data_nonce = b64e(data_nonce)
            self._file.generation = generation
            self.save()

    def _load(self) -> None:
        if not os.path.exists(self.path):
            raise VaultCorrupt(f"no vault file at {self.path}")
        with open(self.path, "r", encoding="utf-8") as fh:
            text = fh.read()
        self._file = VaultFile.from_json(text)

    def exists(self) -> bool:
        return os.path.exists(self.path)

    def is_open(self) -> bool:
        return self._file is not None

    # -- unlocking --------------------------------------------------------

    @contextlib.contextmanager
    def unlock(self, passphrase: str) -> Iterator[_OpenVault]:
        """
        Authenticate and yield an open handle. Seals on exit, always.

        This is the ONLY way to get plaintext out of the vault, and the
        plaintext cannot outlive the with-block.
        """
        with self._lock:
            if self._file is None:
                self._load()
            assert self._file is not None
            params = KdfParams.from_dict(self._file.kdf)
            salt = b64d(self._file.salt)
            master = stretch(passphrase, salt, params)
            data_key = derive_subkey(master, INFO_VAULT_DATA)
            # Verify before touching any record.
            try:
                got = decrypt(
                    data_key,
                    b64d(self._file.check_ct),
                    b64d(self._file.check_nonce),
                    VAULT_AAD_PREFIX + b"|check",
                )
            except Exception as exc:
                raise InvalidPassphrase("wrong passphrase") from exc
            if not got.startswith(b"digital-keys-ok|"):
                raise InvalidPassphrase("wrong passphrase")

            import json

            try:
                docs = json.loads(
                    decrypt(
                        data_key,
                        b64d(self._file.data_ct),
                        b64d(self._file.data_nonce),
                        VAULT_AAD_PREFIX + b"|data|" + str(self._file.generation).encode(),
                    ).decode("utf-8")
                )
            except Exception as exc:
                raise VaultCorrupt("vault data failed authentication") from exc

            providers = [_provider_from_dict(d) for d in docs.get("providers", [])]
            handle = _OpenVault(self, data_key, docs, providers, self._file.generation)
        try:
            yield handle
        finally:
            # Reseal no matter what: normal exit, exception, KeyboardInterrupt.
            handle.seal()


class InvalidPassphrase(Exception):
    """Authentication failed. Deliberately vague - no hint about length/format."""


def sha_like(master: bytes) -> bytes:
    from hashlib import sha256

    return sha256(master).digest()


def _provider_from_dict(d: dict) -> Provider:
    return Provider(
        id=d["id"],
        label=d.get("label", d["id"]),
        category=Category(d.get("category", Category.CUSTOM)),
        base_url=d["base_url"],
        auth_style=d.get("auth_style", "bearer"),
        auth_header=d.get("auth_header", "Authorization"),
        auth_prefix=d.get("auth_prefix", "Bearer "),
        auth_query_param=d.get("auth_query_param"),
        extra_headers=d.get("extra_headers", {}),
        allowed_path_prefixes=d.get("allowed_path_prefixes", []),
        allowed_methods=d.get("allowed_methods", ["GET", "POST"]),
        is_custom=d.get("is_custom", False),
        notes=d.get("notes", ""),
    )


def _provider_to_dict(p: Provider) -> dict:
    return {
        "id": p.id,
        "label": p.label,
        "category": p.category.value,
        "base_url": p.base_url,
        "auth_style": p.auth_style,
        "auth_header": p.auth_header,
        "auth_prefix": p.auth_prefix,
        "auth_query_param": p.auth_query_param,
        "extra_headers": dict(p.extra_headers),
        "allowed_path_prefixes": list(p.allowed_path_prefixes),
        "allowed_methods": list(p.allowed_methods),
        "is_custom": p.is_custom,
        "notes": p.notes,
    }
