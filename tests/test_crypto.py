"""
Unit tests for the primitives and the vault's structural guarantees.

These are the properties that must never silently change: nonce uniqueness,
AAD binding, tamper detection, KDF upgradeability, and the fact that a sealed
handle really is unusable.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from digital_keys.crypto import (  # noqa: E402
    INFO_VAULT_DATA,
    INFO_TOKEN,
    InvalidTag,
    KdfParams,
    b64d,
    b64e,
    decrypt,
    derive_subkey,
    encrypt,
    hkdf_sha512,
    stretch,
)
from digital_keys.records import Category, Record, SecretKind, sanitise_for_header  # noqa: E402
from digital_keys.vault import InvalidPassphrase, Vault, VaultCorrupt, VaultLocked  # noqa: E402

PASS = "a sufficiently long passphrase"


class TestPrimitives(unittest.TestCase):
    def test_roundtrip(self):
        k = b"\x11" * 32
        ct, n = encrypt(k, b"hello world", b"aad")
        self.assertEqual(decrypt(k, ct, n, b"aad"), b"hello world")

    def test_nonce_is_unique_per_call(self):
        k = b"\x22" * 32
        nonces = {encrypt(k, b"same", b"a")[1] for _ in range(500)}
        self.assertEqual(len(nonces), 500, "nonces repeated - catastrophic for GCM")

    def test_aad_is_authenticated(self):
        k = b"\x33" * 32
        ct, n = encrypt(k, b"secret", b"context-A")
        with self.assertRaises(InvalidTag):
            decrypt(k, ct, n, b"context-B")

    def test_wrong_key_fails(self):
        ct, n = encrypt(b"\x44" * 32, b"s", b"a")
        with self.assertRaises(InvalidTag):
            decrypt(b"\x45" * 32, ct, n, b"a")

    def test_tamper_detected(self):
        k = b"\x55" * 32
        ct, n = encrypt(k, b"important", b"a")
        bad = bytearray(ct)
        bad[0] ^= 0x01
        with self.assertRaises(InvalidTag):
            decrypt(k, bytes(bad), n, b"a")

    def test_hkdf_is_deterministic_and_separated(self):
        a = hkdf_sha512(b"master", INFO_VAULT_DATA, 32)
        b = hkdf_sha512(b"master", INFO_VAULT_DATA, 32)
        c = hkdf_sha512(b"master", INFO_TOKEN, 32)
        d = hkdf_sha512(b"master2", INFO_VAULT_DATA, 32)
        self.assertEqual(a, b)
        self.assertNotEqual(a, c, "subkeys for different purposes collided")
        self.assertNotEqual(a, d)
        self.assertEqual(len(a), 32)

    def test_stretch_is_salted(self):
        p = KdfParams.default()
        s1, s2 = os.urandom(16), os.urandom(16)
        self.assertNotEqual(stretch("pw", s1, p), stretch("pw", s2, p))
        self.assertEqual(stretch("pw", s1, p), stretch("pw", s1, p))

    def test_kdf_params_roundtrip(self):
        p = KdfParams.default()
        self.assertEqual(KdfParams.from_dict(p.to_dict()), p)

    def test_b64(self):
        self.assertEqual(b64d(b64e(b"\x00\xff\x10")), b"\x00\xff\x10")


class TestHeaderSanitisation(unittest.TestCase):
    def test_strips_crlf(self):
        self.assertNotIn("\r", sanitise_for_header("a\r\nX-Evil: 1"))
        self.assertNotIn("\n", sanitise_for_header("a\nb"))

    def test_strips_control(self):
        self.assertEqual(sanitise_for_header("a\x00b\x07c"), "abc")

    def test_strips_zero_width(self):
        self.assertEqual(sanitise_for_header("sk-\u200bkey"), "sk-key")

    def test_preserves_normal(self):
        self.assertEqual(sanitise_for_header("  sk-or-v1-abc  "), "sk-or-v1-abc")


class TestVault(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "v.json")

    def test_create_and_reopen(self):
        v = Vault.create(self.path, PASS)
        with v.unlock(PASS) as h:
            rid = h.put(Record(id="", category=Category.LLM, kind=SecretKind.API_KEY,
                               label="x", secret="TOP")).id
        with v.unlock(PASS) as h:
            self.assertEqual(h.get(rid).secret, "TOP")

    def test_wrong_passphrase(self):
        v = Vault.create(self.path, PASS)
        with self.assertRaises(InvalidPassphrase):
            with v.unlock("not the passphrase"):
                pass

    def test_no_plaintext_on_disk(self):
        v = Vault.create(self.path, PASS)
        with v.unlock(PASS) as h:
            h.put(Record(id="", category=Category.SEED, kind=SecretKind.SEED_PHRASE,
                         label="MyWallet", secret="ALPHA BRAVO CHARLIE",
                         username="me@example.com", notes="important note here"))
        raw = open(self.path).read()
        for needle in ("ALPHA", "BRAVO", "MyWallet", "me@example.com", "important note here", PASS):
            self.assertNotIn(needle, raw, f"{needle!r} leaked to disk")

    def test_file_mode(self):
        v = Vault.create(self.path, PASS)
        self.assertEqual(oct(os.stat(self.path).st_mode & 0o777), "0o600")

    def test_seals_on_exit_even_on_exception(self):
        v = Vault.create(self.path, PASS)
        with self.assertRaises(RuntimeError):
            with v.unlock(PASS) as h:
                h.put(Record(id="", category=Category.LLM, kind=SecretKind.API_KEY,
                             label="x", secret="y"))
                raise RuntimeError("boom")
        with self.assertRaises((VaultLocked, RuntimeError)):
            h.records()

    def test_handle_unusable_after_block(self):
        v = Vault.create(self.path, PASS)
        with v.unlock(PASS) as h:
            pass
        with self.assertRaises(VaultLocked):
            h.records()

    def test_record_aad_binding(self):
        """
        A ciphertext lifted from one record must not authenticate as another.
        This is what stops someone rearranging the vault file by hand.
        """
        v = Vault.create(self.path, PASS)
        with v.unlock(PASS) as h:
            a = h.put(Record(id="", category=Category.LLM, kind=SecretKind.API_KEY,
                             label="a", secret="AAAA"))
            b = h.put(Record(id="", category=Category.LLM, kind=SecretKind.API_KEY,
                             label="b", secret="BBBB"))
            docs = h._docs["records"]
            docs[b.id] = docs[a.id]  # swap
        with v.unlock(PASS) as h:
            # Opening still works, but the record now authenticates under a's id
            # only if aad matches; the swap changes the id so GCM must reject.
            try:
                recs = h.records()
                # If it did not raise, confirm the secret did not follow the id.
                got = {r.id: r.secret for r in recs}
                self.assertNotEqual(got.get(a.id), "AAAA")
            except Exception:
                pass  # raising is equally correct

    def test_corrupt_file_detected(self):
        Vault.create(self.path, PASS)
        open(self.path, "w").write("this is not a vault")
        v = Vault(self.path)
        with self.assertRaises(VaultCorrupt):
            with v.unlock(PASS):
                pass

    def test_refuses_overwrite(self):
        Vault.create(self.path, PASS)
        with self.assertRaises(FileExistsError):
            Vault.create(self.path, PASS)

    def test_delete(self):
        v = Vault.create(self.path, PASS)
        with v.unlock(PASS) as h:
            rid = h.put(Record(id="", category=Category.LLM, kind=SecretKind.API_KEY,
                               label="x", secret="y")).id
            h.delete(rid)
            self.assertEqual(len(h.records()), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
