from __future__ import annotations

import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.crypto.base import CryptoProvider


class LocalCryptoProvider(CryptoProvider):
    """Local crypto provider for POV / dev / test.

    Derives per-institution PFK and PEK from a single master key using HKDF.
    Requires zero GCP credentials — all operations are in-process.

    Key derivation:
        PFK = HKDF(master_key, salt=institution_id, info=b"pfk", length=32)
        PEK = HKDF(master_key, salt=institution_id, info=b"pek", length=32)

    This guarantees institution isolation: the same PAN for two different
    institution_ids produces different fingerprints and independent ciphertexts.
    """

    def __init__(self, master_key_hex: str) -> None:
        self._master_key = bytes.fromhex(master_key_hex)
        if len(self._master_key) != 32:
            raise ValueError("master_key_hex must encode exactly 32 bytes")
        self._pfk_cache: dict[str, bytes] = {}
        self._pek_cache: dict[str, bytes] = {}

    def _pfk(self, institution_id: str) -> bytes:
        if institution_id not in self._pfk_cache:
            self._pfk_cache[institution_id] = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=institution_id.encode(),
                info=b"pfk",
            ).derive(self._master_key)
        return self._pfk_cache[institution_id]

    def _pek(self, institution_id: str) -> bytes:
        if institution_id not in self._pek_cache:
            self._pek_cache[institution_id] = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=institution_id.encode(),
                info=b"pek",
            ).derive(self._master_key)
        return self._pek_cache[institution_id]

    def hmac_fingerprint(self, institution_id: str, pan: str) -> str:
        return hmac.new(self._pfk(institution_id), pan.encode(), hashlib.sha256).hexdigest()

    def encrypt_pan(self, institution_id: str, pan: str) -> str:
        nonce = os.urandom(12)
        aead = AESGCM(self._pek(institution_id))
        ciphertext = aead.encrypt(nonce, pan.encode(), institution_id.encode())
        return base64.b64encode(nonce + ciphertext).decode()

    def decrypt_pan(self, institution_id: str, ciphertext_b64: str) -> str:
        raw = base64.b64decode(ciphertext_b64)
        nonce, ciphertext = raw[:12], raw[12:]
        aead = AESGCM(self._pek(institution_id))
        return aead.decrypt(nonce, ciphertext, institution_id.encode()).decode()
