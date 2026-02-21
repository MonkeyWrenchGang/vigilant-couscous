from __future__ import annotations

import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.crypto.base import CryptoProvider


class KMSCryptoProvider(CryptoProvider):
    """Cloud KMS-backed crypto provider.

    Key naming convention (one ring per project, distinct key names per institution):
        PFK: projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/inst-{institution_id}-pfk/cryptoKeyVersions/1
        PEK: projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/inst-{institution_id}-pek/cryptoKeyVersions/1

    Uses KMS rawEncrypt / rawDecrypt (AES-256-GCM) for PEK operations and
    macSign / macVerify for PFK HMAC-SHA-256 fingerprinting.

    Requires: google-cloud-kms installed and Application Default Credentials configured.
    """

    def __init__(self, project: str, location: str, key_ring: str) -> None:
        try:
            from google.cloud import kms  # type: ignore[import-untyped]
        except ImportError as e:
            raise ImportError(
                "google-cloud-kms is required for KMSCryptoProvider. "
                "Install it with: pip install google-cloud-kms"
            ) from e

        self._kms = kms
        self._client = kms.KeyManagementServiceClient()
        self._project = project
        self._location = location
        self._key_ring = key_ring

    def _pfk_key_name(self, institution_id: str) -> str:
        return (
            f"projects/{self._project}/locations/{self._location}"
            f"/keyRings/{self._key_ring}/cryptoKeys/inst-{institution_id}-pfk"
        )

    def _pek_key_name(self, institution_id: str) -> str:
        return (
            f"projects/{self._project}/locations/{self._location}"
            f"/keyRings/{self._key_ring}/cryptoKeys/inst-{institution_id}-pek"
        )

    def hmac_fingerprint(self, institution_id: str, pan: str) -> str:
        response = self._client.mac_sign(
            request={
                "name": self._pfk_key_name(institution_id) + "/cryptoKeyVersions/1",
                "data": pan.encode(),
            }
        )
        return response.mac.hex()

    def encrypt_pan(self, institution_id: str, pan: str) -> str:
        nonce = os.urandom(12)
        response = self._client.raw_encrypt(
            request={
                "name": self._pek_key_name(institution_id) + "/cryptoKeyVersions/1",
                "plaintext": pan.encode(),
                "additional_authenticated_data": institution_id.encode(),
                "initialization_vector": nonce,
            }
        )
        ciphertext = bytes(response.ciphertext)
        return base64.b64encode(nonce + ciphertext).decode()

    def decrypt_pan(self, institution_id: str, ciphertext_b64: str) -> str:
        raw = base64.b64decode(ciphertext_b64)
        nonce, ciphertext = raw[:12], raw[12:]
        response = self._client.raw_decrypt(
            request={
                "name": self._pek_key_name(institution_id) + "/cryptoKeyVersions/1",
                "ciphertext": ciphertext,
                "additional_authenticated_data": institution_id.encode(),
                "initialization_vector": nonce,
            }
        )
        return bytes(response.plaintext).decode()
