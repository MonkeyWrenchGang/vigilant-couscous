from __future__ import annotations

from abc import ABC, abstractmethod


class CryptoProvider(ABC):
    """Abstract crypto interface. Implementations must be institution-isolated:
    the same sensitive value for different institution_ids must produce different
    fingerprints and independent ciphertexts."""

    @abstractmethod
    def hmac_fingerprint(self, institution_id: str, value: str) -> str:
        """Return a hex HMAC-SHA-256 fingerprint of the sensitive value, keyed to the
        institution. Used for REUSABLE token lookup and revocation by fingerprint."""

    @abstractmethod
    def encrypt_value(self, institution_id: str, value: str) -> str:
        """AES-256-GCM encrypt value with institution-scoped PEK.
        Returns a base64-encoded opaque blob (nonce || ciphertext+tag)."""

    @abstractmethod
    def decrypt_value(self, institution_id: str, ciphertext_b64: str) -> str:
        """Decrypt a ciphertext_b64 produced by encrypt_value for the same institution."""
