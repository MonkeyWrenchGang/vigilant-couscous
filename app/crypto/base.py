from __future__ import annotations

from abc import ABC, abstractmethod


class CryptoProvider(ABC):
    """Abstract crypto interface. Implementations must be institution-isolated:
    the same PAN for different institution_ids must produce different fingerprints
    and independent ciphertexts."""

    @abstractmethod
    def hmac_fingerprint(self, institution_id: str, pan: str) -> str:
        """Return a hex HMAC-SHA-256 fingerprint of the PAN, keyed to the institution.
        Used for REUSABLE token lookup and revocation by fingerprint selector."""

    @abstractmethod
    def encrypt_pan(self, institution_id: str, pan: str) -> str:
        """AES-256-GCM encrypt PAN with institution-scoped PEK.
        Returns a base64-encoded opaque blob (nonce || ciphertext+tag)."""

    @abstractmethod
    def decrypt_pan(self, institution_id: str, ciphertext_b64: str) -> str:
        """Decrypt a ciphertext_b64 produced by encrypt_pan for the same institution."""
