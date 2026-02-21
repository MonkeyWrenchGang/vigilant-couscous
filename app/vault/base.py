from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal


@dataclass
class TokenRecord:
    token: str
    institution_id: str
    domain: str
    scope_qualifiers_canonical: str  # canonicalized JSON string
    purpose: str
    pan_fingerprint: str
    encrypted_pan: str  # base64 opaque blob from CryptoProvider.encrypt_pan
    status: Literal["ACTIVE", "REVOKED", "EXPIRED"] = "ACTIVE"
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: datetime | None = None


class VaultStore(ABC):
    """Abstract vault interface. Production implementation uses Cloud Spanner
    partitioned by institution_id. POV uses MemoryVaultStore."""

    @abstractmethod
    def put(self, record: TokenRecord) -> None:
        """Insert a new token record."""

    @abstractmethod
    def get_by_token(self, institution_id: str, token: str) -> TokenRecord | None:
        """Fetch a record by token value, scoped to institution."""

    @abstractmethod
    def get_by_fingerprint(
        self,
        institution_id: str,
        domain: str,
        pan_fingerprint: str,
        scope_qualifiers_canonical: str,
        purpose: str,
    ) -> TokenRecord | None:
        """Find the ACTIVE token for a given PAN scope (REUSABLE lookup)."""

    @abstractmethod
    def revoke_by_token(self, institution_id: str, token: str) -> int:
        """Revoke a single token. Returns 1 if found and revoked, 0 otherwise."""

    @abstractmethod
    def revoke_by_fingerprint(
        self,
        institution_id: str,
        pan_fingerprint: str,
        domain: str | None,
        scope_qualifiers_filter: dict[str, str] | None,
    ) -> int:
        """Bulk revoke tokens matching fingerprint + optional filters.
        Returns count of revoked records."""
