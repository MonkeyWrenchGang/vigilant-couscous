from __future__ import annotations

import json
import threading
from datetime import datetime

from app.vault.base import TokenRecord, VaultStore


class MemoryVaultStore(VaultStore):
    """Thread-safe in-memory vault for POV and testing.

    Two indexes maintained under a single RLock:
        _by_token:  (institution_id, token) -> TokenRecord
        _by_scope:  (institution_id, domain, fingerprint, scope_canonical, purpose) -> token
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._by_token: dict[tuple[str, str], TokenRecord] = {}
        # scope index maps to token string (then looked up in _by_token)
        self._by_scope: dict[tuple[str, str, str, str, str], str] = {}

    def put(self, record: TokenRecord) -> None:
        scope_key = (
            record.institution_id,
            record.domain,
            record.pan_fingerprint,
            record.scope_qualifiers_canonical,
            record.purpose,
        )
        with self._lock:
            self._by_token[(record.institution_id, record.token)] = record
            if record.status == "ACTIVE":
                self._by_scope[scope_key] = record.token

    def get_by_token(self, institution_id: str, token: str) -> TokenRecord | None:
        with self._lock:
            record = self._by_token.get((institution_id, token))
        if record is None:
            return None
        # Check TTL expiry
        if record.expires_at and datetime.utcnow() > record.expires_at:
            record.status = "EXPIRED"
        return record

    def get_by_fingerprint(
        self,
        institution_id: str,
        domain: str,
        pan_fingerprint: str,
        scope_qualifiers_canonical: str,
        purpose: str,
    ) -> TokenRecord | None:
        scope_key = (institution_id, domain, pan_fingerprint, scope_qualifiers_canonical, purpose)
        with self._lock:
            token = self._by_scope.get(scope_key)
            if token is None:
                return None
            record = self._by_token.get((institution_id, token))
        if record is None or record.status != "ACTIVE":
            return None
        if record.expires_at and datetime.utcnow() > record.expires_at:
            record.status = "EXPIRED"
            return None
        return record

    def revoke_by_token(self, institution_id: str, token: str) -> int:
        with self._lock:
            record = self._by_token.get((institution_id, token))
            if record is None or record.status != "ACTIVE":
                return 0
            record.status = "REVOKED"
            scope_key = (
                institution_id,
                record.domain,
                record.pan_fingerprint,
                record.scope_qualifiers_canonical,
                record.purpose,
            )
            self._by_scope.pop(scope_key, None)
        return 1

    def revoke_by_fingerprint(
        self,
        institution_id: str,
        pan_fingerprint: str,
        domain: str | None,
        scope_qualifiers_filter: dict[str, str] | None,
    ) -> int:
        count = 0
        with self._lock:
            candidates = [
                r
                for (iid, _tok), r in self._by_token.items()
                if iid == institution_id
                and r.pan_fingerprint == pan_fingerprint
                and r.status == "ACTIVE"
            ]
            for record in candidates:
                if domain is not None and record.domain != domain:
                    continue
                if scope_qualifiers_filter is not None:
                    # Filter: record's scope_qualifiers must contain all filter k/v pairs
                    try:
                        record_quals = json.loads(record.scope_qualifiers_canonical)
                    except Exception:
                        record_quals = {}
                    if not all(record_quals.get(k) == v for k, v in scope_qualifiers_filter.items()):
                        continue
                record.status = "REVOKED"
                scope_key = (
                    institution_id,
                    record.domain,
                    record.pan_fingerprint,
                    record.scope_qualifiers_canonical,
                    record.purpose,
                )
                self._by_scope.pop(scope_key, None)
                count += 1
        return count
