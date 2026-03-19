from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone

from app.auth.delegation import DelegationGrantChecker
from app.cache.redis_cache import TokenCache
from app.crypto.base import CryptoProvider
from app.models.requests import TokenizeRequest
from app.models.responses import TokenizeResponse
from app.vault.base import TokenRecord, VaultStore

logger = logging.getLogger(__name__)


def _mask_value(value: str, data_type: str) -> str:
    """Return masked representation of a sensitive value based on its type.

    PAN: preserve first 6 and last 4 digits (BIN + last four).
    BANK_ACCOUNT: show only last 4 digits.
    """
    if data_type == "PAN":
        if len(value) <= 10:
            return "*" * len(value)
        return value[:6] + "*" * (len(value) - 10) + value[-4:]
    elif data_type == "BANK_ACCOUNT":
        if len(value) <= 4:
            return "*" * len(value)
        return "*" * (len(value) - 4) + value[-4:]
    # Fallback: mask everything except last 4
    if len(value) <= 4:
        return "*" * len(value)
    return "*" * (len(value) - 4) + value[-4:]


def _canonical_scope(scope_qualifiers: dict[str, str]) -> str:
    """Deterministic JSON serialization for use as a lookup/index key."""
    return json.dumps(dict(sorted(scope_qualifiers.items())), separators=(",", ":"))


class TokenizeService:
    def __init__(
        self,
        crypto: CryptoProvider,
        vault: VaultStore,
        cache: TokenCache,
        delegation: DelegationGrantChecker,
    ) -> None:
        self._crypto = crypto
        self._vault = vault
        self._cache = cache
        self._delegation = delegation

    def tokenize(self, request: TokenizeRequest, caller_identity: str) -> TokenizeResponse:
        # Step 1: delegation grant check (fail-closed)
        if not self._delegation.is_authorized(caller_identity, request.institution_id):
            raise PermissionError(
                f"{caller_identity!r} is not authorized for institution {request.institution_id!r}"
            )

        # Step 2: compute institution-scoped value fingerprint
        fingerprint = self._crypto.hmac_fingerprint(request.institution_id, request.sensitive_value)

        # Step 3: canonicalize scope_qualifiers
        scope_canonical = _canonical_scope(request.scope_qualifiers)

        # Step 4: REUSABLE mode — look up existing ACTIVE token
        if request.token_mode == "REUSABLE":
            existing = self._vault.get_by_fingerprint(
                institution_id=request.institution_id,
                domain=request.domain,
                value_fingerprint=fingerprint,
                scope_qualifiers_canonical=scope_canonical,
                purpose=request.purpose,
            )
            if existing is not None:
                logger.debug("Returning existing REUSABLE token for institution=%s", request.institution_id)
                return TokenizeResponse(
                    token=existing.token,
                    sensitive_data_type=request.sensitive_data_type,
                    token_mode="REUSABLE",
                    institution_id=request.institution_id,
                    masked_value=_mask_value(request.sensitive_value, request.sensitive_data_type),
                    scope_qualifiers=request.scope_qualifiers,
                    expires_at=existing.expires_at,
                )

        # Step 5: mint new token
        token = str(uuid.uuid4())
        encrypted_value = self._crypto.encrypt_value(request.institution_id, request.sensitive_value)
        expires_at: datetime | None = None
        if request.ttl_seconds is not None:
            expires_at = datetime.now(tz=timezone.utc) + timedelta(seconds=request.ttl_seconds)

        record = TokenRecord(
            token=token,
            institution_id=request.institution_id,
            sensitive_data_type=request.sensitive_data_type,
            domain=request.domain,
            scope_qualifiers_canonical=scope_canonical,
            purpose=request.purpose,
            value_fingerprint=fingerprint,
            encrypted_value=encrypted_value,
            expires_at=expires_at,
        )
        self._vault.put(record)

        # Step 6: populate cache
        ttl = request.ttl_seconds or 3600
        self._cache.set(request.institution_id, token, encrypted_value, ttl=ttl)

        logger.info(
            "Minted %s token institution=%s domain=%s type=%s",
            request.token_mode,
            request.institution_id,
            request.domain,
            request.sensitive_data_type,
        )
        return TokenizeResponse(
            token=token,
            sensitive_data_type=request.sensitive_data_type,
            token_mode=request.token_mode,
            institution_id=request.institution_id,
            masked_value=_mask_value(request.sensitive_value, request.sensitive_data_type),
            scope_qualifiers=request.scope_qualifiers,
            expires_at=expires_at,
        )
