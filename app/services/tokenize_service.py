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


def _mask_pan(pan: str) -> str:
    """Return masked PAN preserving first 6 and last 4 digits."""
    if len(pan) <= 10:
        return "*" * len(pan)
    return pan[:6] + "*" * (len(pan) - 10) + pan[-4:]


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

        # Step 2: compute institution-scoped PAN fingerprint
        fingerprint = self._crypto.hmac_fingerprint(request.institution_id, request.pan)

        # Step 3: canonicalize scope_qualifiers
        scope_canonical = _canonical_scope(request.scope_qualifiers)

        # Step 4: REUSABLE mode — look up existing ACTIVE token
        if request.token_mode == "REUSABLE":
            existing = self._vault.get_by_fingerprint(
                institution_id=request.institution_id,
                domain=request.domain,
                pan_fingerprint=fingerprint,
                scope_qualifiers_canonical=scope_canonical,
                purpose=request.purpose,
            )
            if existing is not None:
                logger.debug("Returning existing REUSABLE token for institution=%s", request.institution_id)
                return TokenizeResponse(
                    token=existing.token,
                    token_mode="REUSABLE",
                    institution_id=request.institution_id,
                    masked_pan=_mask_pan(request.pan),
                    scope_qualifiers=request.scope_qualifiers,
                    expires_at=existing.expires_at,
                )

        # Step 5: mint new token
        token = str(uuid.uuid4())
        encrypted_pan = self._crypto.encrypt_pan(request.institution_id, request.pan)
        expires_at: datetime | None = None
        if request.ttl_seconds is not None:
            expires_at = datetime.now(tz=timezone.utc) + timedelta(seconds=request.ttl_seconds)

        record = TokenRecord(
            token=token,
            institution_id=request.institution_id,
            domain=request.domain,
            scope_qualifiers_canonical=scope_canonical,
            purpose=request.purpose,
            pan_fingerprint=fingerprint,
            encrypted_pan=encrypted_pan,
            expires_at=expires_at,
        )
        self._vault.put(record)

        # Step 6: populate cache
        ttl = request.ttl_seconds or 3600
        self._cache.set(request.institution_id, token, encrypted_pan, ttl=ttl)

        logger.info(
            "Minted %s token institution=%s domain=%s",
            request.token_mode,
            request.institution_id,
            request.domain,
        )
        return TokenizeResponse(
            token=token,
            token_mode=request.token_mode,
            institution_id=request.institution_id,
            masked_pan=_mask_pan(request.pan),
            scope_qualifiers=request.scope_qualifiers,
            expires_at=expires_at,
        )
