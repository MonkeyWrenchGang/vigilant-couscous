from __future__ import annotations

import logging

from app.auth.delegation import DelegationGrantChecker
from app.cache.redis_cache import TokenCache
from app.crypto.base import CryptoProvider
from app.models.requests import DetokenizeRequest
from app.models.responses import DetokenizeResponse
from app.vault.base import VaultStore

logger = logging.getLogger(__name__)


def _mask_pan(pan: str) -> str:
    if len(pan) <= 10:
        return "*" * len(pan)
    return pan[:6] + "*" * (len(pan) - 10) + pan[-4:]


class DetokenizeService:
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

    def detokenize(self, request: DetokenizeRequest, caller_identity: str) -> DetokenizeResponse:
        # Step 1: delegation grant check
        if not self._delegation.is_authorized(caller_identity, request.institution_id):
            raise PermissionError(
                f"{caller_identity!r} is not authorized for institution {request.institution_id!r}"
            )

        # Step 2: FULL_PAN requires operator_id (enforced here; also validated by Pydantic)
        if request.detokenize_mode == "FULL_PAN" and not request.operator_id:
            raise ValueError("operator_id is required for FULL_PAN detokenize")

        # Step 3: check cache first
        encrypted_pan = self._cache.get(request.institution_id, request.token)

        if encrypted_pan is None:
            # Step 4: cache miss — fetch from vault
            record = self._vault.get_by_token(request.institution_id, request.token)
            if record is None:
                # Identical 404 for not-found, revoked, and mismatch — prevents oracle attacks
                raise LookupError("Token not found")
            if record.status != "ACTIVE":
                raise LookupError("Token not found")
            encrypted_pan = record.encrypted_pan
            # Backfill cache on miss
            self._cache.set(request.institution_id, request.token, encrypted_pan)

        # Step 5: decrypt PAN
        pan = self._crypto.decrypt_pan(request.institution_id, encrypted_pan)

        # Step 6: apply masking unless FULL_PAN requested
        if request.detokenize_mode == "MASKED_PAN":
            pan = _mask_pan(pan)

        logger.info(
            "Detokenize institution=%s mode=%s reason=%s operator=%s",
            request.institution_id,
            request.detokenize_mode,
            request.reason_code,
            request.operator_id or "n/a",
        )
        return DetokenizeResponse(
            token=request.token,
            institution_id=request.institution_id,
            pan=pan,
            reason_code=request.reason_code,
        )
