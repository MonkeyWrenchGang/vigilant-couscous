from __future__ import annotations

import logging

from app.auth.delegation import DelegationGrantChecker
from app.cache.redis_cache import TokenCache
from app.crypto.base import CryptoProvider
from app.models.requests import DetokenizeRequest
from app.models.responses import DetokenizeResponse
from app.services.tokenize_service import _mask_value
from app.vault.base import VaultStore

logger = logging.getLogger(__name__)


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

        # Step 2: FULL requires operator_id (enforced here; also validated by Pydantic)
        if request.detokenize_mode == "FULL" and not request.operator_id:
            raise ValueError("operator_id is required for FULL detokenize")

        # Step 3: fetch from vault (need record for sensitive_data_type)
        record = self._vault.get_by_token(request.institution_id, request.token)
        if record is None:
            raise LookupError("Token not found")
        if record.status != "ACTIVE":
            raise LookupError("Token not found")

        # Step 4: try cache first for encrypted value, fall back to record
        encrypted_value = self._cache.get(request.institution_id, request.token)
        if encrypted_value is None:
            encrypted_value = record.encrypted_value
            # Backfill cache on miss
            self._cache.set(request.institution_id, request.token, encrypted_value)

        # Step 5: decrypt value
        value = self._crypto.decrypt_value(request.institution_id, encrypted_value)

        # Step 6: apply masking unless FULL requested
        if request.detokenize_mode == "MASKED":
            value = _mask_value(value, record.sensitive_data_type)

        logger.info(
            "Detokenize institution=%s mode=%s reason=%s operator=%s type=%s",
            request.institution_id,
            request.detokenize_mode,
            request.reason_code,
            request.operator_id or "n/a",
            record.sensitive_data_type,
        )
        return DetokenizeResponse(
            token=request.token,
            institution_id=request.institution_id,
            sensitive_data_type=record.sensitive_data_type,
            sensitive_value=value,
            reason_code=request.reason_code,
        )
