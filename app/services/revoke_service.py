from __future__ import annotations

import logging

from app.auth.delegation import DelegationGrantChecker
from app.cache.redis_cache import TokenCache
from app.models.requests import RevokeRequest
from app.models.responses import RevokeResponse
from app.vault.base import VaultStore

logger = logging.getLogger(__name__)


class RevokeService:
    def __init__(
        self,
        vault: VaultStore,
        cache: TokenCache,
        delegation: DelegationGrantChecker,
    ) -> None:
        self._vault = vault
        self._cache = cache
        self._delegation = delegation

    def revoke(self, request: RevokeRequest, caller_identity: str) -> RevokeResponse:
        # Step 1: delegation grant check
        if not self._delegation.is_authorized(caller_identity, request.institution_id):
            raise PermissionError(
                f"{caller_identity!r} is not authorized for institution {request.institution_id!r}"
            )

        count = 0

        if request.token:
            # Single token revocation
            count = self._vault.revoke_by_token(request.institution_id, request.token)
            if count > 0:
                self._cache.delete(request.institution_id, request.token)

        elif request.value_fingerprint:
            # Bulk fingerprint-selector revocation with optional scope filter
            count = self._vault.revoke_by_fingerprint(
                institution_id=request.institution_id,
                value_fingerprint=request.value_fingerprint,
                domain=request.domain,
                scope_qualifiers_filter=request.scope_qualifiers_filter,
            )
            if count > 0:
                # Bulk cache eviction — SCAN-based, evicts all institution tokens
                # (conservative: evicts more than necessary but safe)
                self._cache.delete_by_pattern(
                    request.institution_id, request.value_fingerprint
                )

        logger.info(
            "Revoked %d token(s) institution=%s token=%s fingerprint=%s",
            count,
            request.institution_id,
            request.token or "n/a",
            request.value_fingerprint or "n/a",
        )
        return RevokeResponse(revoked_count=count, institution_id=request.institution_id)
