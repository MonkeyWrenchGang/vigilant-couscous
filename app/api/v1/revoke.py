from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request

from app.auth.delegation import get_caller_identity
from app.models.requests import RevokeRequest
from app.models.responses import RevokeResponse
from app.services.revoke_service import RevokeService

logger = logging.getLogger(__name__)
router = APIRouter()


def _get_service(request: Request) -> RevokeService:
    return request.app.state.revoke_service


@router.post("/tokens/revoke", response_model=RevokeResponse, status_code=200)
def revoke(
    body: RevokeRequest,
    caller_identity: str = Depends(get_caller_identity),
    service: RevokeService = Depends(_get_service),
) -> RevokeResponse:
    """Revoke tokens by token value or by fingerprint selector.

    - **Token revocation**: provide `token` — revokes a single token.
    - **Fingerprint-selector revocation**: provide `value_fingerprint` with optional
      `domain` and `scope_qualifiers_filter` for targeted bulk revocation
      (e.g., decommission one JH application's tokens for a card or account).
    - `revoked_count` of 0 means no matching ACTIVE tokens were found.
    """
    try:
        return service.revoke(body, caller_identity)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("Unexpected error in revoke")
        raise HTTPException(status_code=500, detail="Internal server error")
