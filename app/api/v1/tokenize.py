from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request

from app.auth.delegation import get_caller_identity
from app.models.requests import TokenizeRequest
from app.models.responses import TokenizeResponse
from app.services.tokenize_service import TokenizeService

logger = logging.getLogger(__name__)
router = APIRouter()


def _get_service(request: Request) -> TokenizeService:
    return request.app.state.tokenize_service


@router.post("/tokenize", response_model=TokenizeResponse, status_code=200)
def tokenize(
    body: TokenizeRequest,
    caller_identity: str = Depends(get_caller_identity),
    service: TokenizeService = Depends(_get_service),
) -> TokenizeResponse:
    """Issue a token for a sensitive value (PAN, bank account number, etc.) scoped to
    an institution, domain, and optional scope_qualifiers.

    - **REUSABLE** mode returns an existing ACTIVE token if one exists for the scope.
    - **ONE_TIME** mode always mints a new token.
    - Requires a valid delegation grant for the supplied institution_id.
    """
    try:
        return service.tokenize(body, caller_identity)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("Unexpected error in tokenize")
        raise HTTPException(status_code=500, detail="Internal server error")
