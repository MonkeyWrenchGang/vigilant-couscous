from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request

from app.auth.delegation import get_caller_identity
from app.models.requests import DetokenizeRequest
from app.models.responses import DetokenizeResponse
from app.services.detokenize_service import DetokenizeService

logger = logging.getLogger(__name__)
router = APIRouter()


def _get_service(request: Request) -> DetokenizeService:
    return request.app.state.detokenize_service


@router.post("/detokenize", response_model=DetokenizeResponse, status_code=200)
def detokenize(
    body: DetokenizeRequest,
    caller_identity: str = Depends(get_caller_identity),
    service: DetokenizeService = Depends(_get_service),
) -> DetokenizeResponse:
    """Resolve a token to its sensitive value (PAN, bank account number, etc.).

    - Requires `institution_id` and `reason_code`.
    - Returns **masked value** by default.
    - `FULL` mode requires `operator_id` in the request body.
    - Fail-closed: any authorization failure returns 403, never the sensitive value.
    - Token not found, revoked, or expired returns identical 404 (oracle-safe).
    """
    try:
        return service.detokenize(body, caller_identity)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("Unexpected error in detokenize")
        raise HTTPException(status_code=500, detail="Internal server error")
