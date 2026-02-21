from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class TokenizeResponse(BaseModel):
    token: str
    token_mode: str
    institution_id: str
    masked_pan: str
    scope_qualifiers: dict[str, str]
    expires_at: datetime | None


class DetokenizeResponse(BaseModel):
    token: str
    institution_id: str
    pan: str  # masked or full depending on request
    reason_code: str


class RevokeResponse(BaseModel):
    revoked_count: int
    institution_id: str


class HealthResponse(BaseModel):
    status: str
