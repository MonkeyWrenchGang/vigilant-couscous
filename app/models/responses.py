from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class TokenizeResponse(BaseModel):
    token: str
    sensitive_data_type: str
    token_mode: str
    institution_id: str
    masked_value: str
    scope_qualifiers: dict[str, str]
    expires_at: datetime | None


class DetokenizeResponse(BaseModel):
    token: str
    institution_id: str
    sensitive_data_type: str
    sensitive_value: str  # masked or full depending on request
    reason_code: str


class RevokeResponse(BaseModel):
    revoked_count: int
    institution_id: str


class HealthResponse(BaseModel):
    status: str
