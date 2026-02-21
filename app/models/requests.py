from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, field_validator, model_validator

_PAN_RE = re.compile(r"^\d{13,19}$")


class TokenizeRequest(BaseModel):
    pan: str
    institution_id: str
    domain: str
    token_mode: Literal["REUSABLE", "ONE_TIME"] = "REUSABLE"
    scope_qualifiers: dict[str, str] = {}
    purpose: str = "payment"
    ttl_seconds: int | None = None

    @field_validator("pan")
    @classmethod
    def validate_pan(cls, v: str) -> str:
        if not _PAN_RE.match(v):
            raise ValueError("PAN must be 13–19 digits")
        return v

    @field_validator("institution_id", "domain")
    @classmethod
    def non_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("must not be empty")
        return v


class DetokenizeRequest(BaseModel):
    token: str
    institution_id: str
    reason_code: str
    detokenize_mode: Literal["MASKED_PAN", "FULL_PAN"] = "MASKED_PAN"
    operator_id: str | None = None

    @model_validator(mode="after")
    def operator_id_required_for_full_pan(self) -> DetokenizeRequest:
        if self.detokenize_mode == "FULL_PAN" and not self.operator_id:
            raise ValueError("operator_id is required when detokenize_mode is FULL_PAN")
        return self


class RevokeRequest(BaseModel):
    institution_id: str
    token: str | None = None
    pan_fingerprint: str | None = None
    domain: str | None = None
    scope_qualifiers_filter: dict[str, str] | None = None

    @model_validator(mode="after")
    def token_or_fingerprint_required(self) -> RevokeRequest:
        if not self.token and not self.pan_fingerprint:
            raise ValueError("Either token or pan_fingerprint must be provided")
        return self
