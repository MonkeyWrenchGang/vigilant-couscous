from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, field_validator, model_validator

_PAN_RE = re.compile(r"^\d{13,19}$")
_BANK_ACCOUNT_RE = re.compile(r"^\d{4,17}$")

# Validation rules keyed by sensitive_data_type
_VALUE_RULES: dict[str, tuple[re.Pattern, str]] = {
    "PAN": (_PAN_RE, "PAN must be 13-19 digits"),
    "BANK_ACCOUNT": (_BANK_ACCOUNT_RE, "Bank account number must be 4-17 digits"),
}


class TokenizeRequest(BaseModel):
    sensitive_data_type: Literal["PAN", "BANK_ACCOUNT"]
    sensitive_value: str
    institution_id: str
    domain: str = "default"
    token_mode: Literal["REUSABLE", "ONE_TIME"] = "REUSABLE"
    scope_qualifiers: dict[str, str] = {}
    purpose: str = "payment"
    ttl_seconds: int | None = None

    @field_validator("sensitive_value")
    @classmethod
    def strip_sensitive_value(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("sensitive_value must not be empty")
        return v

    @model_validator(mode="after")
    def validate_sensitive_value(self) -> TokenizeRequest:
        rule = _VALUE_RULES.get(self.sensitive_data_type)
        if rule is None:
            raise ValueError(f"Unsupported sensitive_data_type: {self.sensitive_data_type}")
        pattern, message = rule
        if not pattern.match(self.sensitive_value):
            raise ValueError(message)
        return self

    @field_validator("institution_id", "domain")
    @classmethod
    def non_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("must not be empty")
        return v.strip()

    @field_validator("purpose")
    @classmethod
    def strip_purpose(cls, v: str) -> str:
        v = v.strip()
        return v if v else "payment"

    @field_validator("scope_qualifiers")
    @classmethod
    def clean_scope_qualifiers(cls, v: dict[str, str]) -> dict[str, str]:
        """Strip whitespace from keys/values; drop entries where key or value is blank."""
        cleaned = {}
        for key, val in v.items():
            k = key.strip()
            vv = val.strip()
            if k and vv:
                cleaned[k] = vv
        return cleaned


class DetokenizeRequest(BaseModel):
    token: str
    institution_id: str
    reason_code: str
    detokenize_mode: Literal["MASKED", "FULL"] = "MASKED"
    operator_id: str | None = None

    @model_validator(mode="after")
    def operator_id_required_for_full(self) -> DetokenizeRequest:
        if self.detokenize_mode == "FULL" and not self.operator_id:
            raise ValueError("operator_id is required when detokenize_mode is FULL")
        return self


class RevokeRequest(BaseModel):
    institution_id: str
    token: str | None = None
    value_fingerprint: str | None = None
    domain: str | None = None
    scope_qualifiers_filter: dict[str, str] | None = None

    @model_validator(mode="after")
    def token_or_fingerprint_required(self) -> RevokeRequest:
        if not self.token and not self.value_fingerprint:
            raise ValueError("Either token or value_fingerprint must be provided")
        return self
