from __future__ import annotations

import pytest

from app.models.requests import DetokenizeRequest, TokenizeRequest
from tests.conftest import TEST_CALLER, TEST_INSTITUTION, TEST_PAN


def _tokenize(service, pan=TEST_PAN, institution_id=TEST_INSTITUTION):
    req = TokenizeRequest(pan=pan, institution_id=institution_id, domain="card-payments")
    return service.tokenize(req, TEST_CALLER)


def _detokenize_req(token, **kwargs) -> DetokenizeRequest:
    defaults = dict(
        token=token,
        institution_id=TEST_INSTITUTION,
        reason_code="fraud-review",
    )
    defaults.update(kwargs)
    return DetokenizeRequest(**defaults)


class TestDetokenizeService:
    def test_masked_pan_default(self, tokenize_service, detokenize_service):
        tr = _tokenize(tokenize_service)
        dr = detokenize_service.detokenize(_detokenize_req(tr.token), TEST_CALLER)
        assert dr.pan == "411111******1111"

    def test_full_pan_with_operator_id(self, tokenize_service, detokenize_service):
        tr = _tokenize(tokenize_service)
        req = _detokenize_req(tr.token, detokenize_mode="FULL_PAN", operator_id="op-001")
        dr = detokenize_service.detokenize(req, TEST_CALLER)
        assert dr.pan == TEST_PAN

    def test_full_pan_without_operator_id_raises(self, tokenize_service, detokenize_service):
        tr = _tokenize(tokenize_service)
        # Model-level validation should catch this, but test service layer too
        with pytest.raises(Exception):  # ValueError or ValidationError
            DetokenizeRequest(
                token=tr.token,
                institution_id=TEST_INSTITUTION,
                reason_code="test",
                detokenize_mode="FULL_PAN",
                operator_id=None,
            )

    def test_revoked_token_returns_lookup_error(self, tokenize_service, detokenize_service, revoke_service):
        from app.models.requests import RevokeRequest

        tr = _tokenize(tokenize_service)
        revoke_service.revoke(
            RevokeRequest(institution_id=TEST_INSTITUTION, token=tr.token), TEST_CALLER
        )
        with pytest.raises(LookupError):
            detokenize_service.detokenize(_detokenize_req(tr.token), TEST_CALLER)

    def test_not_found_token_returns_lookup_error(self, detokenize_service):
        with pytest.raises(LookupError):
            detokenize_service.detokenize(_detokenize_req("nonexistent-token"), TEST_CALLER)

    def test_delegation_denied_raises_permission_error(self, tokenize_service, detokenize_service):
        tr = _tokenize(tokenize_service)
        with pytest.raises(PermissionError):
            detokenize_service.detokenize(
                _detokenize_req(tr.token), "unauthorized@jh.iam"
            )

    def test_reason_code_in_response(self, tokenize_service, detokenize_service):
        tr = _tokenize(tokenize_service)
        dr = detokenize_service.detokenize(
            _detokenize_req(tr.token, reason_code="chargeback"), TEST_CALLER
        )
        assert dr.reason_code == "chargeback"

    def test_cross_institution_token_not_found(self, tokenize_service, detokenize_service):
        from tests.conftest import TEST_INSTITUTION_2

        tr = _tokenize(tokenize_service)
        req = DetokenizeRequest(
            token=tr.token,
            institution_id=TEST_INSTITUTION_2,
            reason_code="test",
        )
        with pytest.raises(LookupError):
            detokenize_service.detokenize(req, TEST_CALLER)
