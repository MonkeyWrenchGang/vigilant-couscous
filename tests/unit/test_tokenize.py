from __future__ import annotations

import pytest

from app.models.requests import TokenizeRequest
from tests.conftest import TEST_CALLER, TEST_INSTITUTION, TEST_INSTITUTION_2, TEST_PAN


def _req(**kwargs) -> TokenizeRequest:
    defaults = dict(
        pan=TEST_PAN,
        institution_id=TEST_INSTITUTION,
        domain="card-payments",
        token_mode="REUSABLE",
    )
    defaults.update(kwargs)
    return TokenizeRequest(**defaults)


class TestTokenizeService:
    def test_reusable_returns_same_token_on_second_call(self, tokenize_service):
        req = _req(token_mode="REUSABLE")
        r1 = tokenize_service.tokenize(req, TEST_CALLER)
        r2 = tokenize_service.tokenize(req, TEST_CALLER)
        assert r1.token == r2.token

    def test_one_time_always_mints_new_token(self, tokenize_service):
        req = _req(token_mode="ONE_TIME")
        r1 = tokenize_service.tokenize(req, TEST_CALLER)
        r2 = tokenize_service.tokenize(req, TEST_CALLER)
        assert r1.token != r2.token

    def test_delegation_denied_raises_permission_error(self, tokenize_service):
        req = _req()
        with pytest.raises(PermissionError):
            tokenize_service.tokenize(req, "unauthorized-caller@jh.iam")

    def test_institution_isolation_different_fingerprint(self, tokenize_service, crypto):
        fp1 = crypto.hmac_fingerprint(TEST_INSTITUTION, TEST_PAN)
        fp2 = crypto.hmac_fingerprint(TEST_INSTITUTION_2, TEST_PAN)
        assert fp1 != fp2, "Same PAN must produce different fingerprints for different institutions"

    def test_scope_qualifiers_differentiate_tokens(self, tokenize_service):
        r1 = tokenize_service.tokenize(_req(scope_qualifiers={"application": "banno-mobile"}), TEST_CALLER)
        r2 = tokenize_service.tokenize(_req(scope_qualifiers={"application": "silverlake-core"}), TEST_CALLER)
        assert r1.token != r2.token

    def test_scope_qualifier_order_canonical(self, tokenize_service):
        req_a = _req(scope_qualifiers={"b": "2", "a": "1"})
        req_b = _req(scope_qualifiers={"a": "1", "b": "2"})
        r1 = tokenize_service.tokenize(req_a, TEST_CALLER)
        r2 = tokenize_service.tokenize(req_b, TEST_CALLER)
        assert r1.token == r2.token, "Scope qualifier order must not matter for REUSABLE lookup"

    def test_masked_pan_in_response(self, tokenize_service):
        r = tokenize_service.tokenize(_req(pan="4111111111111111"), TEST_CALLER)
        assert r.masked_pan == "411111******1111"

    def test_short_pan_masking(self, tokenize_service):
        r = tokenize_service.tokenize(_req(pan="4111111111111"), TEST_CALLER)
        # 13-digit: first 6 + 3 stars + last 4
        assert r.masked_pan == "411111***1111"

    def test_response_fields(self, tokenize_service):
        req = _req()
        r = tokenize_service.tokenize(req, TEST_CALLER)
        assert r.institution_id == TEST_INSTITUTION
        assert r.token_mode == "REUSABLE"
        assert r.expires_at is None  # no ttl_seconds

    def test_ttl_sets_expires_at(self, tokenize_service):
        req = _req(ttl_seconds=300, token_mode="ONE_TIME")
        r = tokenize_service.tokenize(req, TEST_CALLER)
        assert r.expires_at is not None
