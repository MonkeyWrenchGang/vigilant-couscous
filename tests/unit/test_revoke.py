from __future__ import annotations

import pytest

from app.models.requests import RevokeRequest, TokenizeRequest
from tests.conftest import TEST_CALLER, TEST_INSTITUTION, TEST_INSTITUTION_2, TEST_PAN


def _tokenize(service, sensitive_value=TEST_PAN, institution_id=TEST_INSTITUTION, scope_qualifiers=None):
    req = TokenizeRequest(
        sensitive_data_type="PAN",
        sensitive_value=sensitive_value,
        institution_id=institution_id,
        domain="card-payments",
        scope_qualifiers=scope_qualifiers or {},
        token_mode="ONE_TIME",
    )
    return service.tokenize(req, TEST_CALLER)


class TestRevokeService:
    def test_revoke_by_token(self, tokenize_service, revoke_service):
        tr = _tokenize(tokenize_service)
        resp = revoke_service.revoke(
            RevokeRequest(institution_id=TEST_INSTITUTION, token=tr.token), TEST_CALLER
        )
        assert resp.revoked_count == 1
        assert resp.institution_id == TEST_INSTITUTION

    def test_revoke_by_token_not_found_returns_zero(self, revoke_service):
        resp = revoke_service.revoke(
            RevokeRequest(institution_id=TEST_INSTITUTION, token="ghost-token"), TEST_CALLER
        )
        assert resp.revoked_count == 0

    def test_revoke_by_fingerprint_bulk(self, tokenize_service, revoke_service, crypto):
        # Mint two ONE_TIME tokens for the same PAN
        _tokenize(tokenize_service)
        _tokenize(tokenize_service)
        fingerprint = crypto.hmac_fingerprint(TEST_INSTITUTION, TEST_PAN)
        resp = revoke_service.revoke(
            RevokeRequest(
                institution_id=TEST_INSTITUTION,
                value_fingerprint=fingerprint,
                domain="card-payments",
            ),
            TEST_CALLER,
        )
        assert resp.revoked_count == 2

    def test_revoke_by_fingerprint_with_scope_filter(self, tokenize_service, revoke_service, crypto):
        _tokenize(tokenize_service, scope_qualifiers={"application": "banno-mobile"})
        _tokenize(tokenize_service, scope_qualifiers={"application": "silverlake-core"})
        fingerprint = crypto.hmac_fingerprint(TEST_INSTITUTION, TEST_PAN)
        # Only revoke banno-mobile tokens
        resp = revoke_service.revoke(
            RevokeRequest(
                institution_id=TEST_INSTITUTION,
                value_fingerprint=fingerprint,
                domain="card-payments",
                scope_qualifiers_filter={"application": "banno-mobile"},
            ),
            TEST_CALLER,
        )
        assert resp.revoked_count == 1

    def test_revoke_denied_for_unauthorized_caller(self, tokenize_service, revoke_service):
        tr = _tokenize(tokenize_service)
        with pytest.raises(PermissionError):
            revoke_service.revoke(
                RevokeRequest(institution_id=TEST_INSTITUTION, token=tr.token),
                "bad-actor@jh.iam",
            )

    def test_revoke_does_not_cross_institutions(self, tokenize_service, revoke_service, crypto):
        # Token minted for inst-test-001
        tr = _tokenize(tokenize_service, institution_id=TEST_INSTITUTION)
        # Try to revoke it under a different institution
        resp = revoke_service.revoke(
            RevokeRequest(institution_id=TEST_INSTITUTION_2, token=tr.token), TEST_CALLER
        )
        assert resp.revoked_count == 0, "Cross-institution revoke must not succeed"

    def test_double_revoke_returns_zero_second_time(self, tokenize_service, revoke_service):
        tr = _tokenize(tokenize_service)
        r1 = revoke_service.revoke(
            RevokeRequest(institution_id=TEST_INSTITUTION, token=tr.token), TEST_CALLER
        )
        r2 = revoke_service.revoke(
            RevokeRequest(institution_id=TEST_INSTITUTION, token=tr.token), TEST_CALLER
        )
        assert r1.revoked_count == 1
        assert r2.revoked_count == 0
