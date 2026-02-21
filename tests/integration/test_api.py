from __future__ import annotations

import pytest

from tests.conftest import TEST_CALLER, TEST_INSTITUTION, TEST_PAN


HEADERS = {"X-Caller-Identity": TEST_CALLER}
TOKENIZE_URL = "/v1/tokenize"
DETOKENIZE_URL = "/v1/detokenize"
REVOKE_URL = "/v1/tokens/revoke"


class TestHealthEndpoint:
    def test_health_ok(self, app_client):
        r = app_client.get("/healthz")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


class TestTokenizeEndpoint:
    def test_basic_tokenize(self, app_client):
        r = app_client.post(
            TOKENIZE_URL,
            json={"pan": TEST_PAN, "institution_id": TEST_INSTITUTION, "domain": "card-payments"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        body = r.json()
        assert "token" in body
        assert body["masked_pan"] == "411111******1111"
        assert body["institution_id"] == TEST_INSTITUTION

    def test_reusable_returns_same_token(self, app_client):
        payload = {
            "pan": TEST_PAN,
            "institution_id": TEST_INSTITUTION,
            "domain": "card-payments",
            "token_mode": "REUSABLE",
        }
        r1 = app_client.post(TOKENIZE_URL, json=payload, headers=HEADERS)
        r2 = app_client.post(TOKENIZE_URL, json=payload, headers=HEADERS)
        assert r1.json()["token"] == r2.json()["token"]

    def test_one_time_mints_new_token(self, app_client):
        payload = {
            "pan": TEST_PAN,
            "institution_id": TEST_INSTITUTION,
            "domain": "card-payments",
            "token_mode": "ONE_TIME",
        }
        r1 = app_client.post(TOKENIZE_URL, json=payload, headers=HEADERS)
        r2 = app_client.post(TOKENIZE_URL, json=payload, headers=HEADERS)
        assert r1.json()["token"] != r2.json()["token"]

    def test_missing_caller_identity_returns_403(self, app_client):
        r = app_client.post(
            TOKENIZE_URL,
            json={"pan": TEST_PAN, "institution_id": TEST_INSTITUTION, "domain": "card-payments"},
        )
        assert r.status_code == 403

    def test_invalid_pan_returns_422(self, app_client):
        r = app_client.post(
            TOKENIZE_URL,
            json={"pan": "not-a-pan", "institution_id": TEST_INSTITUTION, "domain": "card-payments"},
            headers=HEADERS,
        )
        assert r.status_code == 422

    def test_unauthorized_institution_returns_403(self, app_client):
        r = app_client.post(
            TOKENIZE_URL,
            json={"pan": TEST_PAN, "institution_id": "inst-unknown", "domain": "card-payments"},
            headers=HEADERS,
        )
        assert r.status_code == 403


class TestDetokenizeEndpoint:
    def _tokenize(self, client, pan=TEST_PAN) -> str:
        r = client.post(
            TOKENIZE_URL,
            json={"pan": pan, "institution_id": TEST_INSTITUTION, "domain": "card-payments", "token_mode": "ONE_TIME"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        return r.json()["token"]

    def test_masked_pan_default(self, app_client):
        token = self._tokenize(app_client)
        r = app_client.post(
            DETOKENIZE_URL,
            json={"token": token, "institution_id": TEST_INSTITUTION, "reason_code": "fraud"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["pan"] == "411111******1111"

    def test_full_pan_with_operator_id(self, app_client):
        token = self._tokenize(app_client)
        r = app_client.post(
            DETOKENIZE_URL,
            json={
                "token": token,
                "institution_id": TEST_INSTITUTION,
                "reason_code": "fraud",
                "detokenize_mode": "FULL_PAN",
                "operator_id": "op-001",
            },
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["pan"] == TEST_PAN

    def test_full_pan_without_operator_id_returns_422(self, app_client):
        token = self._tokenize(app_client)
        r = app_client.post(
            DETOKENIZE_URL,
            json={
                "token": token,
                "institution_id": TEST_INSTITUTION,
                "reason_code": "fraud",
                "detokenize_mode": "FULL_PAN",
            },
            headers=HEADERS,
        )
        assert r.status_code == 422

    def test_not_found_token_returns_404(self, app_client):
        r = app_client.post(
            DETOKENIZE_URL,
            json={"token": "ghost-token", "institution_id": TEST_INSTITUTION, "reason_code": "test"},
            headers=HEADERS,
        )
        assert r.status_code == 404

    def test_missing_caller_identity_returns_403(self, app_client):
        r = app_client.post(
            DETOKENIZE_URL,
            json={"token": "any", "institution_id": TEST_INSTITUTION, "reason_code": "test"},
        )
        assert r.status_code == 403


class TestRevokeEndpoint:
    def _tokenize(self, client, token_mode="ONE_TIME") -> str:
        r = client.post(
            TOKENIZE_URL,
            json={
                "pan": TEST_PAN,
                "institution_id": TEST_INSTITUTION,
                "domain": "card-payments",
                "token_mode": token_mode,
            },
            headers=HEADERS,
        )
        assert r.status_code == 200
        return r.json()["token"]

    def test_revoke_by_token(self, app_client):
        token = self._tokenize(app_client)
        r = app_client.post(
            REVOKE_URL,
            json={"institution_id": TEST_INSTITUTION, "token": token},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["revoked_count"] == 1

    def test_revoke_then_detokenize_returns_404(self, app_client):
        token = self._tokenize(app_client)
        app_client.post(REVOKE_URL, json={"institution_id": TEST_INSTITUTION, "token": token}, headers=HEADERS)
        r = app_client.post(
            DETOKENIZE_URL,
            json={"token": token, "institution_id": TEST_INSTITUTION, "reason_code": "test"},
            headers=HEADERS,
        )
        assert r.status_code == 404

    def test_neither_token_nor_fingerprint_returns_422(self, app_client):
        r = app_client.post(
            REVOKE_URL,
            json={"institution_id": TEST_INSTITUTION},
            headers=HEADERS,
        )
        assert r.status_code == 422

    def test_full_cycle_tokenize_detokenize_revoke(self, app_client):
        # Tokenize
        r1 = app_client.post(
            TOKENIZE_URL,
            json={"pan": TEST_PAN, "institution_id": TEST_INSTITUTION, "domain": "card-payments", "token_mode": "ONE_TIME"},
            headers=HEADERS,
        )
        assert r1.status_code == 200
        token = r1.json()["token"]

        # Detokenize (masked)
        r2 = app_client.post(
            DETOKENIZE_URL,
            json={"token": token, "institution_id": TEST_INSTITUTION, "reason_code": "test"},
            headers=HEADERS,
        )
        assert r2.status_code == 200
        assert r2.json()["pan"] == "411111******1111"

        # Revoke
        r3 = app_client.post(
            REVOKE_URL,
            json={"institution_id": TEST_INSTITUTION, "token": token},
            headers=HEADERS,
        )
        assert r3.status_code == 200
        assert r3.json()["revoked_count"] == 1

        # Detokenize after revoke → 404
        r4 = app_client.post(
            DETOKENIZE_URL,
            json={"token": token, "institution_id": TEST_INSTITUTION, "reason_code": "test"},
            headers=HEADERS,
        )
        assert r4.status_code == 404
