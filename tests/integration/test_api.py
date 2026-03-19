from __future__ import annotations

import pytest

from tests.conftest import TEST_BANK_ACCOUNT, TEST_CALLER, TEST_INSTITUTION, TEST_PAN


HEADERS = {"X-Caller-Identity": TEST_CALLER}
TOKENIZE_URL = "/v1/tokenize"
DETOKENIZE_URL = "/v1/detokenize"
REVOKE_URL = "/v1/tokens/revoke"


def _pan_payload(**overrides):
    defaults = {
        "sensitive_data_type": "PAN",
        "sensitive_value": TEST_PAN,
        "institution_id": TEST_INSTITUTION,
        "domain": "card-payments",
    }
    defaults.update(overrides)
    return defaults


class TestHealthEndpoint:
    def test_health_ok(self, app_client):
        r = app_client.get("/healthz")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


class TestTokenizeEndpoint:
    def test_basic_tokenize_pan(self, app_client):
        r = app_client.post(TOKENIZE_URL, json=_pan_payload(), headers=HEADERS)
        assert r.status_code == 200
        body = r.json()
        assert "token" in body
        assert body["masked_value"] == "411111******1111"
        assert body["sensitive_data_type"] == "PAN"
        assert body["institution_id"] == TEST_INSTITUTION

    def test_basic_tokenize_bank_account(self, app_client):
        r = app_client.post(
            TOKENIZE_URL,
            json={
                "sensitive_data_type": "BANK_ACCOUNT",
                "sensitive_value": TEST_BANK_ACCOUNT,
                "institution_id": TEST_INSTITUTION,
                "domain": "ach-transfers",
                "scope_qualifiers": {"routing_number": "021000021"},
            },
            headers=HEADERS,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["masked_value"] == "******7890"
        assert body["sensitive_data_type"] == "BANK_ACCOUNT"

    def test_reusable_returns_same_token(self, app_client):
        payload = _pan_payload(token_mode="REUSABLE")
        r1 = app_client.post(TOKENIZE_URL, json=payload, headers=HEADERS)
        r2 = app_client.post(TOKENIZE_URL, json=payload, headers=HEADERS)
        assert r1.json()["token"] == r2.json()["token"]

    def test_one_time_mints_new_token(self, app_client):
        payload = _pan_payload(token_mode="ONE_TIME")
        r1 = app_client.post(TOKENIZE_URL, json=payload, headers=HEADERS)
        r2 = app_client.post(TOKENIZE_URL, json=payload, headers=HEADERS)
        assert r1.json()["token"] != r2.json()["token"]

    def test_missing_caller_identity_returns_403(self, app_client):
        r = app_client.post(TOKENIZE_URL, json=_pan_payload())
        assert r.status_code == 403

    def test_invalid_pan_returns_422(self, app_client):
        r = app_client.post(
            TOKENIZE_URL,
            json=_pan_payload(sensitive_value="not-a-pan"),
            headers=HEADERS,
        )
        assert r.status_code == 422

    def test_invalid_bank_account_returns_422(self, app_client):
        r = app_client.post(
            TOKENIZE_URL,
            json={"sensitive_data_type": "BANK_ACCOUNT", "sensitive_value": "123", "institution_id": TEST_INSTITUTION},
            headers=HEADERS,
        )
        assert r.status_code == 422  # too short (min 4)

    def test_unauthorized_institution_returns_403(self, app_client):
        r = app_client.post(
            TOKENIZE_URL,
            json=_pan_payload(institution_id="inst-unknown"),
            headers=HEADERS,
        )
        assert r.status_code == 403

    def test_domain_optional_defaults(self, app_client):
        payload = {
            "sensitive_data_type": "PAN",
            "sensitive_value": TEST_PAN,
            "institution_id": TEST_INSTITUTION,
            "token_mode": "ONE_TIME",
        }
        r = app_client.post(TOKENIZE_URL, json=payload, headers=HEADERS)
        assert r.status_code == 200


class TestDetokenizeEndpoint:
    def _tokenize(self, client, sensitive_value=TEST_PAN, sensitive_data_type="PAN") -> str:
        r = client.post(
            TOKENIZE_URL,
            json={
                "sensitive_data_type": sensitive_data_type,
                "sensitive_value": sensitive_value,
                "institution_id": TEST_INSTITUTION,
                "domain": "card-payments",
                "token_mode": "ONE_TIME",
            },
            headers=HEADERS,
        )
        assert r.status_code == 200
        return r.json()["token"]

    def test_masked_default(self, app_client):
        token = self._tokenize(app_client)
        r = app_client.post(
            DETOKENIZE_URL,
            json={"token": token, "institution_id": TEST_INSTITUTION, "reason_code": "fraud"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["sensitive_value"] == "411111******1111"
        assert r.json()["sensitive_data_type"] == "PAN"

    def test_full_with_operator_id(self, app_client):
        token = self._tokenize(app_client)
        r = app_client.post(
            DETOKENIZE_URL,
            json={
                "token": token,
                "institution_id": TEST_INSTITUTION,
                "reason_code": "fraud",
                "detokenize_mode": "FULL",
                "operator_id": "op-001",
            },
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["sensitive_value"] == TEST_PAN

    def test_full_without_operator_id_returns_422(self, app_client):
        token = self._tokenize(app_client)
        r = app_client.post(
            DETOKENIZE_URL,
            json={
                "token": token,
                "institution_id": TEST_INSTITUTION,
                "reason_code": "fraud",
                "detokenize_mode": "FULL",
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
            json=_pan_payload(token_mode=token_mode),
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
            json=_pan_payload(token_mode="ONE_TIME"),
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
        assert r2.json()["sensitive_value"] == "411111******1111"

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
