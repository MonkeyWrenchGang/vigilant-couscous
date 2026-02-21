"""Locust load test for the PCI Tokenization Service.

Traffic split matches docs/performance-validation.md:
  70% POST /v1/tokenize
  25% POST /v1/detokenize
   5% POST /v1/tokens/revoke

Usage:
  # Headless smoke run
  locust -f load/locustfile.py --host http://localhost:8000 --headless -u 100 -r 20 --run-time 60s

  # Interactive UI
  locust -f load/locustfile.py --host http://localhost:8000
"""

from __future__ import annotations

import random
import uuid
from collections import deque
from threading import Lock

from locust import HttpUser, between, task

# ── Test configuration ──────────────────────────────────────────────────────

CALLER_IDENTITY = "banno-payments@jh.iam"
INSTITUTION_ID = "inst-001"
DOMAIN = "card-payments"

# Test PANs — Visa/MC test card numbers (not real)
TEST_PANS = [
    "4111111111111111",
    "4012888888881881",
    "4222222222222",
    "5500005555555559",
    "5105105105105100",
]

SCOPE_QUALIFIERS_POOL = [
    {},
    {"application": "banno-mobile"},
    {"application": "silverlake-core", "channel": "web"},
    {"application": "symitar-mobile"},
]

REASON_CODES = ["fraud-review", "chargeback", "dispute", "reconciliation"]

# Shared token pool — seeded by workers and consumed by detokenize/revoke tasks
_token_pool: deque[str] = deque(maxlen=500)
_token_pool_lock = Lock()


def _add_token(token: str) -> None:
    with _token_pool_lock:
        _token_pool.append(token)


def _pop_token() -> str | None:
    with _token_pool_lock:
        return _token_pool.popleft() if _token_pool else None


# ── Locust user ──────────────────────────────────────────────────────────────


class TokenizationUser(HttpUser):
    """Simulates a JH caller application (e.g. Banno) performing tokenize/detokenize/revoke."""

    wait_time = between(0.001, 0.01)  # ~100–1000 RPS per user depending on count

    def on_start(self) -> None:
        """Pre-seed the token pool with a batch of tokens."""
        for pan in TEST_PANS[:3]:
            self._do_tokenize(pan=pan, token_mode="ONE_TIME")

    @task(70)
    def tokenize(self) -> None:
        self._do_tokenize(
            pan=random.choice(TEST_PANS),
            token_mode=random.choice(["REUSABLE", "ONE_TIME"]),
            scope_qualifiers=random.choice(SCOPE_QUALIFIERS_POOL),
        )

    @task(25)
    def detokenize(self) -> None:
        token = _pop_token()
        if token is None:
            # No tokens available — skip (counts as a skipped task, not a failure)
            return
        self.client.post(
            "/v1/detokenize",
            json={
                "token": token,
                "institution_id": INSTITUTION_ID,
                "reason_code": random.choice(REASON_CODES),
            },
            headers={"X-Caller-Identity": CALLER_IDENTITY},
            name="/v1/detokenize",
        )

    @task(5)
    def revoke(self) -> None:
        token = _pop_token()
        if token is None:
            return
        self.client.post(
            "/v1/tokens/revoke",
            json={"institution_id": INSTITUTION_ID, "token": token},
            headers={"X-Caller-Identity": CALLER_IDENTITY},
            name="/v1/tokens/revoke",
        )

    def _do_tokenize(
        self,
        pan: str = TEST_PANS[0],
        token_mode: str = "REUSABLE",
        scope_qualifiers: dict | None = None,
    ) -> None:
        with self.client.post(
            "/v1/tokenize",
            json={
                "pan": pan,
                "institution_id": INSTITUTION_ID,
                "domain": DOMAIN,
                "token_mode": token_mode,
                "scope_qualifiers": scope_qualifiers or {},
            },
            headers={"X-Caller-Identity": CALLER_IDENTITY},
            name="/v1/tokenize",
            catch_response=True,
        ) as resp:
            if resp.status_code == 200:
                token = resp.json().get("token")
                if token and token_mode == "ONE_TIME":
                    _add_token(token)
                resp.success()
            else:
                resp.failure(f"Tokenize failed: {resp.status_code}")
