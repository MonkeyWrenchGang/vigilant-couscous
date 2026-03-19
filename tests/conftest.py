from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

# Fixed test master key (32 bytes)
TEST_MASTER_KEY = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
TEST_CALLER = "banno-payments@jh.iam"
TEST_INSTITUTION = "inst-test-001"
TEST_INSTITUTION_2 = "inst-test-002"
TEST_PAN = "4111111111111111"
TEST_PAN_2 = "5500005555555559"
TEST_BANK_ACCOUNT = "1234567890"

# Set env vars before importing app
os.environ.setdefault("CRYPTO_PROVIDER", "local")
os.environ.setdefault("LOCAL_MASTER_KEY_HEX", TEST_MASTER_KEY)
os.environ.setdefault(
    "DELEGATION_GRANTS_JSON",
    f'{{"{TEST_CALLER}": ["{TEST_INSTITUTION}", "{TEST_INSTITUTION_2}"]}}',
)
os.environ.setdefault("REDIS_URL", "")  # disable Redis in tests


@pytest.fixture
def crypto():
    from app.crypto.local import LocalCryptoProvider

    return LocalCryptoProvider(TEST_MASTER_KEY)


@pytest.fixture
def vault():
    from app.vault.memory import MemoryVaultStore

    return MemoryVaultStore()


@pytest.fixture
def cache():
    from app.cache.redis_cache import TokenCache

    return TokenCache(None)  # disabled


@pytest.fixture
def delegation():
    from app.auth.delegation import DelegationGrantChecker

    return DelegationGrantChecker(
        f'{{"{TEST_CALLER}": ["{TEST_INSTITUTION}", "{TEST_INSTITUTION_2}"]}}'
    )


@pytest.fixture
def tokenize_service(crypto, vault, cache, delegation):
    from app.services.tokenize_service import TokenizeService

    return TokenizeService(crypto, vault, cache, delegation)


@pytest.fixture
def detokenize_service(crypto, vault, cache, delegation):
    from app.services.detokenize_service import DetokenizeService

    return DetokenizeService(crypto, vault, cache, delegation)


@pytest.fixture
def revoke_service(vault, cache, delegation):
    from app.services.revoke_service import RevokeService

    return RevokeService(vault, cache, delegation)


@pytest.fixture
def app_client():
    from app.main import app

    with TestClient(app) as client:
        yield client
