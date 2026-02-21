from __future__ import annotations

from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Crypto provider: "local" requires no GCP creds; "kms" uses Cloud KMS
    CRYPTO_PROVIDER: Literal["local", "kms"] = "local"

    # 32-byte master key as lowercase hex (local provider only)
    LOCAL_MASTER_KEY_HEX: str = (
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    )

    # Redis (optional — disabled if empty/not set)
    REDIS_URL: str | None = None

    # Delegation grants JSON: {"caller@jh.iam": ["inst-001", "inst-002"]}
    # Production: queried from Spanner delegation grant table via Workload Identity
    DELEGATION_GRANTS_JSON: str = "{}"

    LOG_LEVEL: str = "INFO"

    # Cloud KMS (required only when CRYPTO_PROVIDER=kms)
    KMS_PROJECT: str | None = None
    KMS_LOCATION: str | None = None
    KMS_KEY_RING: str | None = None


settings = Settings()
