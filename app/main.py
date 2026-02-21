from __future__ import annotations

import logging
import logging.config
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from app.api.v1 import detokenize, revoke, tokenize
from app.auth.delegation import DelegationGrantChecker
from app.cache.redis_cache import TokenCache
from app.config import settings
from app.models.responses import HealthResponse
from app.vault.memory import MemoryVaultStore


def _configure_logging() -> None:
    logging.basicConfig(
        level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Suppress noisy libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


def _build_crypto():  # type: ignore[return]
    if settings.CRYPTO_PROVIDER == "local":
        from app.crypto.local import LocalCryptoProvider

        return LocalCryptoProvider(settings.LOCAL_MASTER_KEY_HEX)
    elif settings.CRYPTO_PROVIDER == "kms":
        from app.crypto.kms import KMSCryptoProvider

        if not all([settings.KMS_PROJECT, settings.KMS_LOCATION, settings.KMS_KEY_RING]):
            raise RuntimeError(
                "KMS_PROJECT, KMS_LOCATION, and KMS_KEY_RING must be set when CRYPTO_PROVIDER=kms"
            )
        return KMSCryptoProvider(
            settings.KMS_PROJECT,  # type: ignore[arg-type]
            settings.KMS_LOCATION,  # type: ignore[arg-type]
            settings.KMS_KEY_RING,  # type: ignore[arg-type]
        )
    else:
        raise RuntimeError(f"Unknown CRYPTO_PROVIDER: {settings.CRYPTO_PROVIDER!r}")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    _configure_logging()
    logger = logging.getLogger(__name__)
    logger.info("Starting PCI Tokenization Service (crypto=%s)", settings.CRYPTO_PROVIDER)

    crypto = _build_crypto()
    vault = MemoryVaultStore()
    cache = TokenCache(settings.REDIS_URL)
    delegation = DelegationGrantChecker(settings.DELEGATION_GRANTS_JSON)

    # Wire up services
    from app.services.detokenize_service import DetokenizeService
    from app.services.revoke_service import RevokeService
    from app.services.tokenize_service import TokenizeService

    app.state.tokenize_service = TokenizeService(crypto, vault, cache, delegation)
    app.state.detokenize_service = DetokenizeService(crypto, vault, cache, delegation)
    app.state.revoke_service = RevokeService(vault, cache, delegation)

    logger.info(
        "Service ready. Redis cache: %s",
        "enabled" if cache.enabled else "disabled (no REDIS_URL)",
    )
    yield
    logger.info("Shutting down PCI Tokenization Service")


app = FastAPI(
    title="PCI Tokenization Service",
    version="0.1.0",
    description=(
        "PCI DSS 4.0-compliant tokenization platform POV — Jack Henry Associates. "
        "Tokenizes PANs, maintains a secure token vault, supports multiple tokens per PAN "
        "scoped by institution and caller context, and provides robust audit logging. "
        "\n\n**Authentication**: Supply `X-Caller-Identity: caller@jh.iam` header (POV stub; "
        "production uses Google Cloud Workload Identity JWT). "
        "\n\n**Authorization**: Delegation grants configured via `DELEGATION_GRANTS_JSON` env var."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

app.include_router(tokenize.router, prefix="/v1", tags=["Tokenize"])
app.include_router(detokenize.router, prefix="/v1", tags=["Detokenize"])
app.include_router(revoke.router, prefix="/v1", tags=["Revoke"])


@app.get("/healthz", response_model=HealthResponse, tags=["Health"])
def health() -> HealthResponse:
    """Health check endpoint for load balancer / readiness probe."""
    return HealthResponse(status="ok")
