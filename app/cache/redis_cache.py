from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_DEFAULT_TTL = 3600  # 1 hour


class TokenCache:
    """Optional Redis cache for hot token lookups.

    Cache key format: tok:{institution_id}:{token}
    Value: encrypted value blob (base64 string) — never plaintext sensitive data.

    If redis_url is None, all methods are no-ops (cache disabled).
    Institution isolation is enforced by the leading institution_id in the key.
    """

    def __init__(self, redis_url: str | None = None) -> None:
        self._enabled = False
        self._client = None
        if redis_url:
            try:
                import redis

                self._client = redis.from_url(redis_url, decode_responses=True)
                self._client.ping()
                self._enabled = True
                logger.info("Redis cache connected: %s", redis_url)
            except Exception as exc:
                logger.warning("Redis unavailable — cache disabled: %s", exc)

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _key(self, institution_id: str, token: str) -> str:
        return f"tok:{institution_id}:{token}"

    def get(self, institution_id: str, token: str) -> str | None:
        if not self._enabled or self._client is None:
            return None
        try:
            return self._client.get(self._key(institution_id, token))
        except Exception as exc:
            logger.warning("Redis GET failed: %s", exc)
            return None

    def set(
        self,
        institution_id: str,
        token: str,
        encrypted_value: str,
        ttl: int = _DEFAULT_TTL,
    ) -> None:
        if not self._enabled or self._client is None:
            return
        try:
            self._client.setex(self._key(institution_id, token), ttl, encrypted_value)
        except Exception as exc:
            logger.warning("Redis SET failed: %s", exc)

    def delete(self, institution_id: str, token: str) -> None:
        if not self._enabled or self._client is None:
            return
        try:
            self._client.delete(self._key(institution_id, token))
        except Exception as exc:
            logger.warning("Redis DELETE failed: %s", exc)

    def delete_by_pattern(self, institution_id: str, pan_fingerprint: str) -> int:
        """SCAN-based bulk eviction for fingerprint-based revocation.
        Returns number of keys deleted."""
        if not self._enabled or self._client is None:
            return 0
        pattern = f"tok:{institution_id}:*"
        deleted = 0
        try:
            cursor: int | str = 0
            while True:
                cursor, keys = self._client.scan(cursor=cursor, match=pattern, count=100)
                if keys:
                    self._client.delete(*keys)
                    deleted += len(keys)
                if cursor == 0:
                    break
        except Exception as exc:
            logger.warning("Redis SCAN/DELETE failed: %s", exc)
        return deleted
