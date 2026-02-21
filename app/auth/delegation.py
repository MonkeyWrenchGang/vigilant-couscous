from __future__ import annotations

import json
import logging

from fastapi import Header, HTTPException, Request

logger = logging.getLogger(__name__)


class DelegationGrantChecker:
    """POV delegation grant checker backed by a JSON env-var stub.

    Production replacement: query the Spanner delegation grant table,
    keyed on (caller_app_identity, institution_id), using Workload Identity
    JWT from the Authorization header.

    JSON format:
        {"caller@jh.iam": ["inst-001", "inst-002"], ...}

    Fail-closed: any parse error or missing grant → denied (False).
    """

    def __init__(self, grants_json: str) -> None:
        self._grants: dict[str, set[str]] = {}
        try:
            raw: dict[str, list[str]] = json.loads(grants_json)
            self._grants = {k: set(v) for k, v in raw.items()}
            logger.info("Delegation grants loaded for %d callers", len(self._grants))
        except Exception as exc:
            logger.warning("Failed to parse DELEGATION_GRANTS_JSON: %s — all requests denied", exc)

    def is_authorized(self, caller_identity: str, institution_id: str) -> bool:
        """Returns True only if caller_identity has an explicit grant for institution_id."""
        try:
            return institution_id in self._grants.get(caller_identity, set())
        except Exception:
            return False  # fail-closed


def get_caller_identity(
    x_caller_identity: str | None = Header(default=None),
) -> str:
    """FastAPI dependency: extract caller identity from X-Caller-Identity header.

    Production replacement: validate Workload Identity Bearer JWT from the
    Authorization header and extract the service account email from the sub claim.
    """
    if not x_caller_identity:
        raise HTTPException(status_code=403, detail="Missing X-Caller-Identity header")
    return x_caller_identity
