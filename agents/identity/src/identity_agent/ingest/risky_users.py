"""Ingestor: Risky users (requires Entra ID P2 — degrades gracefully)."""

from __future__ import annotations

import logging
from typing import Any

from identity_agent.ingest.base import BaseIngestor

logger = logging.getLogger(__name__)


class RiskyUsersIngestor(BaseIngestor):
    async def ingest(self) -> dict[str, Any]:
        try:
            users = await self._get_all_pages("/identityProtection/riskyUsers")
            return {"risky_users": users, "available": True}
        except Exception as exc:
            msg = f"Risky users API unavailable (P2 required): {exc}"
            logger.warning(msg)
            self.errors.append(msg)
            return {"risky_users": [], "available": False}
