"""Ingestor: Access reviews (requires governance license — degrades gracefully)."""

from __future__ import annotations

import logging
from typing import Any

from identity_agent.ingest.base import BaseIngestor

logger = logging.getLogger(__name__)


class AccessReviewsIngestor(BaseIngestor):
    async def ingest(self) -> dict[str, Any]:
        try:
            definitions = await self._get_all_pages(
                "/identityGovernance/accessReviews/definitions"
            )
            return {"access_review_definitions": definitions, "available": True}
        except Exception as exc:
            msg = f"Access reviews API unavailable (requires license): {exc}"
            logger.warning(msg)
            self.errors.append(msg)
            return {"access_review_definitions": [], "available": False}
