"""Ingestor: MFA registration details."""

from __future__ import annotations

from typing import Any

from identity_agent.ingest.base import BaseIngestor


class MFARegistrationIngestor(BaseIngestor):
    async def ingest(self) -> dict[str, Any]:
        details = await self._get_all_pages(
            "/reports/authenticationMethods/userRegistrationDetails"
        )
        return {"user_registration_details": details}
