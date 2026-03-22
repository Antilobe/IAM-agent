"""Ingestor: App registrations and service principals."""

from __future__ import annotations

from typing import Any

from identity_agent.ingest.base import BaseIngestor


class AppRegistrationsIngestor(BaseIngestor):
    async def ingest(self) -> dict[str, Any]:
        applications = await self._get_all_pages("/applications")
        service_principals = await self._get_all_pages("/servicePrincipals")
        return {
            "applications": applications,
            "service_principals": service_principals,
        }
