"""Ingestor: Directory role assignments and role definitions."""

from __future__ import annotations

from typing import Any

from identity_agent.ingest.base import BaseIngestor


class DirectoryRolesIngestor(BaseIngestor):
    async def ingest(self) -> dict[str, Any]:
        assignments = await self._get_all_pages(
            "/roleManagement/directory/roleAssignments"
        )
        definitions = await self._get_all_pages(
            "/roleManagement/directory/roleDefinitions"
        )
        return {
            "role_assignments": assignments,
            "role_definitions": definitions,
        }
