"""Ingestor: Conditional Access policies, named locations, auth strengths."""

from __future__ import annotations

from typing import Any

from identity_agent.ingest.base import BaseIngestor


class ConditionalAccessIngestor(BaseIngestor):
    async def ingest(self) -> dict[str, Any]:
        policies = await self._get_all_pages("/identity/conditionalAccess/policies")
        named_locations = await self._get_all_pages("/identity/conditionalAccess/namedLocations")
        auth_strengths = await self._get_all_pages(
            "/identity/conditionalAccess/authenticationStrength/policies"
        )
        return {
            "policies": policies,
            "named_locations": named_locations,
            "authentication_strengths": auth_strengths,
        }
