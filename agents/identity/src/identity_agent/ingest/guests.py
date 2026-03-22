"""Ingestor: Guest users and guest access policies."""

from __future__ import annotations

from typing import Any

from identity_agent.ingest.base import BaseIngestor


class GuestsIngestor(BaseIngestor):
    async def ingest(self) -> dict[str, Any]:
        guests = await self._get_all_pages(
            "/users?$filter=userType eq 'Guest'"
            "&$select=id,displayName,userPrincipalName,signInActivity,createdDateTime"
        )
        auth_policy = await self._get("/policies/authorizationPolicy")
        return {
            "guests": guests,
            "authorization_policy": auth_policy,
        }
