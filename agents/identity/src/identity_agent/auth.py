"""OAuth2 client-credentials authentication for Microsoft Graph API."""

from __future__ import annotations

import logging
import time

import httpx

logger = logging.getLogger(__name__)


class GraphAuthProvider:
    """Acquires and caches an OAuth2 access token using client credentials flow."""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._token: str | None = None
        self._expires_at: float = 0.0

    @property
    def _token_url(self) -> str:
        return f"https://login.microsoftonline.com/{self._tenant_id}/oauth2/v2.0/token"

    async def get_token(self) -> str:
        if self._token and time.time() < self._expires_at - 60:
            return self._token
        return await self._refresh_token()

    async def _refresh_token(self) -> str:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                self._token_url,
                data={
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                    "grant_type": "client_credentials",
                },
            )
            resp.raise_for_status()
            data = resp.json()

        self._token = data["access_token"]
        self._expires_at = time.time() + data.get("expires_in", 3600)
        logger.info("Access token acquired (expires in %ds)", data.get("expires_in", 3600))
        return self._token  # type: ignore[return-value]
