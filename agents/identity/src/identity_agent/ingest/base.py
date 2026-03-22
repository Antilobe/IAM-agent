"""Base ingestor with Graph API helpers: pagination, retry, error collection."""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any

import httpx

from identity_agent.auth import GraphAuthProvider

logger = logging.getLogger(__name__)


class BaseIngestor(ABC):
    """Abstract base for all Graph API ingestors.

    Provides:
    - Authenticated GET/POST with automatic pagination (@odata.nextLink)
    - Retry-After header handling and exponential backoff on 429s
    - Error collection without crashing
    - API call counter
    """

    def __init__(
        self,
        auth: GraphAuthProvider,
        base_url: str = "https://graph.microsoft.com/v1.0",
        beta_url: str = "https://graph.microsoft.com/beta",
        timeout: int = 30,
        max_retries: int = 3,
        page_size: int = 999,
    ) -> None:
        self._auth = auth
        self._base_url = base_url
        self._beta_url = beta_url
        self._timeout = timeout
        self._max_retries = max_retries
        self._page_size = page_size
        self.api_calls: int = 0
        self.errors: list[str] = []

    @property
    def name(self) -> str:
        return self.__class__.__name__

    @abstractmethod
    async def ingest(self) -> dict[str, Any]:
        """Run the ingestor and return raw data dict."""

    async def _get(self, url: str, *, beta: bool = False) -> dict[str, Any]:
        """Authenticated GET with retry."""
        if not url.startswith("http"):
            base = self._beta_url if beta else self._base_url
            url = f"{base}{url}"
        return await self._request("GET", url)

    async def _get_all_pages(self, url: str, *, beta: bool = False) -> list[dict[str, Any]]:
        """GET with automatic @odata.nextLink pagination."""
        results: list[dict[str, Any]] = []
        if not url.startswith("http"):
            base = self._beta_url if beta else self._base_url
            url = f"{base}{url}"

        next_url: str | None = url
        while next_url:
            data = await self._request("GET", next_url)
            results.extend(data.get("value", []))
            next_url = data.get("@odata.nextLink")
        return results

    async def _request(self, method: str, url: str) -> dict[str, Any]:
        """Execute an HTTP request with retries and backoff."""
        token = await self._auth.get_token()
        headers = {"Authorization": f"Bearer {token}"}
        last_exc: Exception | None = None

        for attempt in range(self._max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    self.api_calls += 1
                    resp = await client.request(method, url, headers=headers)

                    if resp.status_code == 429:
                        retry_after = int(resp.headers.get("Retry-After", 2 ** attempt))
                        logger.warning(
                            "%s: 429 throttled, retrying after %ds (attempt %d)",
                            self.name, retry_after, attempt + 1,
                        )
                        await asyncio.sleep(retry_after)
                        continue

                    resp.raise_for_status()
                    return resp.json()

            except Exception as exc:
                last_exc = exc
                if attempt < self._max_retries:
                    wait = 2 ** attempt
                    logger.warning(
                        "%s: request failed (%s), retrying in %ds",
                        self.name, exc, wait,
                    )
                    await asyncio.sleep(wait)

        error_msg = f"{self.name}: request failed after {self._max_retries + 1} attempts: {last_exc}"
        logger.error(error_msg)
        self.errors.append(error_msg)
        return {}
