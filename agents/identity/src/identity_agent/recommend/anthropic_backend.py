"""Anthropic LLM backend implementing the LLMBackend protocol."""

from __future__ import annotations

import anthropic


class AnthropicBackend:
    """LLMBackend implementation using the Anthropic SDK."""

    def __init__(self, model: str = "claude-sonnet-4-5-20241022", max_tokens: int = 4096) -> None:
        self._client = anthropic.AsyncAnthropic()
        self._model = model
        self._max_tokens = max_tokens

    async def complete(self, system: str, user: str) -> str:
        response = await self._client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return response.content[0].text
