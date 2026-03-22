"""Configuration loader — merges YAML config with environment overrides."""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class GraphConfig(BaseModel):
    base_url: str = "https://graph.microsoft.com/v1.0"
    beta_url: str = "https://graph.microsoft.com/beta"
    timeout_seconds: int = 30
    max_retries: int = 3
    page_size: int = 999


class AuthConfig(BaseModel):
    client_id: str = ""
    client_secret: str = ""
    authority: str = ""
    scopes: list[str] = Field(default_factory=lambda: ["https://graph.microsoft.com/.default"])


class LLMConfig(BaseModel):
    backend: str = "anthropic"
    model: str = "claude-sonnet-4-5-20241022"
    max_tokens: int = 4096
    temperature: float = 0.2


class StorageConfig(BaseModel):
    backend: str = "sqlite"
    sqlite_path: str = "./data/identity_agent.db"


class AgentConfig(BaseModel):
    tenant_id: str = ""
    graph_api: GraphConfig = Field(default_factory=GraphConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)


def load_config(config_path: Path | None = None) -> AgentConfig:
    """Load configuration from YAML, then overlay environment variables."""
    if config_path is None:
        config_path = Path(__file__).parent.parent.parent / "config" / "default.yaml"

    raw: dict = {}
    if config_path.exists():
        with open(config_path) as f:
            raw = yaml.safe_load(f) or {}

    # Substitute ${ENV_VAR} placeholders
    raw = _substitute_env(raw)

    # Environment overrides take precedence
    if tid := os.getenv("AZURE_TENANT_ID"):
        raw["tenant_id"] = tid
    if cid := os.getenv("AZURE_CLIENT_ID"):
        raw.setdefault("auth", {})["client_id"] = cid
    if cs := os.getenv("AZURE_CLIENT_SECRET"):
        raw.setdefault("auth", {})["client_secret"] = cs

    return AgentConfig.model_validate(raw)


def _substitute_env(obj: dict | list | str | object) -> dict | list | str | object:
    if isinstance(obj, str) and obj.startswith("${") and obj.endswith("}"):
        return os.getenv(obj[2:-1], "")
    if isinstance(obj, dict):
        return {k: _substitute_env(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_substitute_env(v) for v in obj]
    return obj
