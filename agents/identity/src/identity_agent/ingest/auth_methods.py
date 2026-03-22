"""Ingestor: Authentication methods policy (SMS, FIDO2, Authenticator, etc.)."""

from __future__ import annotations

import logging
from typing import Any

from identity_agent.ingest.base import BaseIngestor

logger = logging.getLogger(__name__)

# Methods considered weak / phishable
WEAK_METHODS = {"sms", "voice", "email"}


class AuthMethodsIngestor(BaseIngestor):
    async def ingest(self) -> dict[str, Any]:
        policy = await self._get("/policies/authenticationMethodsPolicy")
        if not policy:
            return self._empty()

        configs = policy.get("authenticationMethodConfigurations", [])

        enabled_methods: list[str] = []
        weak_methods_enabled: list[str] = []
        fido2_enabled = False
        passkey_enabled = False

        for cfg in configs:
            method_id = cfg.get("id", "")
            state = cfg.get("state", "disabled")
            if state != "enabled":
                continue

            enabled_methods.append(method_id)

            if method_id in WEAK_METHODS:
                weak_methods_enabled.append(method_id)
            if method_id == "fido2":
                fido2_enabled = True
            if method_id in ("microsoftAuthenticator",):
                # Passkey is a sub-capability of Authenticator
                # Check if passkey/device-bound credential is enabled
                pass

        # Check for passkey via the dedicated passkey config if present
        for cfg in configs:
            if cfg.get("id") == "microsoftAuthenticator" and cfg.get("state") == "enabled":
                feature_settings = cfg.get("featureSettings", {})
                if feature_settings.get("displayAppInformationRequiredState", {}).get("state") == "enabled":
                    passkey_enabled = True

        return {
            "enabled_methods": enabled_methods,
            "fido2_enabled": fido2_enabled,
            "passkey_enabled": passkey_enabled,
            "weak_methods_enabled": weak_methods_enabled,
            "raw_policy": policy,
        }

    def _empty(self) -> dict[str, Any]:
        return {
            "enabled_methods": [],
            "fido2_enabled": False,
            "passkey_enabled": False,
            "weak_methods_enabled": [],
            "raw_policy": {},
        }
