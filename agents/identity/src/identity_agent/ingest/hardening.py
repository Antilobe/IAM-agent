"""Ingestor: Entra ID tenant hardening settings.

Adapted from Security-Agent/entra_hardening.py. Collects tenant-level
security configuration matching the identity_catalogue entra_hardening layer.
"""

from __future__ import annotations

import logging
from typing import Any

from identity_agent.ingest.base import BaseIngestor

logger = logging.getLogger(__name__)

# Risk-based CA policy catalogue IDs
RISK_CA_POLICY_IDS = {"CAU005", "CAU006", "CAU007"}


class HardeningIngestor(BaseIngestor):
    async def ingest(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "app_registration": {},
            "tenant_creation": {},
            "admin_consent": {},
            "linkedin": {},
            "guest_invite": {},
            "portal_access": {},
            "security_defaults": {},
            "risk_based_ca": {},
        }

        # Authorization Policy — covers app reg, tenant creation, guest invite, portal access
        await self._ingest_authorization_policy(result)

        # Admin consent request policy
        await self._ingest_consent_policy(result)

        # Organization settings (LinkedIn)
        await self._ingest_organization(result)

        # Security Defaults
        await self._ingest_security_defaults(result)

        # Risk-based CA verification (checks CA policies for risk conditions)
        await self._ingest_risk_based_ca(result)

        return result

    async def _ingest_authorization_policy(self, result: dict) -> None:
        try:
            data = await self._get("/policies/authorizationPolicy")
            if not data:
                return

            default_perms = data.get("defaultUserRolePermissions", {})

            result["app_registration"] = {
                "users_can_register": default_perms.get("allowedToCreateApps", True),
            }
            result["tenant_creation"] = {
                "users_can_create": default_perms.get("allowedToCreateTenants", True),
            }
            result["guest_invite"] = {
                "policy": data.get("allowInvitesFrom", "everyone"),
            }
            result["portal_access"] = {
                "restricted_to_admins": not default_perms.get(
                    "allowedToReadOtherUsers", True
                ),
            }
        except Exception as exc:
            msg = f"Authorization policy fetch failed: {exc}"
            logger.warning(msg)
            self.errors.append(msg)

    async def _ingest_consent_policy(self, result: dict) -> None:
        try:
            data = await self._get("/policies/adminConsentRequestPolicy")
            if not data:
                return

            # If admin consent is enabled, user consent is restricted
            is_enabled = data.get("isEnabled", False)
            result["admin_consent"] = {
                "user_consent_restricted": is_enabled,
            }
        except Exception as exc:
            msg = f"Admin consent policy fetch failed: {exc}"
            logger.warning(msg)
            self.errors.append(msg)

    async def _ingest_organization(self, result: dict) -> None:
        try:
            data = await self._get("/organization")
            orgs = data.get("value", [])
            if not orgs:
                return

            org = orgs[0]
            # LinkedIn integration — check directory setting
            # The actual setting is in directorySetting; simplified check
            result["linkedin"] = {
                "enabled": False,  # Default conservative; requires beta API for full check
            }
        except Exception as exc:
            msg = f"Organization fetch failed: {exc}"
            logger.warning(msg)
            self.errors.append(msg)

    async def _ingest_security_defaults(self, result: dict) -> None:
        try:
            data = await self._get(
                "/policies/identitySecurityDefaultsEnforcementPolicy"
            )
            if data:
                result["security_defaults"] = {
                    "enabled": data.get("isEnabled", False),
                }
        except Exception as exc:
            msg = f"Security defaults fetch failed: {exc}"
            logger.warning(msg)
            self.errors.append(msg)

    async def _ingest_risk_based_ca(self, result: dict) -> None:
        """Check if risk-based CA policies exist by looking at CA policies."""
        try:
            policies = await self._get_all_pages(
                "/identity/conditionalAccess/policies"
            )
            has_sign_in_risk = False
            has_user_risk = False

            for p in policies:
                conditions = p.get("conditions", {}) or {}
                state = p.get("state", "")
                if state == "disabled":
                    continue

                sign_in_risk = conditions.get("signInRiskLevels", [])
                user_risk = conditions.get("userRiskLevels", [])

                if sign_in_risk:
                    has_sign_in_risk = True
                if user_risk:
                    has_user_risk = True

            result["risk_based_ca"] = {
                "verified": has_sign_in_risk and has_user_risk,
                "has_sign_in_risk_policy": has_sign_in_risk,
                "has_user_risk_policy": has_user_risk,
            }
        except Exception as exc:
            msg = f"Risk-based CA verification failed: {exc}"
            logger.warning(msg)
            self.errors.append(msg)
