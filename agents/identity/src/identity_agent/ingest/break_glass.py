"""Ingestor: Break glass (emergency access) accounts.

Convention-based detection, adapted from Security-Agent/entra_break_glass.py.
Discovers accounts by jobTitle or displayName convention, then checks posture.
"""

from __future__ import annotations

import logging
from typing import Any

from identity_agent.ingest.base import BaseIngestor

logger = logging.getLogger(__name__)

GLOBAL_ADMIN_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"
JOB_TITLE_CONVENTION = "Emergency Access Account"
DISPLAY_NAME_PREFIX = "Break Glass"
CA_EXCLUSION_GROUP_NAMES = [
    "CA-BreakGlassExclusion",
    "SG-BreakGlass",
    "SEC-CAExclusion-BreakGlass",
]


class BreakGlassIngestor(BaseIngestor):
    async def ingest(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "summary": {"accounts_found": 0, "valid_accounts": 0, "issues": []},
            "accounts": [],
            "ca_exclusion_group": {"exists": False, "member_count": 0},
        }

        # Step 1: Discover break glass accounts by naming convention
        accounts = await self._discover_accounts()
        result["summary"]["accounts_found"] = len(accounts)

        if not accounts:
            result["summary"]["issues"].append("No break glass accounts detected")
            logger.warning("No break glass accounts found in tenant")
            return result

        # Step 2: Find CA exclusion group
        ca_group = await self._find_ca_exclusion_group()
        result["ca_exclusion_group"] = ca_group
        ca_group_member_ids = ca_group.get("member_ids", set())

        # Step 3: Get Global Admin role members
        ga_member_ids = await self._get_global_admin_member_ids()

        # Step 4: Enrich each account
        enriched = []
        valid = 0
        for acct in accounts:
            user_id = acct.get("id", "")
            enabled = acct.get("accountEnabled", False)
            is_cloud_only = not acct.get("onPremisesSyncEnabled", False)
            has_global_admin = user_id in ga_member_ids
            in_ca_exclusion = user_id in ca_group_member_ids

            # MFA registration check
            mfa_registered = await self._check_mfa_registered(user_id)

            # Risk level
            risk_level = await self._check_risk_level(user_id)

            entry = {
                "id": user_id,
                "upn": acct.get("userPrincipalName", ""),
                "display_name": acct.get("displayName", ""),
                "enabled": enabled,
                "is_cloud_only": is_cloud_only,
                "has_global_admin": has_global_admin,
                "in_ca_exclusion_group": in_ca_exclusion,
                "mfa_registered": mfa_registered,
                "risk_level": risk_level,
            }
            enriched.append(entry)

            # Validity check: enabled + cloud-only + GA + CA exclusion
            if enabled and is_cloud_only and has_global_admin and in_ca_exclusion:
                valid += 1

        result["accounts"] = enriched
        result["summary"]["valid_accounts"] = valid
        return result

    async def _discover_accounts(self) -> list[dict]:
        """Find break glass accounts by jobTitle or displayName convention."""
        # Try jobTitle first (most reliable)
        try:
            by_title = await self._get_all_pages(
                f"/users?$filter=jobTitle eq '{JOB_TITLE_CONVENTION} - DO NOT DELETE'"
                "&$select=id,displayName,userPrincipalName,accountEnabled,"
                "onPremisesSyncEnabled,jobTitle,signInActivity"
            )
            if by_title:
                logger.info("Found %d break glass accounts by jobTitle", len(by_title))
                return by_title
        except Exception:
            pass

        # Fallback: displayName prefix
        try:
            by_name = await self._get_all_pages(
                f"/users?$filter=startsWith(displayName,'{DISPLAY_NAME_PREFIX}')"
                "&$select=id,displayName,userPrincipalName,accountEnabled,"
                "onPremisesSyncEnabled,jobTitle,signInActivity"
            )
            if by_name:
                logger.info("Found %d break glass accounts by displayName", len(by_name))
                return by_name
        except Exception:
            pass

        return []

    async def _find_ca_exclusion_group(self) -> dict[str, Any]:
        """Find the CA exclusion group by known naming conventions."""
        for group_name in CA_EXCLUSION_GROUP_NAMES:
            try:
                data = await self._get(
                    f"/groups?$filter=displayName eq '{group_name}'"
                    "&$select=id,displayName"
                )
                groups = data.get("value", [])
                if groups:
                    group_id = groups[0]["id"]
                    members_data = await self._get_all_pages(
                        f"/groups/{group_id}/members?$select=id"
                    )
                    member_ids = {m.get("id") for m in members_data}
                    return {
                        "exists": True,
                        "group_name": group_name,
                        "group_id": group_id,
                        "member_count": len(member_ids),
                        "member_ids": member_ids,
                    }
            except Exception:
                continue

        return {"exists": False, "member_count": 0, "member_ids": set()}

    async def _get_global_admin_member_ids(self) -> set[str]:
        """Get all users assigned to the Global Administrator role."""
        try:
            assignments = await self._get_all_pages(
                f"/roleManagement/directory/roleAssignments"
                f"?$filter=roleDefinitionId eq '{GLOBAL_ADMIN_TEMPLATE_ID}'"
            )
            return {a.get("principalId", "") for a in assignments}
        except Exception:
            return set()

    async def _check_mfa_registered(self, user_id: str) -> bool:
        """Check if a user has any MFA methods registered."""
        try:
            data = await self._get(
                f"/users/{user_id}/authentication/methods"
            )
            methods = data.get("value", [])
            # Filter out password-only — check for real MFA methods
            mfa_types = {
                "#microsoft.graph.phoneAuthenticationMethod",
                "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod",
                "#microsoft.graph.fido2AuthenticationMethod",
                "#microsoft.graph.softwareOathAuthenticationMethod",
            }
            return any(m.get("@odata.type") in mfa_types for m in methods)
        except Exception:
            return False

    async def _check_risk_level(self, user_id: str) -> str:
        """Get the user's risk level from Identity Protection."""
        try:
            data = await self._get(f"/identityProtection/riskyUsers/{user_id}")
            return data.get("riskLevel", "none")
        except Exception:
            return "none"
