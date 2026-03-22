"""Ingestor: Privileged Identity Management (requires P2 — degrades gracefully).

Collects PIM eligibility, assignment schedules, role management policies,
and enriches privileged users with onPremisesImmutableId for hybrid detection.
"""

from __future__ import annotations

import logging
from typing import Any

from identity_agent.ingest.base import BaseIngestor

logger = logging.getLogger(__name__)

# Critical roles requiring approval + phishing-resistant MFA
CRITICAL_ROLE_TEMPLATE_IDS = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
}

# Operational roles — MFA + justification, no approval needed
OPERATIONAL_ROLE_TEMPLATE_IDS = {
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "29232cdf-9323-42fd-abe3-a380a76c3b73": "Exchange Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "cf1c38e5-3621-4004-a7cb-879624dced7c": "Cloud Application Administrator",
    "17315797-102d-40b4-93e0-432062caca18": "Compliance Administrator",
    "44367163-eba1-44c3-98af-f5787879f96a": "Intune Administrator",
}

ALL_PRIVILEGED_ROLES = {**CRITICAL_ROLE_TEMPLATE_IDS, **OPERATIONAL_ROLE_TEMPLATE_IDS}

# Max activation duration in hours by tier
MAX_DURATION_HOURS = {
    "critical": 4,
    "operational": 8,
}


class PIMIngestor(BaseIngestor):
    async def ingest(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "eligibility_schedules": [],
            "assignment_schedules": [],
            "role_settings": [],
            "privileged_users": [],
            "available": False,
        }

        # Eligibility schedules
        try:
            result["eligibility_schedules"] = await self._get_all_pages(
                "/roleManagement/directory/roleEligibilityScheduleInstances"
            )
        except Exception as exc:
            self._warn("Eligibility schedules", exc)

        # Assignment schedules (active PIM assignments)
        try:
            result["assignment_schedules"] = await self._get_all_pages(
                "/roleManagement/directory/roleAssignmentScheduleInstances"
            )
        except Exception as exc:
            self._warn("Assignment schedules", exc)

        # Role management policies (activation settings)
        try:
            result["role_settings"] = await self._get_all_pages(
                "/policies/roleManagementPolicies"
            )
        except Exception as exc:
            # Try beta if v1.0 fails
            try:
                result["role_settings"] = await self._get_all_pages(
                    "/policies/roleManagementPolicies", beta=True
                )
            except Exception as exc2:
                self._warn("Role management policies", exc2)

        # Mark available if we got at least eligibility or assignment data
        if result["eligibility_schedules"] or result["assignment_schedules"]:
            result["available"] = True

        # Enrich privileged users with onPremisesImmutableId for hybrid detection
        result["privileged_users"] = await self._get_privileged_users()

        return result

    async def _get_privileged_users(self) -> list[dict[str, Any]]:
        """Fetch privileged role holders with immutableId for hybrid detection (PIM-006)."""
        users: list[dict[str, Any]] = []
        try:
            role_assignments = await self._get_all_pages(
                "/roleManagement/directory/roleAssignments"
            )

            # Collect unique principal IDs in privileged roles
            privileged_principal_ids: dict[str, list[str]] = {}
            for a in role_assignments:
                role_id = a.get("roleDefinitionId", "")
                principal_id = a.get("principalId", "")
                if role_id in ALL_PRIVILEGED_ROLES and principal_id:
                    if principal_id not in privileged_principal_ids:
                        privileged_principal_ids[principal_id] = []
                    privileged_principal_ids[principal_id].append(role_id)

            # Fetch user details with immutableId
            for principal_id, role_ids in privileged_principal_ids.items():
                try:
                    user_data = await self._get(
                        f"/users/{principal_id}"
                        "?$select=id,displayName,userPrincipalName,"
                        "onPremisesImmutableId,onPremisesSyncEnabled,userType"
                    )
                    if user_data and user_data.get("id"):
                        users.append({
                            "id": user_data.get("id"),
                            "displayName": user_data.get("displayName"),
                            "userPrincipalName": user_data.get("userPrincipalName"),
                            "onPremisesImmutableId": user_data.get("onPremisesImmutableId"),
                            "onPremisesSyncEnabled": user_data.get("onPremisesSyncEnabled", False),
                            "roleDefinitionIds": role_ids,
                            "role_names": [
                                ALL_PRIVILEGED_ROLES.get(rid, rid) for rid in role_ids
                            ],
                        })
                except Exception:
                    continue  # Skip individual user fetch failures

        except Exception as exc:
            self._warn("Privileged users enrichment", exc)

        return users

    def _warn(self, component: str, exc: Exception) -> None:
        msg = f"PIM {component} fetch failed: {exc}"
        logger.warning(msg)
        self.errors.append(msg)
