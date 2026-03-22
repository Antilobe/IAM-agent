"""Draft PIM role settings for missing or misconfigured PIM controls.

Generates deployable Graph API JSON for PIM role management policies.
Follows the same pattern as ca_drafter.py — always produces a draft
for operator review, never auto-deploys.
"""

from __future__ import annotations

import logging
from typing import Any

from identity_agent.models.gaps import IdentityGap

logger = logging.getLogger(__name__)

# Role template IDs by tier
CRITICAL_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
}

OPERATIONAL_ROLES = {
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


class PIMDrafter:
    """Generates draft PIM role settings for operator review."""

    def draft(self, gap: IdentityGap) -> dict | None:
        """Generate PIM role settings drafts based on the gap.

        Returns a dict containing per-role drafts and any required operator input.
        Returns None if the gap isn't PIM-related.
        """
        catalogue_ref = gap.catalogue_ref
        if not catalogue_ref or not catalogue_ref.startswith("PIM-"):
            return None

        if catalogue_ref == "PIM-001":
            return self._draft_standing_ga_remediation()
        if catalogue_ref == "PIM-002":
            return self._draft_activation_duration()
        if catalogue_ref == "PIM-003":
            return self._draft_approval_workflow()
        if catalogue_ref == "PIM-004":
            return self._draft_mfa_on_activation()
        if catalogue_ref == "PIM-005":
            return self._draft_justification()
        if catalogue_ref == "PIM-006":
            return self._draft_hybrid_remediation(gap)
        if catalogue_ref == "PIM-007":
            return self._draft_access_reviews()

        return None

    def get_required_operator_input(self, gap: IdentityGap) -> dict | None:
        """Return required_operator_input for gaps that need approver UPNs."""
        if gap.catalogue_ref == "PIM-003":
            return {
                "field": "approvers",
                "prompt": (
                    "Provide at least 2 approver UPNs for Global Admin activation. "
                    "One should be a break-glass account owner."
                ),
                "example": ["admin1@contoso.com", "admin2@contoso.com"],
            }
        return None

    def _draft_standing_ga_remediation(self) -> dict:
        """PIM-001: Convert standing GA to eligible assignments."""
        return {
            "description": "Convert all standing Global Admin assignments to PIM-eligible. Only break-glass accounts may retain permanent assignment.",
            "roles": [
                self._role_settings(
                    role_id="62e90394-69f5-4237-9190-012177145e10",
                    role_name="Global Administrator",
                    tier="critical",
                ),
            ],
            "steps": [
                "1. Navigate to Entra ID > Privileged Identity Management > Entra ID roles",
                "2. Select 'Global Administrator' role",
                "3. Under 'Assignments', identify all permanent (Active) assignments",
                "4. Remove permanent assignments (except documented break-glass accounts)",
                "5. Add PIM-eligible assignments for each user with 8-hour max duration",
            ],
        }

    def _draft_activation_duration(self) -> dict:
        """PIM-002: Cap activation duration by role tier."""
        roles = []
        for role_id, role_name in CRITICAL_ROLES.items():
            roles.append(self._role_settings(role_id, role_name, "critical"))
        for role_id, role_name in OPERATIONAL_ROLES.items():
            roles.append(self._role_settings(role_id, role_name, "operational"))
        return {
            "description": "Cap activation duration: critical roles (GA, PRA, PAA) at 4 hours, operational roles at 8 hours.",
            "roles": roles,
        }

    def _draft_approval_workflow(self) -> dict:
        """PIM-003: Approval for critical roles only."""
        roles = []
        for role_id, role_name in CRITICAL_ROLES.items():
            settings = self._role_settings(role_id, role_name, "critical")
            settings["requires_approval"] = True
            settings["approvers"] = ["APPROVER_UPN_1", "APPROVER_UPN_2"]
            roles.append(settings)
        return {
            "description": "Enable approval workflow for Global Admin, Privileged Role Admin, and Privileged Authentication Admin. Operational roles require MFA + justification only.",
            "roles": roles,
        }

    def _draft_mfa_on_activation(self) -> dict:
        """PIM-004: MFA on every activation, phishing-resistant for critical."""
        roles = []
        for role_id, role_name in CRITICAL_ROLES.items():
            settings = self._role_settings(role_id, role_name, "critical")
            settings["requires_phishing_resistant_mfa"] = True
            roles.append(settings)
        for role_id, role_name in OPERATIONAL_ROLES.items():
            settings = self._role_settings(role_id, role_name, "operational")
            settings["requires_phishing_resistant_mfa"] = False
            roles.append(settings)
        return {
            "description": "Require MFA re-authentication on every activation. Phishing-resistant MFA (FIDO2/WHfB) required for critical roles.",
            "roles": roles,
        }

    def _draft_justification(self) -> dict:
        """PIM-005: Justification on every activation."""
        return {
            "description": "Require written justification on every PIM activation for audit trail compliance.",
            "applies_to": "All PIM-eligible roles",
            "graph_api_payload": {
                "rules": [
                    {
                        "ruleType": "RoleManagementPolicyEnablementRule",
                        "id": "Enablement_EndUser_Assignment",
                        "enabledRules": ["Justification"],
                    }
                ],
            },
        }

    def _draft_hybrid_remediation(self, gap: IdentityGap) -> dict:
        """PIM-006: Remediate synced accounts in critical roles."""
        synced_users = gap.evidence.get("synced_users", [])
        return {
            "description": "Remove synced (on-prem) accounts from critical Entra roles. Create cloud-only replacement accounts.",
            "affected_users": synced_users,
            "steps": [
                "1. For each synced account listed below, create a cloud-only replacement account",
                "2. Assign the cloud-only account as PIM-eligible for the same role",
                "3. Remove the synced account from the privileged role",
                "4. Document the migration in your change management system",
            ],
        }

    def _draft_access_reviews(self) -> dict:
        """PIM-007: Configure access reviews on eligible assignments."""
        return {
            "description": "Configure recurring access reviews on PIM eligible assignments. Critical roles quarterly, operational roles semi-annually.",
            "steps": [
                "1. Navigate to Identity Governance > Access reviews",
                "2. Create review for 'Privileged roles' scope",
                "3. Set recurrence: quarterly for Global Admin/PRA/PAA, semi-annual for others",
                "4. Reviewers: role owners or security team",
                "5. Enable auto-apply for denied reviews",
            ],
        }

    def _role_settings(self, role_id: str, role_name: str, tier: str) -> dict:
        """Generate standard role settings for a given tier."""
        max_hours = 4 if tier == "critical" else 8
        return {
            "role_name": role_name,
            "role_template_id": role_id,
            "tier": tier,
            "requires_approval": tier == "critical",
            "approvers": (
                ["APPROVER_UPN_1", "APPROVER_UPN_2"] if tier == "critical" else []
            ),
            "activation_duration_hours": max_hours,
            "requires_mfa": True,
            "requires_phishing_resistant_mfa": tier == "critical",
            "requires_justification": True,
            "graph_api_payload": {
                "rules": [
                    {
                        "ruleType": "RoleManagementPolicyExpirationRule",
                        "id": "Expiration_EndUser_Assignment",
                        "isExpirationRequired": True,
                        "maximumDuration": f"PT{max_hours}H",
                    },
                    {
                        "ruleType": "RoleManagementPolicyEnablementRule",
                        "id": "Enablement_EndUser_Assignment",
                        "enabledRules": [
                            "MultiFactorAuthentication",
                            "Justification",
                        ] + (["Ticketing"] if tier == "critical" else []),
                    },
                    {
                        "ruleType": "RoleManagementPolicyApprovalRule",
                        "id": "Approval_EndUser_Assignment",
                        "setting": {
                            "isApprovalRequired": tier == "critical",
                            "approvalStages": [
                                {
                                    "approvalStageTimeOutInDays": 1,
                                    "isApproverJustificationRequired": True,
                                    "primaryApprovers": [
                                        {
                                            "@odata.type": "#microsoft.graph.singleUser",
                                            "userId": "APPROVER_UPN_1",
                                        },
                                        {
                                            "@odata.type": "#microsoft.graph.singleUser",
                                            "userId": "APPROVER_UPN_2",
                                        },
                                    ] if tier == "critical" else [],
                                }
                            ] if tier == "critical" else [],
                        },
                    },
                ],
            },
        }
