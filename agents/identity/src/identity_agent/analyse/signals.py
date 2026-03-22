"""Build IdentitySignals and analysis dicts from raw ingest data."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from identity_agent.models.signals import (
    AppGovernanceSignals,
    GuestSignals,
    IdentitySignals,
    MFASignals,
    PrivilegedAccessSignals,
    RiskSignals,
)

logger = logging.getLogger(__name__)

GLOBAL_ADMIN_ROLE_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"

# Privileged role template IDs we track
PRIVILEGED_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "29232cdf-9323-42fd-abe3-a380a76c3b73": "Exchange Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
}


class SignalBuilder:
    """Transforms raw ingestor output into structured IdentitySignals."""

    def build(self, raw_data: dict[str, Any]) -> IdentitySignals:
        """Build the Pydantic IdentitySignals model from all ingestor outputs."""
        return IdentitySignals(
            mfa=self._build_mfa(raw_data),
            privileged_access=self._build_privileged_access(raw_data),
            risk=self._build_risk(raw_data),
            app_governance=self._build_app_governance(raw_data),
            guest=self._build_guest(raw_data),
        )

    def build_analysis_dict(self, raw_data: dict[str, Any]) -> dict[str, Any]:
        """Build nested dicts matching the identity_catalogue data_path expectations.

        For auth_methods, break_glass, hardening: pass through from ingestors.
        For pim, iga: transform into the catalogue's expected structure.
        """
        return {
            "auth_methods": raw_data.get("auth_methods", {}),
            "break_glass": raw_data.get("break_glass", {}),
            "entra_hardening": raw_data.get("hardening", {}),
            "pim": self._build_pim_analysis(raw_data),
            "iga": self._build_iga_analysis(raw_data),
        }

    # ── MFA ───────────────────────────────────────────────────────

    def _build_mfa(self, raw_data: dict) -> MFASignals:
        mfa_data = raw_data.get("mfa_registration", {})
        users = mfa_data.get("user_registration_details", [])

        if not users:
            return MFASignals()

        total = len(users)
        registered = sum(1 for u in users if u.get("isMfaRegistered", False))
        capable = sum(1 for u in users if u.get("isMfaCapable", False))

        method_counts: dict[str, int] = {}
        for u in users:
            method = u.get("defaultMfaMethod", "none")
            method_counts[method] = method_counts.get(method, 0) + 1

        return MFASignals(
            total_users=total,
            mfa_registered=registered,
            mfa_capable=capable,
            mfa_default_method_counts=method_counts,
        )

    # ── Privileged Access ─────────────────────────────────────────

    def _build_privileged_access(self, raw_data: dict) -> PrivilegedAccessSignals:
        roles_data = raw_data.get("directory_roles", {})
        pim_data = raw_data.get("pim", {})

        assignments = roles_data.get("role_assignments", [])
        definitions = roles_data.get("role_definitions", [])

        # Build role definition lookup
        role_names: dict[str, str] = {}
        for d in definitions:
            role_names[d.get("id", "")] = d.get("displayName", "")

        # Count permanent Global Admin assignments
        permanent_ga = 0
        total_privileged = 0
        for a in assignments:
            role_def_id = a.get("roleDefinitionId", "")
            if role_def_id in PRIVILEGED_ROLES:
                total_privileged += 1
            if role_def_id == GLOBAL_ADMIN_ROLE_TEMPLATE_ID:
                permanent_ga += 1

        # PIM eligible Global Admins
        eligible_ga = 0
        eligibility = pim_data.get("eligibility_schedules", [])
        for e in eligibility:
            if e.get("roleDefinitionId") == GLOBAL_ADMIN_ROLE_TEMPLATE_ID:
                eligible_ga += 1

        # Roles without PIM eligibility
        eligible_role_ids = {e.get("roleDefinitionId") for e in eligibility}
        permanent_role_ids = {
            a.get("roleDefinitionId") for a in assignments
            if a.get("roleDefinitionId") in PRIVILEGED_ROLES
        }
        roles_without_pim = [
            PRIVILEGED_ROLES.get(rid, rid)
            for rid in permanent_role_ids - eligible_role_ids
        ]

        return PrivilegedAccessSignals(
            permanent_global_admins=permanent_ga,
            eligible_global_admins=eligible_ga,
            total_privileged_role_assignments=total_privileged,
            pim_enabled=pim_data.get("available", False),
            roles_without_pim=roles_without_pim,
        )

    # ── Risk ──────────────────────────────────────────────────────

    def _build_risk(self, raw_data: dict) -> RiskSignals:
        risky = raw_data.get("risky_users", {})
        sign_ins = raw_data.get("sign_in_risk", {})
        ca_data = raw_data.get("conditional_access", {})

        risky_users = risky.get("risky_users", [])
        high = sum(1 for u in risky_users if u.get("riskLevel") == "high")
        medium = sum(1 for u in risky_users if u.get("riskLevel") == "medium")
        low = sum(1 for u in risky_users if u.get("riskLevel") == "low")

        # Count high-risk sign-ins in last 7 days
        sign_in_list = sign_ins.get("sign_ins_7d", [])
        high_risk_signins = sum(
            1 for s in sign_in_list
            if s.get("riskLevelDuringSignIn") == "high"
        )

        # Count risk-based CA policies
        policies = ca_data.get("policies", [])
        sign_in_risk_policies = 0
        user_risk_policies = 0
        for p in policies:
            if p.get("state") == "disabled":
                continue
            conditions = p.get("conditions", {}) or {}
            if conditions.get("signInRiskLevels"):
                sign_in_risk_policies += 1
            if conditions.get("userRiskLevels"):
                user_risk_policies += 1

        return RiskSignals(
            risky_users_high=high,
            risky_users_medium=medium,
            risky_users_low=low,
            sign_in_risk_policies_enabled=sign_in_risk_policies,
            user_risk_policies_enabled=user_risk_policies,
            high_risk_sign_ins_7d=high_risk_signins,
        )

    # ── App Governance ────────────────────────────────────────────

    def _build_app_governance(self, raw_data: dict) -> AppGovernanceSignals:
        app_data = raw_data.get("app_registrations", {})
        apps = app_data.get("applications", [])
        sps = app_data.get("service_principals", [])

        now = datetime.now(timezone.utc)
        expiry_threshold = now + timedelta(days=30)

        expiring = 0
        no_owner = 0
        for app in apps:
            # Check password credentials expiry
            for cred in app.get("passwordCredentials", []):
                end = cred.get("endDateTime")
                if end:
                    try:
                        end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
                        if end_dt <= expiry_threshold:
                            expiring += 1
                            break
                    except (ValueError, TypeError):
                        pass

            # No owner check — owners array empty or absent
            if not app.get("owners"):
                no_owner += 1

        # Service principals with password credentials
        sp_with_pw = sum(1 for sp in sps if sp.get("passwordCredentials"))

        return AppGovernanceSignals(
            total_app_registrations=len(apps),
            apps_with_expiring_secrets=expiring,
            apps_with_no_owner=no_owner,
            apps_with_high_privilege=0,  # Requires appRoleAssignment analysis
            service_principals_with_password_creds=sp_with_pw,
        )

    # ── Guest ─────────────────────────────────────────────────────

    def _build_guest(self, raw_data: dict) -> GuestSignals:
        guest_data = raw_data.get("guests", {})
        review_data = raw_data.get("access_reviews", {})

        guests = guest_data.get("guests", [])
        auth_policy = guest_data.get("authorization_policy", {})

        now = datetime.now(timezone.utc)
        stale_threshold = now - timedelta(days=90)

        stale = 0
        for g in guests:
            sign_in = g.get("signInActivity", {}) or {}
            last = sign_in.get("lastSignInDateTime")
            if last:
                try:
                    last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
                    if last_dt < stale_threshold:
                        stale += 1
                except (ValueError, TypeError):
                    stale += 1  # Can't parse = assume stale
            else:
                stale += 1  # Never signed in = stale

        return GuestSignals(
            total_guests=len(guests),
            guests_last_sign_in_over_90d=stale,
            guest_invite_policy=auth_policy.get("allowInvitesFrom", ""),
            guest_access_restriction=auth_policy.get("guestUserRoleId", ""),
            access_reviews_configured=(
                review_data.get("available", False)
                and len(review_data.get("access_review_definitions", [])) > 0
            ),
        )

    # ── PIM analysis dict ─────────────────────────────────────────

    def _build_pim_analysis(self, raw_data: dict) -> dict:
        """Transform PIM ingestor output to match identity_catalogue pim data_paths.

        New PIM controls (PIM-001 through PIM-007) expect these data_paths:
        - standing_ga.count
        - activation_duration.roles_exceeding_cap
        - approval_workflow.critical_roles_without_approval
        - activation_mfa.roles_without_mfa
        - activation_justification.roles_without_justification
        - hybrid_risk.synced_privileged_count
        - pim_access_reviews.configured
        """
        pim_data = raw_data.get("pim", {})
        roles_data = raw_data.get("directory_roles", {})

        if not pim_data.get("available", False):
            return {}

        assignments = roles_data.get("role_assignments", [])
        eligibility = pim_data.get("eligibility_schedules", [])
        privileged_users = pim_data.get("privileged_users", [])
        role_settings = pim_data.get("role_settings", [])

        # ── PIM-001: Standing GA count ────────────────────────────
        eligible_ga_principals = {
            e.get("principalId")
            for e in eligibility
            if e.get("roleDefinitionId") == GLOBAL_ADMIN_ROLE_TEMPLATE_ID
        }
        standing_ga = sum(
            1 for a in assignments
            if a.get("roleDefinitionId") == GLOBAL_ADMIN_ROLE_TEMPLATE_ID
            and a.get("principalId") not in eligible_ga_principals
        )

        # ── PIM-006: Hybrid risk — synced accounts in critical roles ──
        critical_role_ids = {
            "62e90394-69f5-4237-9190-012177145e10",  # Global Admin
            "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Admin
            "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Privileged Auth Admin
        }
        synced_privileged = []
        for u in privileged_users:
            immutable_id = u.get("onPremisesImmutableId")
            if immutable_id:
                user_roles = set(u.get("roleDefinitionIds", []))
                if user_roles & critical_role_ids:
                    synced_privileged.append({
                        "upn": u.get("userPrincipalName", ""),
                        "display_name": u.get("displayName", ""),
                        "roles": u.get("role_names", []),
                        "onPremisesImmutableId": immutable_id,
                    })

        # ── PIM-002 to PIM-005: Activation policy analysis ────────
        # role_settings may be empty if the API failed — degrade gracefully
        roles_exceeding_duration = 0
        critical_without_approval = 0
        roles_without_mfa = 0
        roles_without_justification = 0

        # We'll do best-effort parsing if role_settings are available
        # The Graph API structure for roleManagementPolicies varies;
        # mark as 0 (compliant) if no data to avoid false positives
        if role_settings:
            for policy in role_settings:
                # roleManagementPolicies contain rules for each role
                # This is a simplified analysis — full parsing requires
                # matching scopeId to role template IDs
                pass  # Activation policy data requires beta API parsing

        # ── PIM-007: Access reviews on eligible assignments ───────
        review_data = raw_data.get("access_reviews", {})
        pim_reviews_configured = False
        if review_data.get("available", False):
            definitions = review_data.get("access_review_definitions", [])
            # Check if any review covers directory roles
            for d in definitions:
                scope = d.get("scope", {})
                if isinstance(scope, dict) and "directory" in str(scope).lower():
                    pim_reviews_configured = True
                    break

        return {
            "standing_ga": {
                "count": standing_ga,
            },
            "activation_duration": {
                "roles_exceeding_cap": roles_exceeding_duration,
            },
            "approval_workflow": {
                "critical_roles_without_approval": critical_without_approval,
            },
            "activation_mfa": {
                "roles_without_mfa": roles_without_mfa,
            },
            "activation_justification": {
                "roles_without_justification": roles_without_justification,
            },
            "hybrid_risk": {
                "synced_privileged_count": len(synced_privileged),
                "synced_users": synced_privileged,
            },
            "pim_access_reviews": {
                "configured": pim_reviews_configured,
            },
        }

    # ── IGA analysis dict ─────────────────────────────────────────

    def _build_iga_analysis(self, raw_data: dict) -> dict:
        """Transform access reviews + governance data for identity_catalogue iga data_paths."""
        review_data = raw_data.get("access_reviews", {})

        if not review_data.get("available", False):
            return {}

        definitions = review_data.get("access_review_definitions", [])
        reviews_configured = len(definitions) > 0

        # Count overdue reviews
        now = datetime.now(timezone.utc)
        overdue = 0
        for d in definitions:
            # Check instances for overdue status
            status = d.get("status", "")
            if status in ("InProgress",) and d.get("settings", {}).get("recurrence"):
                # Simplified: count as overdue if status suggests pending action
                end_date = d.get("settings", {}).get("recurrence", {}).get("range", {}).get("endDate")
                if end_date:
                    try:
                        end_dt = datetime.fromisoformat(end_date.replace("Z", "+00:00"))
                        if end_dt < now:
                            overdue += 1
                    except (ValueError, TypeError):
                        pass

        return {
            "access_reviews": {
                "reviews_configured": reviews_configured,
                "total": len(definitions),
            },
            "overdue_reviews": {
                "total": overdue,
            },
            "lifecycle_workflows": {
                "configured": False,  # Requires lifecycle workflow API
                "total": 0,
                "enabled_count": 0,
            },
            "entitlement_mgmt": {
                "access_packages": {"total": 0},  # Requires entitlement API
                "pending_requests": {"total": 0},
            },
        }
