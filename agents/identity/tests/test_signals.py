"""Tests for SignalBuilder: raw ingestor data → IdentitySignals."""

from __future__ import annotations

import pytest

from identity_agent.analyse.signals import SignalBuilder


@pytest.fixture
def raw_data() -> dict:
    """Fully populated mock ingestor output."""
    return {
        "mfa_registration": {
            "user_registration_details": [
                {"userPrincipalName": "alice@contoso.com", "isMfaRegistered": True, "isMfaCapable": True, "defaultMfaMethod": "microsoftAuthenticator"},
                {"userPrincipalName": "bob@contoso.com", "isMfaRegistered": True, "isMfaCapable": True, "defaultMfaMethod": "fido2"},
                {"userPrincipalName": "charlie@contoso.com", "isMfaRegistered": False, "isMfaCapable": False, "defaultMfaMethod": "none"},
            ],
        },
        "directory_roles": {
            "role_assignments": [
                {"roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10", "principalId": "user-1"},  # GA
                {"roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10", "principalId": "user-2"},  # GA
                {"roleDefinitionId": "194ae4cb-b126-40b2-bd5b-6091b380977d", "principalId": "user-3"},  # Security Admin
            ],
            "role_definitions": [
                {"id": "62e90394-69f5-4237-9190-012177145e10", "displayName": "Global Administrator"},
                {"id": "194ae4cb-b126-40b2-bd5b-6091b380977d", "displayName": "Security Administrator"},
            ],
        },
        "pim": {
            "available": True,
            "eligibility_schedules": [
                {"roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10", "principalId": "user-1"},
            ],
            "assignment_schedules": [],
            "role_settings": [],
        },
        "risky_users": {
            "risky_users": [
                {"riskLevel": "high", "userPrincipalName": "risk1@contoso.com"},
                {"riskLevel": "medium", "userPrincipalName": "risk2@contoso.com"},
                {"riskLevel": "low", "userPrincipalName": "risk3@contoso.com"},
            ],
            "available": True,
        },
        "sign_in_risk": {
            "sign_ins_7d": [
                {"riskLevelDuringSignIn": "high"},
                {"riskLevelDuringSignIn": "none"},
                {"riskLevelDuringSignIn": "high"},
            ],
        },
        "conditional_access": {
            "policies": [
                {"displayName": "Block high risk", "state": "enabled", "conditions": {"signInRiskLevels": ["high"]}},
                {"displayName": "Block risky users", "state": "enabled", "conditions": {"userRiskLevels": ["high"]}},
                {"displayName": "Require MFA", "state": "enabled", "conditions": {}},
            ],
            "named_locations": [],
            "authentication_strengths": [],
        },
        "app_registrations": {
            "applications": [
                {"id": "app-1", "passwordCredentials": [{"endDateTime": "2025-01-01T00:00:00Z"}], "owners": [{"id": "u1"}]},
                {"id": "app-2", "passwordCredentials": [], "owners": []},
                {"id": "app-3", "passwordCredentials": [{"endDateTime": "2099-01-01T00:00:00Z"}], "owners": [{"id": "u2"}]},
            ],
            "service_principals": [
                {"id": "sp-1", "passwordCredentials": [{"endDateTime": "2099-01-01T00:00:00Z"}]},
                {"id": "sp-2", "passwordCredentials": []},
            ],
        },
        "guests": {
            "guests": [
                {"id": "g1", "signInActivity": {"lastSignInDateTime": "2020-01-01T00:00:00Z"}},
                {"id": "g2", "signInActivity": {"lastSignInDateTime": "2099-01-01T00:00:00Z"}},
                {"id": "g3", "signInActivity": None},
            ],
            "authorization_policy": {
                "allowInvitesFrom": "adminsAndGuestInviters",
                "guestUserRoleId": "10dae51f-b6af-4016-8d66-8c2a99b929b3",
            },
        },
        "access_reviews": {
            "available": True,
            "access_review_definitions": [
                {"id": "ar-1", "status": "Completed"},
                {"id": "ar-2", "status": "InProgress"},
            ],
        },
        "auth_methods": {
            "enabled_methods": ["microsoftAuthenticator", "fido2"],
            "fido2_enabled": True,
            "passkey_enabled": False,
            "weak_methods_enabled": [],
        },
        "break_glass": {
            "summary": {"accounts_found": 2},
            "accounts": [
                {"enabled": True, "is_cloud_only": True, "has_global_admin": True, "in_ca_exclusion_group": True, "mfa_registered": False, "risk_level": "none"},
                {"enabled": True, "is_cloud_only": True, "has_global_admin": True, "in_ca_exclusion_group": True, "mfa_registered": False, "risk_level": "none"},
            ],
            "ca_exclusion_group": {"exists": True},
        },
        "hardening": {
            "app_registration": {"users_can_register": False},
            "tenant_creation": {"users_can_create": False},
            "admin_consent": {"user_consent_restricted": True},
            "linkedin": {"enabled": False},
            "guest_invite": {"policy": "adminsAndGuestInviters"},
            "portal_access": {"restricted_to_admins": True},
            "security_defaults": {"enabled": False},
            "risk_based_ca": {"verified": True},
        },
    }


class TestBuildSignals:
    def test_mfa_signals(self, raw_data: dict) -> None:
        signals = SignalBuilder().build(raw_data)
        assert signals.mfa.total_users == 3
        assert signals.mfa.mfa_registered == 2
        assert signals.mfa.mfa_capable == 2
        assert signals.mfa.registration_rate == pytest.approx(2 / 3)
        assert signals.mfa.mfa_default_method_counts["microsoftAuthenticator"] == 1
        assert signals.mfa.mfa_default_method_counts["fido2"] == 1

    def test_privileged_access_signals(self, raw_data: dict) -> None:
        signals = SignalBuilder().build(raw_data)
        assert signals.privileged_access.permanent_global_admins == 2
        assert signals.privileged_access.eligible_global_admins == 1
        assert signals.privileged_access.total_privileged_role_assignments == 3
        assert signals.privileged_access.pim_enabled is True

    def test_risk_signals(self, raw_data: dict) -> None:
        signals = SignalBuilder().build(raw_data)
        assert signals.risk.risky_users_high == 1
        assert signals.risk.risky_users_medium == 1
        assert signals.risk.risky_users_low == 1
        assert signals.risk.high_risk_sign_ins_7d == 2
        assert signals.risk.sign_in_risk_policies_enabled == 1
        assert signals.risk.user_risk_policies_enabled == 1

    def test_app_governance_signals(self, raw_data: dict) -> None:
        signals = SignalBuilder().build(raw_data)
        assert signals.app_governance.total_app_registrations == 3
        assert signals.app_governance.apps_with_expiring_secrets == 1  # expired
        assert signals.app_governance.apps_with_no_owner == 1
        assert signals.app_governance.service_principals_with_password_creds == 1

    def test_guest_signals(self, raw_data: dict) -> None:
        signals = SignalBuilder().build(raw_data)
        assert signals.guest.total_guests == 3
        assert signals.guest.guests_last_sign_in_over_90d == 2  # 2020 date + no activity
        assert signals.guest.guest_invite_policy == "adminsAndGuestInviters"
        assert signals.guest.access_reviews_configured is True

    def test_empty_data(self) -> None:
        signals = SignalBuilder().build({})
        assert signals.mfa.total_users == 0
        assert signals.risk.risky_users_high == 0
        assert signals.guest.total_guests == 0


class TestBuildAnalysisDict:
    def test_auth_methods_passthrough(self, raw_data: dict) -> None:
        ad = SignalBuilder().build_analysis_dict(raw_data)
        assert ad["auth_methods"]["fido2_enabled"] is True
        assert "microsoftAuthenticator" in ad["auth_methods"]["enabled_methods"]

    def test_break_glass_passthrough(self, raw_data: dict) -> None:
        ad = SignalBuilder().build_analysis_dict(raw_data)
        assert ad["break_glass"]["summary"]["accounts_found"] == 2
        assert ad["break_glass"]["ca_exclusion_group"]["exists"] is True

    def test_entra_hardening_passthrough(self, raw_data: dict) -> None:
        ad = SignalBuilder().build_analysis_dict(raw_data)
        assert ad["entra_hardening"]["app_registration"]["users_can_register"] is False
        assert ad["entra_hardening"]["risk_based_ca"]["verified"] is True

    def test_pim_transformation(self, raw_data: dict) -> None:
        ad = SignalBuilder().build_analysis_dict(raw_data)
        pim = ad["pim"]
        assert "standing_ga" in pim
        # user-2 is permanent GA without PIM eligibility
        assert pim["standing_ga"]["count"] == 1
        assert pim["hybrid_risk"]["synced_privileged_count"] == 0
        assert "activation_mfa" in pim

    def test_iga_transformation(self, raw_data: dict) -> None:
        ad = SignalBuilder().build_analysis_dict(raw_data)
        iga = ad["iga"]
        assert iga["access_reviews"]["reviews_configured"] is True
        assert iga["access_reviews"]["total"] == 2

    def test_empty_pim(self) -> None:
        ad = SignalBuilder().build_analysis_dict({"pim": {"available": False}})
        assert ad["pim"] == {}
