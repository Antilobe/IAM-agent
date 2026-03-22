"""Signals collected during the ingest phase."""

from __future__ import annotations

from pydantic import BaseModel, Field


class MFASignals(BaseModel):
    total_users: int = 0
    mfa_registered: int = 0
    mfa_capable: int = 0
    mfa_default_method_counts: dict[str, int] = Field(default_factory=dict)

    @property
    def registration_rate(self) -> float:
        return self.mfa_registered / self.total_users if self.total_users else 0.0


class PrivilegedAccessSignals(BaseModel):
    permanent_global_admins: int = 0
    eligible_global_admins: int = 0
    total_privileged_role_assignments: int = 0
    pim_enabled: bool = False
    roles_without_pim: list[str] = Field(default_factory=list)


class RiskSignals(BaseModel):
    risky_users_high: int = 0
    risky_users_medium: int = 0
    risky_users_low: int = 0
    sign_in_risk_policies_enabled: int = 0
    user_risk_policies_enabled: int = 0
    high_risk_sign_ins_7d: int = 0


class AppGovernanceSignals(BaseModel):
    total_app_registrations: int = 0
    apps_with_expiring_secrets: int = 0
    apps_with_no_owner: int = 0
    apps_with_high_privilege: int = 0
    service_principals_with_password_creds: int = 0


class GuestSignals(BaseModel):
    total_guests: int = 0
    guests_last_sign_in_over_90d: int = 0
    guest_invite_policy: str = ""
    guest_access_restriction: str = ""
    access_reviews_configured: bool = False


class IdentitySignals(BaseModel):
    """Aggregated signals from all ingestors — used by analysis and recommendation layers."""

    mfa: MFASignals = Field(default_factory=MFASignals)
    privileged_access: PrivilegedAccessSignals = Field(default_factory=PrivilegedAccessSignals)
    risk: RiskSignals = Field(default_factory=RiskSignals)
    app_governance: AppGovernanceSignals = Field(default_factory=AppGovernanceSignals)
    guest: GuestSignals = Field(default_factory=GuestSignals)

    # Raw CA policy data is stored separately in CAPolicyResult list,
    # not duplicated here.
