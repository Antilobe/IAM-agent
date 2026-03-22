"""Tests for identity scorer."""

from __future__ import annotations

import pytest

from identity_agent.analyse.scorer import Scorer
from identity_agent.models.assessment import CAPolicyResult, CAPolicyStatus
from identity_agent.models.signals import (
    AppGovernanceSignals,
    GuestSignals,
    IdentitySignals,
    MFASignals,
    PrivilegedAccessSignals,
    RiskSignals,
)


def _make_ca(status: CAPolicyStatus, name: str = "Policy") -> CAPolicyResult:
    return CAPolicyResult(
        catalogue_id="CA-X", catalogue_name=name, status=status, match_confidence=1.0,
    )


class TestScorer:
    def test_perfect_score(self) -> None:
        signals = IdentitySignals(
            mfa=MFASignals(total_users=100, mfa_registered=100, mfa_capable=100),
            privileged_access=PrivilegedAccessSignals(permanent_global_admins=2, pim_enabled=True),
            risk=RiskSignals(sign_in_risk_policies_enabled=1, user_risk_policies_enabled=1),
            app_governance=AppGovernanceSignals(),
            guest=GuestSignals(access_reviews_configured=True, guest_invite_policy="adminsOnly"),
        )
        ca_results = [
            _make_ca(CAPolicyStatus.ENFORCED, "Require MFA for All Users"),
            _make_ca(CAPolicyStatus.ENFORCED, "Require Phishing-Resistant MFA"),
        ]
        score, breakdown = Scorer().score(signals, [], ca_results)
        assert score >= 90
        assert breakdown.ca_policy_score == 100.0
        assert breakdown.mfa_score == 100.0  # 100% + phishing bonus, capped

    def test_worst_case(self) -> None:
        signals = IdentitySignals(
            mfa=MFASignals(total_users=100, mfa_registered=0),
            privileged_access=PrivilegedAccessSignals(permanent_global_admins=10, pim_enabled=False),
            risk=RiskSignals(risky_users_high=5, risky_users_medium=5),
            app_governance=AppGovernanceSignals(total_app_registrations=10, apps_with_expiring_secrets=10, apps_with_no_owner=10),
            guest=GuestSignals(total_guests=10, guests_last_sign_in_over_90d=10, guest_invite_policy="everyone"),
        )
        score, _ = Scorer().score(signals, [], [])
        assert score < 20

    def test_ca_scoring_report_only(self) -> None:
        ca_results = [
            _make_ca(CAPolicyStatus.ENFORCED),
            _make_ca(CAPolicyStatus.REPORT_ONLY),
            _make_ca(CAPolicyStatus.MISSING),
        ]
        scorer = Scorer()
        _, breakdown = scorer.score(IdentitySignals(), [], ca_results)
        # (1.0 + 0.3 + 0.0) / 3 * 100 = 43.3
        assert breakdown.ca_policy_score == pytest.approx(43.3, abs=0.1)

    def test_mfa_penalty_no_policy(self) -> None:
        signals = IdentitySignals(mfa=MFASignals(total_users=100, mfa_registered=80))
        _, breakdown = Scorer().score(signals, [], [])
        # 80% - 20 penalty = 60
        assert breakdown.mfa_score == 60.0

    def test_privileged_access_pim_cap(self) -> None:
        signals = IdentitySignals(
            privileged_access=PrivilegedAccessSignals(permanent_global_admins=2, pim_enabled=False),
        )
        _, breakdown = Scorer().score(signals, [], [])
        assert breakdown.privileged_access_score <= 50

    def test_custom_weights(self) -> None:
        weights = {"ca_policy": 1.0, "mfa": 0.0, "privileged_access": 0.0, "risk_posture": 0.0, "app_governance": 0.0, "guest": 0.0}
        ca_results = [_make_ca(CAPolicyStatus.ENFORCED)]
        score, _ = Scorer(weights=weights).score(IdentitySignals(), [], ca_results)
        assert score == 100.0

    def test_risk_deductions(self) -> None:
        signals = IdentitySignals(
            risk=RiskSignals(risky_users_high=3, risky_users_medium=2),
        )
        _, breakdown = Scorer().score(signals, [], [])
        # 100 - 30 (high) - 10 (medium) - 20 (no sign-in risk) - 20 (no user risk) = 20
        assert breakdown.risk_posture_score == 20.0
