"""Identity score calculation from signals, gaps, and CA results."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from identity_agent.models.assessment import CAPolicyResult, CAPolicyStatus, ScoringBreakdown
from identity_agent.models.gaps import IdentityGap
from identity_agent.models.signals import IdentitySignals

logger = logging.getLogger(__name__)

DEFAULT_WEIGHTS = {
    "ca_policy": 0.30,
    "mfa": 0.25,
    "privileged_access": 0.20,
    "risk_posture": 0.10,
    "app_governance": 0.10,
    "guest": 0.05,
}

DEFAULT_CA_WEIGHTS = {
    "enforced_weight": 1.0,
    "report_only_weight": 0.3,
    "disabled_weight": 0.0,
    "missing_weight": 0.0,
}


class Scorer:
    """Computes the 0-100 identity score with per-domain breakdown."""

    def __init__(self, weights: dict[str, float] | None = None, config_path: Path | None = None) -> None:
        if weights:
            self._weights = weights
        elif config_path and config_path.exists():
            with open(config_path) as f:
                data = yaml.safe_load(f) or {}
            self._weights = data.get("weights", DEFAULT_WEIGHTS)
            self._ca_weights = data.get("ca_policy", DEFAULT_CA_WEIGHTS)
        else:
            self._weights = DEFAULT_WEIGHTS
            self._ca_weights = DEFAULT_CA_WEIGHTS

        if not hasattr(self, "_ca_weights"):
            self._ca_weights = DEFAULT_CA_WEIGHTS

    def score(
        self,
        signals: IdentitySignals,
        gaps: list[IdentityGap],
        ca_results: list[CAPolicyResult],
        layer_coverages: dict[str, float] | None = None,
    ) -> tuple[float, ScoringBreakdown]:
        """Compute overall identity score and per-domain breakdown."""
        ca = self._score_ca(ca_results)
        mfa = self._score_mfa(signals, ca_results)
        priv = self._score_privileged_access(signals)
        risk = self._score_risk(signals)
        app = self._score_app_governance(signals)
        guest = self._score_guest(signals)

        breakdown = ScoringBreakdown(
            ca_policy_score=ca,
            mfa_score=mfa,
            privileged_access_score=priv,
            risk_posture_score=risk,
            app_governance_score=app,
            guest_score=guest,
        )

        overall = (
            ca * self._weights.get("ca_policy", 0.30)
            + mfa * self._weights.get("mfa", 0.25)
            + priv * self._weights.get("privileged_access", 0.20)
            + risk * self._weights.get("risk_posture", 0.10)
            + app * self._weights.get("app_governance", 0.10)
            + guest * self._weights.get("guest", 0.05)
        )

        return round(min(max(overall, 0), 100), 1), breakdown

    def _score_ca(self, ca_results: list[CAPolicyResult]) -> float:
        if not ca_results:
            return 0.0

        total = len(ca_results)
        weighted_sum = 0.0
        for r in ca_results:
            if r.status == CAPolicyStatus.ENFORCED:
                weighted_sum += self._ca_weights.get("enforced_weight", 1.0)
            elif r.status == CAPolicyStatus.REPORT_ONLY:
                weighted_sum += self._ca_weights.get("report_only_weight", 0.3)
            elif r.status == CAPolicyStatus.DISABLED:
                weighted_sum += self._ca_weights.get("disabled_weight", 0.0)
            # MISSING = 0

        return min(round(weighted_sum / total * 100, 1), 100)

    def _score_mfa(self, signals: IdentitySignals, ca_results: list[CAPolicyResult]) -> float:
        base = signals.mfa.registration_rate * 100

        # Penalty if no MFA-requiring CA policy is enforced
        has_mfa_policy = any(
            r.status == CAPolicyStatus.ENFORCED
            and "mfa" in r.catalogue_name.lower()
            for r in ca_results
        )
        if not has_mfa_policy and signals.mfa.total_users > 0:
            base -= 20

        # Bonus for phishing-resistant MFA for admins
        has_pr_mfa = any(
            r.status == CAPolicyStatus.ENFORCED
            and "phishing" in r.catalogue_name.lower()
            for r in ca_results
        )
        if has_pr_mfa:
            base += 10

        return min(max(round(base, 1), 0), 100)

    def _score_privileged_access(self, signals: IdentitySignals) -> float:
        score = 100.0

        # Deduct for permanent GAs beyond break-glass (assume 2)
        excess_ga = max(signals.privileged_access.permanent_global_admins - 2, 0)
        score -= excess_ga * 20

        # Deduct per role without PIM
        score -= len(signals.privileged_access.roles_without_pim) * 5

        # Cap if PIM not enabled
        if not signals.privileged_access.pim_enabled:
            score = min(score, 50)

        return min(max(round(score, 1), 0), 100)

    def _score_risk(self, signals: IdentitySignals) -> float:
        score = 100.0

        score -= signals.risk.risky_users_high * 10
        score -= signals.risk.risky_users_medium * 5

        if signals.risk.sign_in_risk_policies_enabled == 0:
            score -= 20
        if signals.risk.user_risk_policies_enabled == 0:
            score -= 20

        return min(max(round(score, 1), 0), 100)

    def _score_app_governance(self, signals: IdentitySignals) -> float:
        score = 100.0
        total = signals.app_governance.total_app_registrations

        if total > 0:
            expiring_pct = signals.app_governance.apps_with_expiring_secrets / total
            score -= expiring_pct * 30

            no_owner_pct = signals.app_governance.apps_with_no_owner / total
            score -= no_owner_pct * 20

        score -= min(signals.app_governance.service_principals_with_password_creds * 5, 30)

        return min(max(round(score, 1), 0), 100)

    def _score_guest(self, signals: IdentitySignals) -> float:
        score = 100.0

        if signals.guest.total_guests > 0:
            stale_pct = signals.guest.guests_last_sign_in_over_90d / signals.guest.total_guests
            score -= stale_pct * 30

        # Permissive invite policy
        if signals.guest.guest_invite_policy in ("everyone", ""):
            score -= 20

        if not signals.guest.access_reviews_configured:
            score -= 20

        return min(max(round(score, 1), 0), 100)
