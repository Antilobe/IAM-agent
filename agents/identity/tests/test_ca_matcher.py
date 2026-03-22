"""Tests for CA policy matching (Engine 1)."""

from __future__ import annotations

from pathlib import Path

import pytest

from identity_agent.analyse.ca_matcher import CAMatcher
from identity_agent.models.assessment import CAPolicyStatus
from identity_agent.models.signals import IdentitySignals, MFASignals, GuestSignals

CATALOGUE_DIR = Path(__file__).parent.parent / "catalogues"


@pytest.fixture
def matcher() -> CAMatcher:
    return CAMatcher(catalogue_dir=CATALOGUE_DIR, target_ig="IG1")


@pytest.fixture
def signals() -> IdentitySignals:
    return IdentitySignals(
        mfa=MFASignals(total_users=100, mfa_registered=80),
        guest=GuestSignals(total_guests=5),
    )


class TestCAMatcher:
    def test_exact_name_match(self, matcher: CAMatcher, signals: IdentitySignals) -> None:
        tenant_policies = [
            {"displayName": "CAP001-All-BlockLegacyAuthentication-v1.0", "state": "enabled"},
        ]
        results = matcher.match(tenant_policies, signals)
        cap001 = next(r for r in results if r.catalogue_id == "CAP001")
        assert cap001.status == CAPolicyStatus.ENFORCED
        assert cap001.match_confidence == 1.0
        assert cap001.matched_tenant_policy == "CAP001-All-BlockLegacyAuthentication-v1.0"

    def test_report_only_status(self, matcher: CAMatcher, signals: IdentitySignals) -> None:
        tenant_policies = [
            {"displayName": "CAU001-All-RequireMFAAllUsers-v1.0", "state": "enabledForReportingButNotEnforced"},
        ]
        results = matcher.match(tenant_policies, signals)
        cau001 = next(r for r in results if r.catalogue_id == "CAU001")
        assert cau001.status == CAPolicyStatus.REPORT_ONLY

    def test_missing_policy(self, matcher: CAMatcher, signals: IdentitySignals) -> None:
        results = matcher.match([], signals)
        # All should be missing
        assert all(r.status == CAPolicyStatus.MISSING for r in results)
        assert all(r.match_confidence == 0.0 for r in results)

    def test_one_to_many_prevention(self, matcher: CAMatcher, signals: IdentitySignals) -> None:
        # Same tenant policy name appears twice - should only match once
        tenant_policies = [
            {"displayName": "CAP001-All-BlockLegacyAuthentication-v1.0", "state": "enabled"},
        ]
        results = matcher.match(tenant_policies, signals)
        matched = [r for r in results if r.matched_tenant_policy is not None]
        # Each tenant policy matches at most one catalogue entry
        tenant_names = [r.matched_tenant_policy for r in matched]
        assert len(tenant_names) == len(set(tenant_names))

    def test_structural_match_mfa(self, matcher: CAMatcher, signals: IdentitySignals) -> None:
        # Tenant policy with MFA grant control should match CAU001
        tenant_policies = [
            {
                "displayName": "Require MFA for everyone",
                "state": "enabled",
                "conditions": {"users": {"includeUsers": ["All"]}, "applications": {"includeApplications": ["All"]}},
                "grantControls": {"builtInControls": ["mfa"]},
            },
        ]
        results = matcher.match(tenant_policies, signals)
        # Should find at least one matched MFA-related policy
        matched = [r for r in results if r.matched_tenant_policy == "Require MFA for everyone"]
        assert len(matched) >= 1
        assert matched[0].status == CAPolicyStatus.ENFORCED

    def test_catalogue_loads(self, matcher: CAMatcher, signals: IdentitySignals) -> None:
        results = matcher.match([], signals)
        # Should have loaded foundation policies (16 at IG1)
        assert len(results) == 16

    def test_guest_no_active_exposure_when_no_guests(self, matcher: CAMatcher) -> None:
        signals_no_guests = IdentitySignals(guest=GuestSignals(total_guests=0))
        results = matcher.match([], signals_no_guests)
        guest_policies = [r for r in results if "guest" in r.catalogue_name.lower()]
        for gp in guest_policies:
            assert gp.active_exposure is False
