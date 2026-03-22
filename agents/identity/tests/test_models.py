"""Tests: model instantiation, validation, and JSON round-trip."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from identity_agent.models.assessment import (
    AssessmentMetadata,
    CAPolicyResult,
    CAPolicyStatus,
    IdentityAssessment,
    ScoringBreakdown,
)
from identity_agent.models.gaps import GapDomain, GapType, IdentityGap, Severity
from identity_agent.models.recommendations import (
    ActionType,
    Effort,
    IdentityRecommendation,
    Priority,
    RemediationType,
)
from identity_agent.models.signals import IdentitySignals, MFASignals


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture
def sample_gap() -> IdentityGap:
    return IdentityGap(
        id="GAP-CA-001",
        domain=GapDomain.CA_POLICY,
        catalogue_ref="CA-001",
        title="MFA not enforced for all users",
        description="No Conditional Access policy enforces MFA for all users.",
        severity=Severity.CRITICAL,
        gap_type=GapType.MISSING,
        active_exposure=True,
        affected_entities=["all_users"],
        affected_count=1500,
        evidence={"checked_policies": 12, "matching": 0},
        best_practice_ref="https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa",
        compliance_notes={
            "category": "authentication",
            "function": "enforce_mfa",
            "keywords": ["mfa", "conditional access"],
            "scope": "all_users",
        },
    )


@pytest.fixture
def sample_recommendation() -> IdentityRecommendation:
    return IdentityRecommendation(
        id="IDREC-001",
        gap_ids=["GAP-CA-001"],
        title="Deploy MFA enforcement policy for all users",
        priority=Priority.CRITICAL,
        action_type=ActionType.CONFIG,
        effort=Effort.LOW,
        score_lift=15.0,
        finding="No Conditional Access policy enforces MFA across the tenant.",
        remediation="Create a Conditional Access policy targeting all users requiring MFA.",
        remediation_type=RemediationType.GUIDED,
        evidence={"gap_count": 1},
        ca_policy_draft={
            "displayName": "[Draft] Require MFA for all users",
            "state": "enabledForReportingButNotEnforced",
            "conditions": {
                "users": {"includeUsers": ["All"]},
                "applications": {"includeApplications": ["All"]},
            },
            "grantControls": {
                "operator": "OR",
                "builtInControls": ["mfa"],
            },
        },
        best_practice_ref="https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa",
        compliance_notes={
            "category": "authentication",
            "function": "enforce_mfa",
            "keywords": ["mfa", "conditional access"],
            "scope": "all_users",
        },
    )


@pytest.fixture
def sample_ca_result() -> CAPolicyResult:
    return CAPolicyResult(
        catalogue_id="CA-002",
        catalogue_name="Block legacy authentication",
        status=CAPolicyStatus.ENFORCED,
        matched_tenant_policy="Block Legacy Auth - All Users",
        match_confidence=0.95,
        scope_coverage={"users": 1.0, "applications": 1.0},
        active_exposure=False,
        affected_users=[],
        affected_user_count=0,
    )


@pytest.fixture
def sample_signals() -> IdentitySignals:
    return IdentitySignals(
        mfa=MFASignals(total_users=1500, mfa_registered=1200, mfa_capable=1350),
    )


@pytest.fixture
def sample_assessment(
    sample_gap: IdentityGap,
    sample_recommendation: IdentityRecommendation,
    sample_ca_result: CAPolicyResult,
    sample_signals: IdentitySignals,
) -> IdentityAssessment:
    return IdentityAssessment(
        tenant_id="00000000-0000-0000-0000-000000000001",
        timestamp=datetime(2026, 3, 22, 12, 0, 0, tzinfo=timezone.utc),
        identity_score=62.5,
        scoring_breakdown=ScoringBreakdown(
            ca_policy_score=50.0,
            mfa_score=80.0,
            privileged_access_score=60.0,
            risk_posture_score=70.0,
            app_governance_score=55.0,
            guest_score=90.0,
        ),
        ca_policy_results=[sample_ca_result],
        signals=sample_signals,
        gaps=[sample_gap],
        recommendations=[sample_recommendation],
        metadata=AssessmentMetadata(
            agent_version="0.1.0",
            duration_seconds=12.5,
            api_calls_made=47,
            ingestors_run=["ConditionalAccessIngestor", "MFARegistrationIngestor"],
            p2_license_detected=True,
        ),
    )


# ── Model instantiation tests ────────────────────────────────────────────


class TestIdentityGap:
    def test_create(self, sample_gap: IdentityGap) -> None:
        assert sample_gap.id == "GAP-CA-001"
        assert sample_gap.domain == GapDomain.CA_POLICY
        assert sample_gap.severity == Severity.CRITICAL
        assert sample_gap.active_exposure is True
        assert sample_gap.compliance_notes["category"] == "authentication"

    def test_json_round_trip(self, sample_gap: IdentityGap) -> None:
        json_str = sample_gap.model_dump_json()
        restored = IdentityGap.model_validate_json(json_str)
        assert restored == sample_gap

    def test_dict_round_trip(self, sample_gap: IdentityGap) -> None:
        data = sample_gap.model_dump()
        restored = IdentityGap.model_validate(data)
        assert restored == sample_gap


class TestIdentityRecommendation:
    def test_create(self, sample_recommendation: IdentityRecommendation) -> None:
        assert sample_recommendation.id == "IDREC-001"
        assert sample_recommendation.priority == Priority.CRITICAL
        assert sample_recommendation.ca_policy_draft is not None
        assert sample_recommendation.ca_policy_draft["state"] == "enabledForReportingButNotEnforced"

    def test_json_round_trip(self, sample_recommendation: IdentityRecommendation) -> None:
        json_str = sample_recommendation.model_dump_json()
        restored = IdentityRecommendation.model_validate_json(json_str)
        assert restored == sample_recommendation

    def test_score_lift_bounds(self) -> None:
        with pytest.raises(Exception):
            IdentityRecommendation(
                id="IDREC-999",
                gap_ids=["GAP-001"],
                title="Bad",
                priority=Priority.LOW,
                action_type=ActionType.CONFIG,
                effort=Effort.LOW,
                score_lift=150.0,  # > 100, should fail
                finding="x",
                remediation="y",
                remediation_type=RemediationType.MANUAL,
            )


class TestCAPolicyResult:
    def test_create(self, sample_ca_result: CAPolicyResult) -> None:
        assert sample_ca_result.status == CAPolicyStatus.ENFORCED
        assert sample_ca_result.match_confidence == 0.95

    def test_json_round_trip(self, sample_ca_result: CAPolicyResult) -> None:
        json_str = sample_ca_result.model_dump_json()
        restored = CAPolicyResult.model_validate_json(json_str)
        assert restored == sample_ca_result

    def test_confidence_bounds(self) -> None:
        with pytest.raises(Exception):
            CAPolicyResult(
                catalogue_id="CA-999",
                catalogue_name="Bad",
                status=CAPolicyStatus.MISSING,
                match_confidence=1.5,  # > 1.0
            )


class TestIdentitySignals:
    def test_defaults(self) -> None:
        signals = IdentitySignals()
        assert signals.mfa.total_users == 0
        assert signals.risk.risky_users_high == 0

    def test_mfa_registration_rate(self) -> None:
        mfa = MFASignals(total_users=100, mfa_registered=80)
        assert mfa.registration_rate == 0.8

    def test_mfa_registration_rate_zero_users(self) -> None:
        mfa = MFASignals()
        assert mfa.registration_rate == 0.0

    def test_json_round_trip(self, sample_signals: IdentitySignals) -> None:
        json_str = sample_signals.model_dump_json()
        restored = IdentitySignals.model_validate_json(json_str)
        assert restored == sample_signals


class TestScoringBreakdown:
    def test_defaults(self) -> None:
        breakdown = ScoringBreakdown()
        assert breakdown.ca_policy_score == 0.0
        assert breakdown.guest_score == 0.0

    def test_score_bounds(self) -> None:
        with pytest.raises(Exception):
            ScoringBreakdown(ca_policy_score=150.0)


class TestIdentityAssessment:
    def test_create(self, sample_assessment: IdentityAssessment) -> None:
        assert sample_assessment.tenant_id == "00000000-0000-0000-0000-000000000001"
        assert sample_assessment.identity_score == 62.5
        assert len(sample_assessment.gaps) == 1
        assert len(sample_assessment.recommendations) == 1
        assert len(sample_assessment.ca_policy_results) == 1

    def test_json_round_trip(self, sample_assessment: IdentityAssessment) -> None:
        json_str = sample_assessment.model_dump_json()
        restored = IdentityAssessment.model_validate_json(json_str)
        assert restored.tenant_id == sample_assessment.tenant_id
        assert restored.identity_score == sample_assessment.identity_score
        assert len(restored.gaps) == len(sample_assessment.gaps)
        assert len(restored.recommendations) == len(sample_assessment.recommendations)

    def test_dict_round_trip(self, sample_assessment: IdentityAssessment) -> None:
        data = sample_assessment.model_dump(mode="json")
        restored = IdentityAssessment.model_validate(data)
        assert restored.tenant_id == sample_assessment.tenant_id
        assert restored.identity_score == sample_assessment.identity_score

    def test_metadata(self, sample_assessment: IdentityAssessment) -> None:
        assert sample_assessment.metadata.p2_license_detected is True
        assert sample_assessment.metadata.api_calls_made == 47
        assert "ConditionalAccessIngestor" in sample_assessment.metadata.ingestors_run


class TestAssessmentMetadata:
    def test_defaults(self) -> None:
        meta = AssessmentMetadata()
        assert meta.agent_version == "0.1.0"
        assert meta.errors == []
        assert meta.p2_license_detected is False
