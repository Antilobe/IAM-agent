"""Top-level assessment model and supporting types."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from identity_agent.models.gaps import IdentityGap
from identity_agent.models.recommendations import IdentityRecommendation
from identity_agent.models.signals import IdentitySignals


class CAPolicyStatus(str, Enum):
    ENFORCED = "enforced"
    REPORT_ONLY = "report_only"
    DISABLED = "disabled"
    MISSING = "missing"
    PARTIALLY_MATCHED = "partially_matched"


class CAPolicyResult(BaseModel):
    """Result of matching a catalogue CA policy against tenant policies."""

    catalogue_id: str = Field(description="Catalogue policy ID, e.g. CA-001")
    catalogue_name: str
    status: CAPolicyStatus
    matched_tenant_policy: str | None = Field(
        default=None, description="Display name of the matched tenant policy"
    )
    match_confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    scope_coverage: dict = Field(
        default_factory=dict,
        description="Breakdown of scope match — e.g. {users: 0.8, apps: 1.0}",
    )
    active_exposure: bool = False
    affected_users: list[str] = Field(default_factory=list)
    affected_user_count: int = 0


class ScoringBreakdown(BaseModel):
    """Per-domain scores that compose the overall identity score."""

    ca_policy_score: float = Field(ge=0, le=100, default=0.0)
    mfa_score: float = Field(ge=0, le=100, default=0.0)
    privileged_access_score: float = Field(ge=0, le=100, default=0.0)
    risk_posture_score: float = Field(ge=0, le=100, default=0.0)
    app_governance_score: float = Field(ge=0, le=100, default=0.0)
    guest_score: float = Field(ge=0, le=100, default=0.0)


class AssessmentMetadata(BaseModel):
    """Metadata about the assessment run."""

    agent_version: str = "0.1.0"
    duration_seconds: float = 0.0
    api_calls_made: int = 0
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    ingestors_run: list[str] = Field(default_factory=list)
    p2_license_detected: bool = False


class IdentityAssessment(BaseModel):
    """Top-level output of the Identity Security Agent."""

    tenant_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    identity_score: float = Field(ge=0, le=100)
    scoring_breakdown: ScoringBreakdown
    ca_policy_results: list[CAPolicyResult] = Field(default_factory=list)
    signals: IdentitySignals = Field(default_factory=IdentitySignals)
    gaps: list[IdentityGap] = Field(default_factory=list)
    recommendations: list[IdentityRecommendation] = Field(default_factory=list)
    metadata: AssessmentMetadata = Field(default_factory=AssessmentMetadata)
