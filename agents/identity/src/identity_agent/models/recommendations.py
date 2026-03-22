"""Recommendation models produced by the recommendation layer."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Priority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ActionType(str, Enum):
    CONFIG = "config"
    PROCESS = "process"
    HYBRID = "hybrid"


class Effort(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RemediationType(str, Enum):
    AUTOMATED = "automated"
    MANUAL = "manual"
    GUIDED = "guided"


class IdentityRecommendation(BaseModel):
    """An actionable recommendation linked to one or more identity gaps."""

    id: str = Field(description="Recommendation ID, e.g. IDREC-001")
    gap_ids: list[str] = Field(description="Gap IDs this recommendation addresses")
    title: str
    priority: Priority
    action_type: ActionType
    effort: Effort
    score_lift: float = Field(
        ge=0, le=100, description="Estimated identity score improvement"
    )
    finding: str = Field(description="Human-readable summary of the problem")
    remediation: str = Field(description="Step-by-step remediation guidance")
    remediation_type: RemediationType
    evidence: dict = Field(default_factory=dict)
    ca_policy_draft: dict | None = Field(
        default=None,
        description=(
            "Draft CA policy JSON (reportOnly state). "
            "Only present for gap_type=missing + domain=ca_policy."
        ),
    )
    pim_policy_draft: dict | None = Field(
        default=None,
        description=(
            "Draft PIM role settings JSON for operator review. "
            "Only present for PIM-related gaps (domain=pim)."
        ),
    )
    required_operator_input: dict | None = Field(
        default=None,
        description=(
            "Fields requiring operator input before deployment. "
            "E.g. approver UPNs for PIM approval workflows."
        ),
    )
    best_practice_ref: str | None = None
    compliance_notes: dict = Field(
        default_factory=dict,
        description="Compliance hook for future compliance agent",
    )
