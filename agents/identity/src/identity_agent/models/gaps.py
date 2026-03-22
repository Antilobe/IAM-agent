"""Identity gap models."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class GapDomain(str, Enum):
    CA_POLICY = "ca_policy"
    MFA = "mfa"
    PRIVILEGED_ACCESS = "privileged_access"
    RISK = "risk"
    APP_GOVERNANCE = "app_governance"
    GUEST = "guest"
    AUTH_METHODS = "auth_methods"
    BREAK_GLASS = "break_glass"
    ENTRA_HARDENING = "entra_hardening"
    PIM = "pim"
    IGA = "iga"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class GapType(str, Enum):
    MISSING = "missing"
    REPORT_ONLY = "report_only"
    MISCONFIGURED = "misconfigured"
    INSUFFICIENT = "insufficient"
    DISABLED = "disabled"


class IdentityGap(BaseModel):
    """A single identified gap in the tenant's identity posture."""

    id: str = Field(description="Unique gap identifier, e.g. GAP-CA-001")
    domain: GapDomain
    catalogue_ref: str | None = Field(
        default=None, description="Reference to catalogue item, e.g. CA-001"
    )
    title: str
    description: str
    severity: Severity
    gap_type: GapType
    active_exposure: bool = Field(
        description="True if the gap currently exposes the tenant to risk"
    )
    affected_entities: list[str] = Field(
        default_factory=list,
        description="User IDs, app IDs, or policy names affected",
    )
    affected_count: int = 0
    evidence: dict = Field(
        default_factory=dict,
        description="Supporting data — structure varies by domain",
    )
    best_practice_ref: str | None = Field(
        default=None, description="URL or doc reference to Microsoft best practice"
    )
    compliance_notes: dict = Field(
        default_factory=dict,
        description=(
            "Lightweight compliance hook — structured as "
            "{category, function, keywords, scope} for future compliance agent"
        ),
    )
