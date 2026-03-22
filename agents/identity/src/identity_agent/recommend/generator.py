"""LLM-enriched recommendation generator."""

from __future__ import annotations

import json
import logging
import re
from typing import Protocol, runtime_checkable

from identity_agent.models.gaps import IdentityGap, Severity
from identity_agent.models.recommendations import (
    ActionType,
    Effort,
    IdentityRecommendation,
    Priority,
    RemediationType,
)
from identity_agent.models.signals import IdentitySignals

logger = logging.getLogger(__name__)


@runtime_checkable
class LLMBackend(Protocol):
    """Protocol for swappable LLM backends (Anthropic, local, etc.)."""

    async def complete(self, system: str, user: str) -> str: ...


SYSTEM_PROMPT = """You are a senior cybersecurity advisor specialising in Microsoft Entra ID.
You analyse identity posture gaps and produce precise, evidence-based security recommendations.

RULES:
1. NAME SPECIFIC POLICIES: Reference catalogue IDs (e.g. CAU001) and framework controls.
2. CROSS-REFERENCE FRAMEWORKS: Map each gap to NIS2, ISO 27001, CIS 18, CISA where applicable.
3. REMEDIATION MUST BE EXECUTABLE: Give exact Entra portal paths or PowerShell commands.
4. DO NOT INVENT: Only recommend what is evidenced by the gap data.
5. SEVERITY CAP: If a gap has active_exposure=false, maximum priority is "high" (never "critical").
6. gap_type MUST match the deterministic analysis (missing/report_only/disabled/misconfigured).

PRIORITY: critical (24-48h) | high (2 weeks) | medium (30 days) | low (quarter)
EFFORT: low (<2h) | medium (2-8h) | high (days/weeks)
ACTION_TYPE: config | process | hybrid

Return a JSON array only. No markdown fences, no preamble:
[
  {
    "gap_ids": ["GAP-CA-001"],
    "title": "10 words max",
    "priority": "critical|high|medium|low",
    "action_type": "config|process|hybrid",
    "effort": "low|medium|high",
    "score_lift": 5.0,
    "finding": "What is wrong, with evidence.",
    "remediation": "Step-by-step fix with portal paths.",
    "remediation_type": "automated|manual|guided",
    "evidence": {},
    "best_practice_ref": "URL or null",
    "compliance_notes": {"framework_controls": {}}
  }
]"""


class RecommendationGenerator:
    """Accepts gaps + signals, uses LLM to produce enriched recommendations."""

    def __init__(self, llm: LLMBackend) -> None:
        self._llm = llm

    async def generate(
        self,
        gaps: list[IdentityGap],
        signals: IdentitySignals,
    ) -> list[IdentityRecommendation]:
        if not gaps:
            return []

        user_prompt = self._build_user_prompt(gaps, signals)
        raw_response = await self._llm.complete(system=SYSTEM_PROMPT, user=user_prompt)

        parsed = self._parse_response(raw_response)
        recommendations = self._validate_and_map(parsed, gaps)
        return recommendations

    def _build_user_prompt(self, gaps: list[IdentityGap], signals: IdentitySignals) -> str:
        sections = []

        # Signals summary
        sections.append("## Identity Signals")
        sections.append(f"- MFA: {signals.mfa.mfa_registered}/{signals.mfa.total_users} registered ({signals.mfa.registration_rate:.0%})")
        sections.append(f"- Privileged: {signals.privileged_access.permanent_global_admins} permanent GAs, PIM {'enabled' if signals.privileged_access.pim_enabled else 'disabled'}")
        sections.append(f"- Risk: {signals.risk.risky_users_high} high-risk users, {signals.risk.high_risk_sign_ins_7d} high-risk sign-ins (7d)")
        sections.append(f"- Apps: {signals.app_governance.total_app_registrations} registrations, {signals.app_governance.apps_with_expiring_secrets} expiring secrets")
        sections.append(f"- Guests: {signals.guest.total_guests} total, {signals.guest.guests_last_sign_in_over_90d} stale (>90d)")
        sections.append("")

        # Group gaps by domain
        domains: dict[str, list[IdentityGap]] = {}
        for g in gaps:
            domains.setdefault(g.domain.value, []).append(g)

        sections.append("## Gaps")
        for domain, domain_gaps in domains.items():
            sections.append(f"\n### {domain}")
            for g in domain_gaps:
                sections.append(
                    f"- [{g.id}] {g.title} | severity={g.severity.value} | "
                    f"gap_type={g.gap_type.value} | active_exposure={g.active_exposure} | "
                    f"catalogue_ref={g.catalogue_ref}"
                )
                if g.compliance_notes:
                    fc = g.compliance_notes.get("framework_controls", {})
                    if fc:
                        sections.append(f"  frameworks: {json.dumps(fc, default=str)}")

        return "\n".join(sections)

    def _parse_response(self, raw: str) -> list[dict]:
        """Parse LLM response into a list of recommendation dicts."""
        # Strip markdown fences
        cleaned = re.sub(r"```(?:json)?\s*", "", raw).strip()
        cleaned = re.sub(r"```\s*$", "", cleaned).strip()

        try:
            parsed = json.loads(cleaned)
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, dict):
                return [parsed]
        except json.JSONDecodeError:
            pass

        # Fallback: extract individual objects
        results = []
        for match in re.finditer(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", cleaned):
            try:
                obj = json.loads(match.group())
                results.append(obj)
            except json.JSONDecodeError:
                continue
        return results

    def _validate_and_map(
        self, parsed: list[dict], gaps: list[IdentityGap]
    ) -> list[IdentityRecommendation]:
        """Validate parsed recommendations and map to Pydantic models."""
        gap_ids = {g.id for g in gaps}
        gap_lookup = {g.id: g for g in gaps}
        recommendations: list[IdentityRecommendation] = []

        for i, rec_dict in enumerate(parsed):
            try:
                rec_gap_ids = rec_dict.get("gap_ids", [])
                # Validate gap_ids exist
                valid_gap_ids = [gid for gid in rec_gap_ids if gid in gap_ids]
                if not valid_gap_ids:
                    continue

                # Determine priority with severity cap enforcement
                priority_str = rec_dict.get("priority", "medium").lower()
                priority = Priority(priority_str) if priority_str in [p.value for p in Priority] else Priority.MEDIUM

                # Enforce severity cap: if all referenced gaps have no active exposure, cap at HIGH
                all_no_exposure = all(
                    not gap_lookup[gid].active_exposure
                    for gid in valid_gap_ids
                    if gid in gap_lookup
                )
                if all_no_exposure and priority == Priority.CRITICAL:
                    priority = Priority.HIGH

                rec = IdentityRecommendation(
                    id=f"IDREC-{i + 1:03d}",
                    gap_ids=valid_gap_ids,
                    title=rec_dict.get("title", "Untitled")[:80],
                    priority=priority,
                    action_type=ActionType(rec_dict.get("action_type", "config")),
                    effort=Effort(rec_dict.get("effort", "medium")),
                    score_lift=min(float(rec_dict.get("score_lift", 0)), 100),
                    finding=rec_dict.get("finding", ""),
                    remediation=rec_dict.get("remediation", ""),
                    remediation_type=RemediationType(rec_dict.get("remediation_type", "guided")),
                    evidence=rec_dict.get("evidence", {}),
                    best_practice_ref=rec_dict.get("best_practice_ref"),
                    compliance_notes=rec_dict.get("compliance_notes", {}),
                )
                recommendations.append(rec)
            except Exception as exc:
                logger.warning("Skipping invalid recommendation %d: %s", i, exc)
                continue

        # Sort: Critical > High > Medium > Low, then by score_lift desc
        priority_order = {Priority.CRITICAL: 0, Priority.HIGH: 1, Priority.MEDIUM: 2, Priority.LOW: 3}
        recommendations.sort(key=lambda r: (priority_order.get(r.priority, 9), -r.score_lift))

        return recommendations
