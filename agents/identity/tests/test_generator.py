"""Tests for LLM recommendation generator."""

from __future__ import annotations

import json

import pytest

from identity_agent.models.gaps import GapDomain, GapType, IdentityGap, Severity
from identity_agent.models.signals import IdentitySignals
from identity_agent.recommend.generator import RecommendationGenerator


class MockLLM:
    """Mock LLM backend that returns a known JSON response."""

    def __init__(self, response: str) -> None:
        self._response = response

    async def complete(self, system: str, user: str) -> str:
        return self._response


def _make_gap(
    gap_id: str = "GAP-CA-001",
    active_exposure: bool = True,
    severity: Severity = Severity.CRITICAL,
) -> IdentityGap:
    return IdentityGap(
        id=gap_id,
        domain=GapDomain.CA_POLICY,
        catalogue_ref="CAU001",
        title="Require MFA for All Users",
        description="Missing MFA policy",
        severity=severity,
        gap_type=GapType.MISSING,
        active_exposure=active_exposure,
    )


LLM_RESPONSE = json.dumps([
    {
        "gap_ids": ["GAP-CA-001"],
        "title": "Deploy MFA enforcement for all users",
        "priority": "critical",
        "action_type": "config",
        "effort": "low",
        "score_lift": 15.0,
        "finding": "No MFA policy enforced.",
        "remediation": "Entra admin > Protection > Conditional Access > New policy",
        "remediation_type": "guided",
        "evidence": {},
        "best_practice_ref": "https://learn.microsoft.com/...",
        "compliance_notes": {"framework_controls": {"nis2": "Article 21(2)(i)"}}
    },
])


class TestRecommendationGenerator:
    @pytest.mark.asyncio
    async def test_basic_generation(self) -> None:
        gap = _make_gap()
        gen = RecommendationGenerator(MockLLM(LLM_RESPONSE))
        recs = await gen.generate([gap], IdentitySignals())
        assert len(recs) == 1
        assert recs[0].id == "IDREC-001"
        assert recs[0].gap_ids == ["GAP-CA-001"]
        assert recs[0].score_lift == 15.0

    @pytest.mark.asyncio
    async def test_severity_cap_enforcement(self) -> None:
        """Gap with no active exposure should cap recommendation at HIGH."""
        gap = _make_gap(active_exposure=False)
        response = json.dumps([{
            "gap_ids": ["GAP-CA-001"],
            "title": "Fix it",
            "priority": "critical",  # Should be capped to high
            "action_type": "config",
            "effort": "low",
            "score_lift": 10.0,
            "finding": "x",
            "remediation": "y",
            "remediation_type": "guided",
        }])
        gen = RecommendationGenerator(MockLLM(response))
        recs = await gen.generate([gap], IdentitySignals())
        assert len(recs) == 1
        assert recs[0].priority.value == "high"  # Capped from critical

    @pytest.mark.asyncio
    async def test_empty_gaps(self) -> None:
        gen = RecommendationGenerator(MockLLM("[]"))
        recs = await gen.generate([], IdentitySignals())
        assert recs == []

    @pytest.mark.asyncio
    async def test_malformed_json_fallback(self) -> None:
        """Parser should handle markdown fences and extract objects."""
        response = '```json\n[{"gap_ids":["GAP-CA-001"],"title":"Fix","priority":"high","action_type":"config","effort":"low","score_lift":5,"finding":"x","remediation":"y","remediation_type":"manual"}]\n```'
        gap = _make_gap()
        gen = RecommendationGenerator(MockLLM(response))
        recs = await gen.generate([gap], IdentitySignals())
        assert len(recs) == 1

    @pytest.mark.asyncio
    async def test_invalid_gap_ids_filtered(self) -> None:
        """Recommendations referencing non-existent gaps are dropped."""
        response = json.dumps([{
            "gap_ids": ["NONEXISTENT"],
            "title": "Fix",
            "priority": "high",
            "action_type": "config",
            "effort": "low",
            "score_lift": 5,
            "finding": "x",
            "remediation": "y",
            "remediation_type": "manual",
        }])
        gap = _make_gap()
        gen = RecommendationGenerator(MockLLM(response))
        recs = await gen.generate([gap], IdentitySignals())
        assert len(recs) == 0
