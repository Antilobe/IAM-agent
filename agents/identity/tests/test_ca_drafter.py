"""Tests for CA policy drafter."""

from __future__ import annotations

import json

import pytest

from identity_agent.models.gaps import GapDomain, GapType, IdentityGap, Severity
from identity_agent.recommend.ca_drafter import CADrafter


def _make_ca_gap(catalogue_ref: str, title: str = "Test Policy") -> IdentityGap:
    return IdentityGap(
        id="GAP-CA-001",
        domain=GapDomain.CA_POLICY,
        catalogue_ref=catalogue_ref,
        title=title,
        description="Missing CA policy",
        severity=Severity.HIGH,
        gap_type=GapType.MISSING,
        active_exposure=True,
    )


class MockLLM:
    def __init__(self, response: str) -> None:
        self._response = response

    async def complete(self, system: str, user: str) -> str:
        return self._response


class TestCADrafter:
    @pytest.mark.asyncio
    async def test_deterministic_cap001(self) -> None:
        drafter = CADrafter()
        gap = _make_ca_gap("CAP001", "Block Legacy Auth")
        draft = await drafter.draft(gap)
        assert draft is not None
        assert draft["state"] == "enabledForReportingButNotEnforced"
        assert draft["displayName"] == "CAP001-All-BlockLegacyAuthentication-v1.0"
        assert "block" in draft["grantControls"]["builtInControls"]

    @pytest.mark.asyncio
    async def test_deterministic_cap003(self) -> None:
        drafter = CADrafter()
        gap = _make_ca_gap("CAP003")
        draft = await drafter.draft(gap)
        assert draft is not None
        assert "deviceCodeFlow" in str(draft["conditions"])

    @pytest.mark.asyncio
    async def test_no_llm_non_deterministic_returns_none(self) -> None:
        drafter = CADrafter(llm=None)
        gap = _make_ca_gap("CAU001", "Require MFA for All Users")
        draft = await drafter.draft(gap)
        assert draft is None

    @pytest.mark.asyncio
    async def test_llm_based_draft(self) -> None:
        llm_response = json.dumps({
            "displayName": "Require MFA",
            "state": "enabledForReportingButNotEnforced",
            "conditions": {
                "users": {"includeUsers": ["All"]},
                "applications": {"includeApplications": ["All"]},
            },
            "grantControls": {"builtInControls": ["mfa"]},
        })
        drafter = CADrafter(llm=MockLLM(llm_response))
        gap = _make_ca_gap("CAU001", "Require MFA for All Users")
        draft = await drafter.draft(gap)
        assert draft is not None
        assert draft["state"] == "enabledForReportingButNotEnforced"

    @pytest.mark.asyncio
    async def test_llm_wrong_state_corrected(self) -> None:
        """If LLM returns wrong state, it gets corrected."""
        llm_response = json.dumps({
            "displayName": "Test",
            "state": "enabled",  # Wrong!
            "conditions": {"users": {"includeUsers": ["All"]}},
        })
        drafter = CADrafter(llm=MockLLM(llm_response))
        gap = _make_ca_gap("CAU005")
        draft = await drafter.draft(gap)
        assert draft is not None
        assert draft["state"] == "enabledForReportingButNotEnforced"

    @pytest.mark.asyncio
    async def test_no_catalogue_ref(self) -> None:
        drafter = CADrafter()
        gap = IdentityGap(
            id="GAP-X",
            domain=GapDomain.CA_POLICY,
            catalogue_ref=None,
            title="X",
            description="X",
            severity=Severity.LOW,
            gap_type=GapType.MISSING,
            active_exposure=False,
        )
        draft = await drafter.draft(gap)
        assert draft is None
