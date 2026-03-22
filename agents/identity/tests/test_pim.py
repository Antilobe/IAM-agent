"""Tests for PIM gap detection, signal building, and PIM drafter.

Covers hybrid vs cloud-only scenarios, standing GA detection,
and PIM policy draft generation.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from identity_agent.analyse.gap_analyser import GapAnalyser
from identity_agent.analyse.signals import SignalBuilder
from identity_agent.models.gaps import GapDomain, GapType, IdentityGap, Severity
from identity_agent.models.signals import IdentitySignals
from identity_agent.recommend.pim_drafter import PIMDrafter

CATALOGUE_DIR = Path(__file__).parent.parent / "catalogues"

GA_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"
PRA_ROLE_ID = "e8611ab8-c189-46e8-94e1-60213ab1f814"
PAA_ROLE_ID = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"
SEC_ADMIN_ROLE_ID = "194ae4cb-b126-40b2-bd5b-6091b380977d"


# ── Signal builder tests ──────────────────────────────────────────


class TestPIMSignalBuilder:
    def test_standing_ga_detected(self) -> None:
        """PIM-001: Standing GA should be counted."""
        raw_data = {
            "pim": {
                "available": True,
                "eligibility_schedules": [],  # No PIM eligibility
                "assignment_schedules": [],
                "role_settings": [],
                "privileged_users": [],
            },
            "directory_roles": {
                "role_assignments": [
                    {"roleDefinitionId": GA_ROLE_ID, "principalId": "user-1"},
                    {"roleDefinitionId": GA_ROLE_ID, "principalId": "user-2"},
                ],
                "role_definitions": [],
            },
        }
        analysis = SignalBuilder().build_analysis_dict(raw_data)
        assert analysis["pim"]["standing_ga"]["count"] == 2

    def test_standing_ga_zero_when_all_eligible(self) -> None:
        """PIM-001: No standing GA when all are PIM-eligible."""
        raw_data = {
            "pim": {
                "available": True,
                "eligibility_schedules": [
                    {"roleDefinitionId": GA_ROLE_ID, "principalId": "user-1"},
                ],
                "assignment_schedules": [],
                "role_settings": [],
                "privileged_users": [],
            },
            "directory_roles": {
                "role_assignments": [
                    {"roleDefinitionId": GA_ROLE_ID, "principalId": "user-1"},
                ],
                "role_definitions": [],
            },
        }
        analysis = SignalBuilder().build_analysis_dict(raw_data)
        assert analysis["pim"]["standing_ga"]["count"] == 0

    def test_hybrid_risk_synced_account_detected(self) -> None:
        """PIM-006: Synced account in GA role detected."""
        raw_data = {
            "pim": {
                "available": True,
                "eligibility_schedules": [],
                "assignment_schedules": [],
                "role_settings": [],
                "privileged_users": [
                    {
                        "id": "user-1",
                        "displayName": "Synced Admin",
                        "userPrincipalName": "syncedadmin@contoso.com",
                        "onPremisesImmutableId": "abc123==",
                        "onPremisesSyncEnabled": True,
                        "roleDefinitionIds": [GA_ROLE_ID],
                        "role_names": ["Global Administrator"],
                    },
                ],
            },
            "directory_roles": {"role_assignments": [], "role_definitions": []},
        }
        analysis = SignalBuilder().build_analysis_dict(raw_data)
        assert analysis["pim"]["hybrid_risk"]["synced_privileged_count"] == 1
        assert analysis["pim"]["hybrid_risk"]["synced_users"][0]["upn"] == "syncedadmin@contoso.com"

    def test_hybrid_risk_cloud_only_safe(self) -> None:
        """PIM-006: Cloud-only account in GA role is fine."""
        raw_data = {
            "pim": {
                "available": True,
                "eligibility_schedules": [],
                "assignment_schedules": [],
                "role_settings": [],
                "privileged_users": [
                    {
                        "id": "user-2",
                        "displayName": "Cloud Admin",
                        "userPrincipalName": "cloudadmin@contoso.com",
                        "onPremisesImmutableId": None,
                        "onPremisesSyncEnabled": False,
                        "roleDefinitionIds": [GA_ROLE_ID],
                        "role_names": ["Global Administrator"],
                    },
                ],
            },
            "directory_roles": {"role_assignments": [], "role_definitions": []},
        }
        analysis = SignalBuilder().build_analysis_dict(raw_data)
        assert analysis["pim"]["hybrid_risk"]["synced_privileged_count"] == 0

    def test_hybrid_risk_synced_operational_role_ignored(self) -> None:
        """PIM-006: Synced account in operational role (not critical) should NOT trigger."""
        raw_data = {
            "pim": {
                "available": True,
                "eligibility_schedules": [],
                "assignment_schedules": [],
                "role_settings": [],
                "privileged_users": [
                    {
                        "id": "user-3",
                        "displayName": "Synced Sec Admin",
                        "userPrincipalName": "secsync@contoso.com",
                        "onPremisesImmutableId": "xyz789==",
                        "onPremisesSyncEnabled": True,
                        "roleDefinitionIds": [SEC_ADMIN_ROLE_ID],
                        "role_names": ["Security Administrator"],
                    },
                ],
            },
            "directory_roles": {"role_assignments": [], "role_definitions": []},
        }
        analysis = SignalBuilder().build_analysis_dict(raw_data)
        assert analysis["pim"]["hybrid_risk"]["synced_privileged_count"] == 0

    def test_pim_unavailable_returns_empty(self) -> None:
        analysis = SignalBuilder().build_analysis_dict({"pim": {"available": False}})
        assert analysis["pim"] == {}


# ── Gap analyser tests ────────────────────────────────────────────


class TestPIMGapAnalyser:
    def test_standing_ga_creates_critical_gap(self) -> None:
        analyser = GapAnalyser(catalogue_dir=CATALOGUE_DIR)
        analysis_dict = {
            "pim": {
                "standing_ga": {"count": 3},
                "activation_duration": {"roles_exceeding_cap": 0},
                "approval_workflow": {"critical_roles_without_approval": 0},
                "activation_mfa": {"roles_without_mfa": 0},
                "activation_justification": {"roles_without_justification": 0},
                "hybrid_risk": {"synced_privileged_count": 0, "synced_users": []},
                "pim_access_reviews": {"configured": True},
            },
        }
        gaps, coverages = analyser.analyse(IdentitySignals(), [], analysis_dict)
        pim_gaps = [g for g in gaps if g.domain == GapDomain.PIM]
        ga_gap = [g for g in pim_gaps if g.catalogue_ref == "PIM-001"]
        assert len(ga_gap) == 1
        assert ga_gap[0].severity == Severity.CRITICAL

    def test_hybrid_synced_creates_critical_gap(self) -> None:
        analyser = GapAnalyser(catalogue_dir=CATALOGUE_DIR)
        analysis_dict = {
            "pim": {
                "standing_ga": {"count": 0},
                "activation_duration": {"roles_exceeding_cap": 0},
                "approval_workflow": {"critical_roles_without_approval": 0},
                "activation_mfa": {"roles_without_mfa": 0},
                "activation_justification": {"roles_without_justification": 0},
                "hybrid_risk": {
                    "synced_privileged_count": 1,
                    "synced_users": [{"upn": "synced@contoso.com", "roles": ["Global Administrator"]}],
                },
                "pim_access_reviews": {"configured": True},
            },
        }
        gaps, _ = analyser.analyse(IdentitySignals(), [], analysis_dict)
        hybrid_gaps = [g for g in gaps if g.catalogue_ref == "PIM-006"]
        assert len(hybrid_gaps) == 1
        assert hybrid_gaps[0].severity == Severity.CRITICAL

    def test_fully_compliant_pim_no_gaps(self) -> None:
        analyser = GapAnalyser(catalogue_dir=CATALOGUE_DIR)
        analysis_dict = {
            "pim": {
                "standing_ga": {"count": 0},
                "activation_duration": {"roles_exceeding_cap": 0},
                "approval_workflow": {"critical_roles_without_approval": 0},
                "activation_mfa": {"roles_without_mfa": 0},
                "activation_justification": {"roles_without_justification": 0},
                "hybrid_risk": {"synced_privileged_count": 0, "synced_users": []},
                "pim_access_reviews": {"configured": True},
            },
        }
        gaps, coverages = analyser.analyse(IdentitySignals(), [], analysis_dict)
        pim_gaps = [g for g in gaps if g.domain == GapDomain.PIM]
        assert len(pim_gaps) == 0
        assert coverages.get("pim", 0) == 100.0


# ── PIM drafter tests ────────────────────────────────────────────


def _make_pim_gap(catalogue_ref: str, title: str = "PIM Gap") -> IdentityGap:
    return IdentityGap(
        id="GAP-PIM-001",
        domain=GapDomain.PIM,
        catalogue_ref=catalogue_ref,
        title=title,
        description="PIM misconfiguration",
        severity=Severity.CRITICAL,
        gap_type=GapType.MISCONFIGURED,
        active_exposure=True,
        evidence={},
    )


class TestPIMDrafter:
    def test_draft_standing_ga(self) -> None:
        drafter = PIMDrafter()
        gap = _make_pim_gap("PIM-001", "No Standing GA")
        draft = drafter.draft(gap)
        assert draft is not None
        assert "roles" in draft
        assert draft["roles"][0]["role_name"] == "Global Administrator"
        assert draft["roles"][0]["activation_duration_hours"] == 4

    def test_draft_activation_duration(self) -> None:
        drafter = PIMDrafter()
        gap = _make_pim_gap("PIM-002")
        draft = drafter.draft(gap)
        assert draft is not None
        critical_roles = [r for r in draft["roles"] if r["tier"] == "critical"]
        operational_roles = [r for r in draft["roles"] if r["tier"] == "operational"]
        assert all(r["activation_duration_hours"] == 4 for r in critical_roles)
        assert all(r["activation_duration_hours"] == 8 for r in operational_roles)

    def test_draft_approval_workflow_has_placeholders(self) -> None:
        drafter = PIMDrafter()
        gap = _make_pim_gap("PIM-003")
        draft = drafter.draft(gap)
        assert draft is not None
        for role in draft["roles"]:
            assert role["requires_approval"] is True
            assert "APPROVER_UPN_1" in role["approvers"]

    def test_draft_mfa_phishing_resistant_for_critical(self) -> None:
        drafter = PIMDrafter()
        gap = _make_pim_gap("PIM-004")
        draft = drafter.draft(gap)
        assert draft is not None
        critical = [r for r in draft["roles"] if r["tier"] == "critical"]
        operational = [r for r in draft["roles"] if r["tier"] == "operational"]
        assert all(r["requires_phishing_resistant_mfa"] is True for r in critical)
        assert all(r["requires_phishing_resistant_mfa"] is False for r in operational)

    def test_draft_hybrid_includes_affected_users(self) -> None:
        drafter = PIMDrafter()
        gap = _make_pim_gap("PIM-006")
        gap.evidence = {
            "synced_users": [
                {"upn": "synced@contoso.com", "roles": ["Global Administrator"]},
            ],
        }
        draft = drafter.draft(gap)
        assert draft is not None
        assert len(draft["affected_users"]) == 1

    def test_required_operator_input_for_approval(self) -> None:
        drafter = PIMDrafter()
        gap = _make_pim_gap("PIM-003")
        oi = drafter.get_required_operator_input(gap)
        assert oi is not None
        assert oi["field"] == "approvers"
        assert "break-glass" in oi["prompt"]

    def test_no_operator_input_for_non_approval(self) -> None:
        drafter = PIMDrafter()
        gap = _make_pim_gap("PIM-001")
        oi = drafter.get_required_operator_input(gap)
        assert oi is None

    def test_non_pim_gap_returns_none(self) -> None:
        drafter = PIMDrafter()
        gap = IdentityGap(
            id="GAP-CA-001",
            domain=GapDomain.CA_POLICY,
            catalogue_ref="CAP001",
            title="CA Policy",
            description="Not PIM",
            severity=Severity.HIGH,
            gap_type=GapType.MISSING,
            active_exposure=True,
        )
        assert drafter.draft(gap) is None

    def test_graph_api_payload_structure(self) -> None:
        drafter = PIMDrafter()
        gap = _make_pim_gap("PIM-002")
        draft = drafter.draft(gap)
        role = draft["roles"][0]
        payload = role["graph_api_payload"]
        assert "rules" in payload
        # Check expiration rule
        exp_rule = next(r for r in payload["rules"] if "Expiration" in r["ruleType"])
        assert "PT4H" in exp_rule["maximumDuration"] or "PT8H" in exp_rule["maximumDuration"]
