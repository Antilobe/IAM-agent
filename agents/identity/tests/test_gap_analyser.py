"""Tests for gap analysis (Engine 2: generic control matching)."""

from __future__ import annotations

from pathlib import Path

import pytest

from identity_agent.analyse.gap_analyser import (
    GapAnalyser,
    _evaluate_control,
    _resolve_data_path,
)
from identity_agent.models.assessment import CAPolicyResult, CAPolicyStatus
from identity_agent.models.gaps import GapDomain, GapType, Severity
from identity_agent.models.signals import IdentitySignals

CATALOGUE_DIR = Path(__file__).parent.parent / "catalogues"


# ── _resolve_data_path ────────────────────────────────────────────


class TestResolveDataPath:
    def test_simple_key(self) -> None:
        assert _resolve_data_path({"a": 1}, "a") == 1

    def test_nested_key(self) -> None:
        assert _resolve_data_path({"a": {"b": {"c": 42}}}, "a.b.c") == 42

    def test_missing_key(self) -> None:
        assert _resolve_data_path({"a": 1}, "b") is None

    def test_missing_nested(self) -> None:
        assert _resolve_data_path({"a": {"b": 1}}, "a.c") is None

    def test_empty_data(self) -> None:
        assert _resolve_data_path({}, "a") is None

    def test_empty_path(self) -> None:
        assert _resolve_data_path({"a": 1}, "") is None


# ── _evaluate_control (each check_type) ──────────────────────────


class TestEvaluateControl:
    def test_boolean_true(self) -> None:
        ctrl = {"id": "T1", "title": "t", "check_type": "boolean", "data_path": "x", "expected": True}
        r = _evaluate_control(ctrl, {"x": True})
        assert r["status"] == "compliant"

    def test_boolean_false(self) -> None:
        ctrl = {"id": "T2", "title": "t", "check_type": "boolean", "data_path": "x", "expected": False}
        r = _evaluate_control(ctrl, {"x": True})
        assert r["status"] == "non_compliant"

    def test_boolean_present(self) -> None:
        ctrl = {"id": "T3", "title": "t", "check_type": "boolean_present", "data_path": "methods", "check_value": "fido2"}
        r = _evaluate_control(ctrl, {"methods": ["fido2", "sms"]})
        assert r["status"] == "compliant"

    def test_boolean_present_missing(self) -> None:
        ctrl = {"id": "T4", "title": "t", "check_type": "boolean_present", "data_path": "methods", "check_value": "fido2"}
        r = _evaluate_control(ctrl, {"methods": ["sms"]})
        assert r["status"] == "non_compliant"

    def test_boolean_absent(self) -> None:
        ctrl = {"id": "T5", "title": "t", "check_type": "boolean_absent", "data_path": "methods", "check_value": "sms"}
        r = _evaluate_control(ctrl, {"methods": ["fido2"]})
        assert r["status"] == "compliant"

    def test_boolean_absent_present(self) -> None:
        ctrl = {"id": "T6", "title": "t", "check_type": "boolean_absent", "data_path": "methods", "check_value": "sms"}
        r = _evaluate_control(ctrl, {"methods": ["fido2", "sms"]})
        assert r["status"] == "non_compliant"

    def test_threshold_gte_pass(self) -> None:
        ctrl = {"id": "T7", "title": "t", "check_type": "threshold_gte", "data_path": "count", "expected": 2}
        r = _evaluate_control(ctrl, {"count": 3})
        assert r["status"] == "compliant"

    def test_threshold_gte_fail(self) -> None:
        ctrl = {"id": "T8", "title": "t", "check_type": "threshold_gte", "data_path": "count", "expected": 5}
        r = _evaluate_control(ctrl, {"count": 3})
        assert r["status"] == "non_compliant"

    def test_threshold_eq(self) -> None:
        ctrl = {"id": "T9", "title": "t", "check_type": "threshold_eq", "data_path": "count", "expected": 0}
        r = _evaluate_control(ctrl, {"count": 0})
        assert r["status"] == "compliant"

    def test_count_eq_list(self) -> None:
        ctrl = {"id": "T10", "title": "t", "check_type": "count_eq", "data_path": "items", "expected": 2}
        r = _evaluate_control(ctrl, {"items": ["a", "b"]})
        assert r["status"] == "compliant"

    def test_enum_pass(self) -> None:
        ctrl = {"id": "T11", "title": "t", "check_type": "enum", "data_path": "policy", "expected_values": ["adminsOnly", "none"]}
        r = _evaluate_control(ctrl, {"policy": "adminsOnly"})
        assert r["status"] == "compliant"

    def test_enum_fail(self) -> None:
        ctrl = {"id": "T12", "title": "t", "check_type": "enum", "data_path": "policy", "expected_values": ["adminsOnly"]}
        r = _evaluate_control(ctrl, {"policy": "everyone"})
        assert r["status"] == "non_compliant"

    def test_all_true_pass(self) -> None:
        ctrl = {"id": "T13", "title": "t", "check_type": "all_true", "data_path": "accounts", "check_field": "enabled", "expected": True}
        r = _evaluate_control(ctrl, {"accounts": [{"enabled": True}, {"enabled": True}]})
        assert r["status"] == "compliant"

    def test_all_true_fail(self) -> None:
        ctrl = {"id": "T14", "title": "t", "check_type": "all_true", "data_path": "accounts", "check_field": "enabled", "expected": True}
        r = _evaluate_control(ctrl, {"accounts": [{"enabled": True}, {"enabled": False}]})
        assert r["status"] == "non_compliant"

    def test_no_data(self) -> None:
        ctrl = {"id": "T15", "title": "t", "check_type": "boolean", "data_path": "missing.path", "expected": True}
        r = _evaluate_control(ctrl, {})
        assert r["status"] == "no_data"


# ── Full gap analyser ────────────────────────────────────────────


class TestGapAnalyser:
    def test_ca_gaps_from_results(self) -> None:
        analyser = GapAnalyser(catalogue_dir=CATALOGUE_DIR)
        ca_results = [
            CAPolicyResult(catalogue_id="CAP001", catalogue_name="Block Legacy Auth", status=CAPolicyStatus.ENFORCED, match_confidence=1.0),
            CAPolicyResult(catalogue_id="CAU001", catalogue_name="Require MFA All Users", status=CAPolicyStatus.MISSING, match_confidence=0.0, active_exposure=True),
        ]
        gaps, coverages = analyser.analyse(IdentitySignals(), ca_results, {})
        ca_gaps = [g for g in gaps if g.domain == GapDomain.CA_POLICY]
        assert len(ca_gaps) == 1
        assert ca_gaps[0].catalogue_ref == "CAU001"
        assert ca_gaps[0].gap_type == GapType.MISSING
        # CAU001 is foundationally critical + active exposure → CRITICAL
        assert ca_gaps[0].severity == Severity.CRITICAL
        assert coverages["ca"] == 50.0  # 1 enforced / 2 total

    def test_severity_capping(self) -> None:
        analyser = GapAnalyser(catalogue_dir=CATALOGUE_DIR)
        # Non-critical, no active exposure → capped at HIGH
        ca_results = [
            CAPolicyResult(
                catalogue_id="CAU008",  # Not foundationally critical
                catalogue_name="Admin Session Timeout",
                status=CAPolicyStatus.MISSING,
                match_confidence=0.0,
                active_exposure=False,
            ),
        ]
        gaps, _ = analyser.analyse(IdentitySignals(), ca_results, {})
        ca_gaps = [g for g in gaps if g.domain == GapDomain.CA_POLICY]
        assert len(ca_gaps) == 1
        # HIGH is assigned for missing non-critical, and not capped further since it's already HIGH
        assert ca_gaps[0].severity in (Severity.HIGH, Severity.MEDIUM)

    def test_identity_catalogue_controls(self) -> None:
        analyser = GapAnalyser(catalogue_dir=CATALOGUE_DIR)
        analysis_dict = {
            "auth_methods": {
                "enabled_methods": ["microsoftAuthenticator", "sms"],
                "fido2_enabled": False,
                "passkey_enabled": False,
                "weak_methods_enabled": ["sms"],
            },
        }
        gaps, coverages = analyser.analyse(IdentitySignals(), [], analysis_dict)
        auth_gaps = [g for g in gaps if g.domain == GapDomain.AUTH_METHODS]
        # Should find gaps for: SMS not absent (AUTH001), FIDO2 not enabled (AUTH004), etc.
        assert len(auth_gaps) > 0
        assert "auth_methods" in coverages

    def test_sorting(self) -> None:
        analyser = GapAnalyser(catalogue_dir=CATALOGUE_DIR)
        ca_results = [
            CAPolicyResult(catalogue_id="CAU001", catalogue_name="MFA", status=CAPolicyStatus.MISSING, active_exposure=True),
            CAPolicyResult(catalogue_id="CAU004", catalogue_name="Guest MFA", status=CAPolicyStatus.REPORT_ONLY, active_exposure=True),
        ]
        gaps, _ = analyser.analyse(IdentitySignals(), ca_results, {})
        ca_gaps = [g for g in gaps if g.domain == GapDomain.CA_POLICY]
        # Missing should come before report_only
        if len(ca_gaps) >= 2:
            assert ca_gaps[0].gap_type == GapType.MISSING
