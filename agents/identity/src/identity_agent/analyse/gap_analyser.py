"""Deterministic gap analysis across all identity domains.

Engine 2: generic control matching for identity catalogue layers
(auth_methods, break_glass, entra_hardening, pim, iga).

Adapted from Security-Agent's identity_gap_analyser.py.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from identity_agent.models.assessment import CAPolicyResult, CAPolicyStatus
from identity_agent.models.gaps import GapDomain, GapType, IdentityGap, Severity
from identity_agent.models.signals import IdentitySignals

logger = logging.getLogger(__name__)

# Map catalogue layer keys to GapDomain
LAYER_TO_DOMAIN: dict[str, GapDomain] = {
    "auth_methods": GapDomain.AUTH_METHODS,
    "break_glass": GapDomain.BREAK_GLASS,
    "entra_hardening": GapDomain.ENTRA_HARDENING,
    "pim": GapDomain.PIM,
    "iga": GapDomain.IGA,
}

# Foundationally critical controls — severity NOT capped even without active exposure
FOUNDATIONALLY_CRITICAL = {
    "CAP001", "CAP002", "CAU001", "CAU002",
    "BRK001", "BRK004",
    "PIM-001", "PIM-004", "PIM-006",
}


class GapAnalyser:
    """Analyses ingest data and signals to produce IdentityGap items."""

    def __init__(self, catalogue_dir: Path | None = None) -> None:
        self._catalogue_dir = catalogue_dir or (
            Path(__file__).parent.parent.parent.parent / "catalogues"
        )

    def analyse(
        self,
        signals: IdentitySignals,
        ca_policy_results: list[CAPolicyResult],
        analysis_dict: dict[str, Any],
    ) -> tuple[list[IdentityGap], dict[str, float]]:
        """Run gap analysis. Returns (gaps, layer_coverage_percentages)."""
        gaps: list[IdentityGap] = []
        layer_coverages: dict[str, float] = {}
        gap_counter = 0

        # ── Engine 1 output: CA policy gaps ──────────────────────
        ca_enforced = 0
        ca_report_only = 0
        ca_total = len(ca_policy_results)

        for cr in ca_policy_results:
            if cr.status == CAPolicyStatus.ENFORCED:
                ca_enforced += 1
                continue
            if cr.status == CAPolicyStatus.REPORT_ONLY:
                ca_report_only += 1

            gap_counter += 1
            gap_type = _status_to_gap_type(cr.status)
            severity = _ca_severity(cr.status, cr.catalogue_id)

            # Cap severity if no active exposure (unless foundationally critical)
            if not cr.active_exposure and cr.catalogue_id not in FOUNDATIONALLY_CRITICAL:
                if severity == Severity.CRITICAL:
                    severity = Severity.HIGH

            gaps.append(IdentityGap(
                id=f"GAP-CA-{gap_counter:03d}",
                domain=GapDomain.CA_POLICY,
                catalogue_ref=cr.catalogue_id,
                title=cr.catalogue_name,
                description=f"CA policy {cr.catalogue_id} is {cr.status.value}",
                severity=severity,
                gap_type=gap_type,
                active_exposure=cr.active_exposure,
                affected_entities=[cr.matched_tenant_policy] if cr.matched_tenant_policy else [],
                affected_count=cr.affected_user_count,
                evidence={
                    "status": cr.status.value,
                    "matched_policy": cr.matched_tenant_policy,
                    "match_confidence": cr.match_confidence,
                },
                compliance_notes=_build_ca_compliance_notes(cr),
            ))

        # CA coverage
        scorable = ca_enforced + ca_report_only + (ca_total - ca_enforced - ca_report_only)
        layer_coverages["ca"] = round(ca_enforced / scorable * 100, 1) if scorable > 0 else 0.0

        # ── Engine 2: generic control matching ───────────────────
        identity_catalogue = self._load_identity_catalogue()

        for layer_key, layer_def in identity_catalogue.items():
            domain = LAYER_TO_DOMAIN.get(layer_key)
            if not domain:
                continue

            ingestor_data = analysis_dict.get(layer_key, {})
            ingestor_key = layer_def.get("ingestor_key")
            if ingestor_key and ingestor_data:
                ingestor_data = ingestor_data.get(ingestor_key, {})

            controls = layer_def.get("controls", [])
            compliant_count = 0
            non_compliant_count = 0

            for ctrl in controls:
                result = _evaluate_control(ctrl, ingestor_data)

                if result["status"] == "compliant":
                    compliant_count += 1
                elif result["status"] == "non_compliant":
                    non_compliant_count += 1
                    gap_counter += 1

                    ctrl_severity = Severity(result.get("severity", "medium"))
                    active_exp = True  # Non-compliant controls are active by default

                    # Cap severity
                    ctrl_id = result["id"]
                    if not active_exp and ctrl_id not in FOUNDATIONALLY_CRITICAL:
                        if ctrl_severity == Severity.CRITICAL:
                            ctrl_severity = Severity.HIGH

                    gaps.append(IdentityGap(
                        id=f"GAP-{layer_key.upper()[:3]}-{gap_counter:03d}",
                        domain=domain,
                        catalogue_ref=ctrl_id,
                        title=result["title"],
                        description=result.get("description", ""),
                        severity=ctrl_severity,
                        gap_type=GapType.MISSING,
                        active_exposure=active_exp,
                        evidence={
                            "check_type": ctrl.get("check_type"),
                            "actual_value": result.get("actual_value"),
                            "expected": result.get("expected"),
                        },
                        compliance_notes={
                            "framework_controls": result.get("framework_controls", {}),
                            "category": layer_key,
                            "control_id": ctrl_id,
                        },
                    ))

            # Layer coverage
            scorable = compliant_count + non_compliant_count
            layer_coverages[layer_key] = (
                round(compliant_count / scorable * 100, 1) if scorable > 0 else 0.0
            )

        # Sort: missing first, then report_only, then disabled; by severity within
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
        type_order = {GapType.MISSING: 0, GapType.REPORT_ONLY: 1, GapType.DISABLED: 2, GapType.MISCONFIGURED: 3, GapType.INSUFFICIENT: 4}
        gaps.sort(key=lambda g: (type_order.get(g.gap_type, 9), severity_order.get(g.severity, 9)))

        return gaps, layer_coverages

    def _load_identity_catalogue(self) -> dict:
        path = self._catalogue_dir / "identity_catalogue.json"
        if not path.exists():
            logger.warning("Identity catalogue not found: %s", path)
            return {}
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            return data.get("layers", {})
        except Exception as exc:
            logger.warning("Failed to load identity catalogue: %s", exc)
            return {}


# ── Control evaluation engine ─────────────────────────────────────


def _resolve_data_path(data: dict, path: str) -> Any:
    """Resolve a dot-notation path into a nested dict."""
    if not data or not path:
        return None
    parts = path.split(".")
    current: Any = data
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
        if current is None:
            return None
    return current


def _evaluate_control(control: dict, data: dict) -> dict:
    """Evaluate a single catalogue control against ingestor data."""
    ctrl_id = control["id"]
    check_type = control.get("check_type", "boolean")
    data_path = control.get("data_path", "")
    severity = control.get("severity", "medium")
    fw = control.get("framework_controls", {})

    base = {
        "id": ctrl_id,
        "title": control.get("title", ""),
        "description": control.get("description", ""),
        "severity": severity,
        "framework_controls": fw,
    }

    actual = _resolve_data_path(data, data_path)

    if actual is None:
        return {**base, "status": "no_data", "actual_value": None, "expected": control.get("expected")}

    # boolean: value == expected
    if check_type == "boolean":
        expected = control.get("expected")
        compliant = actual == expected
        return {**base, "status": "compliant" if compliant else "non_compliant", "actual_value": actual, "expected": expected}

    # boolean_present: check_value in list
    if check_type == "boolean_present":
        check_value = control.get("check_value", "")
        compliant = check_value in actual if isinstance(actual, list) else str(actual) == str(check_value)
        return {**base, "status": "compliant" if compliant else "non_compliant", "actual_value": actual, "expected": f"contains '{check_value}'"}

    # boolean_absent: check_value NOT in list
    if check_type == "boolean_absent":
        check_value = control.get("check_value", "")
        compliant = check_value not in actual if isinstance(actual, list) else str(actual) != str(check_value)
        return {**base, "status": "compliant" if compliant else "non_compliant", "actual_value": actual, "expected": f"not contains '{check_value}'"}

    # threshold_gte: numeric >= expected
    if check_type == "threshold_gte":
        expected = control.get("expected", 0)
        try:
            compliant = float(actual) >= float(expected)
        except (ValueError, TypeError):
            return {**base, "status": "no_data", "actual_value": actual, "expected": f">= {expected}"}
        return {**base, "status": "compliant" if compliant else "non_compliant", "actual_value": actual, "expected": f">= {expected}"}

    # threshold_eq: numeric == expected
    if check_type == "threshold_eq":
        expected = control.get("expected", 0)
        try:
            compliant = float(actual) == float(expected)
        except (ValueError, TypeError):
            return {**base, "status": "no_data", "actual_value": actual, "expected": f"== {expected}"}
        return {**base, "status": "compliant" if compliant else "non_compliant", "actual_value": actual, "expected": f"== {expected}"}

    # count_eq: len(list) == expected
    if check_type == "count_eq":
        expected = control.get("expected", 0)
        actual_count = len(actual) if isinstance(actual, list) else actual
        try:
            compliant = float(actual_count) == float(expected)
        except (ValueError, TypeError):
            return {**base, "status": "no_data", "actual_value": actual_count, "expected": f"count == {expected}"}
        return {**base, "status": "compliant" if compliant else "non_compliant", "actual_value": actual_count, "expected": f"count == {expected}"}

    # enum: value is one of expected_values
    if check_type == "enum":
        expected_values = control.get("expected_values", [])
        compliant = actual in expected_values
        return {**base, "status": "compliant" if compliant else "non_compliant", "actual_value": actual, "expected": f"one of {expected_values}"}

    # all_true: all items in list have field == expected
    if check_type == "all_true":
        check_field = control.get("check_field", "")
        expected = control.get("expected", True)
        if not isinstance(actual, list) or len(actual) == 0:
            return {**base, "status": "no_data", "actual_value": actual, "expected": f"all {check_field} == {expected}"}
        all_match = all(
            item.get(check_field) == expected for item in actual if isinstance(item, dict)
        )
        return {**base, "status": "compliant" if all_match else "non_compliant", "actual_value": f"{len(actual)} items", "expected": f"all {check_field} == {expected}"}

    logger.warning("Unknown check_type '%s' for control %s", check_type, ctrl_id)
    return {**base, "status": "no_data", "actual_value": None, "expected": None}


# ── Gap helpers ───────────────────────────────────────────────────


def _status_to_gap_type(status: CAPolicyStatus) -> GapType:
    return {
        CAPolicyStatus.MISSING: GapType.MISSING,
        CAPolicyStatus.REPORT_ONLY: GapType.REPORT_ONLY,
        CAPolicyStatus.DISABLED: GapType.DISABLED,
        CAPolicyStatus.PARTIALLY_MATCHED: GapType.MISCONFIGURED,
    }.get(status, GapType.MISSING)


def _ca_severity(status: CAPolicyStatus, catalogue_id: str) -> Severity:
    """Assign severity based on CA policy status and importance."""
    if catalogue_id in FOUNDATIONALLY_CRITICAL:
        if status == CAPolicyStatus.MISSING:
            return Severity.CRITICAL
        return Severity.HIGH
    if status == CAPolicyStatus.MISSING:
        return Severity.HIGH
    if status == CAPolicyStatus.REPORT_ONLY:
        return Severity.MEDIUM
    return Severity.LOW


def _build_ca_compliance_notes(cr: CAPolicyResult) -> dict:
    """Build compliance_notes for a CA policy gap."""
    return {
        "category": "conditional_access",
        "control_id": cr.catalogue_id,
        "function": f"enforce_{cr.catalogue_id.lower()}",
        "scope": "tenant",
    }
