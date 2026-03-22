"""Match tenant CA policies against the best-practice catalogue.

Engine 1: semantic/structural matching adapted from Security-Agent's
identity_gap_analyser.py. Prevents one-to-many matching.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from identity_agent.models.assessment import CAPolicyResult, CAPolicyStatus
from identity_agent.models.signals import IdentitySignals

logger = logging.getLogger(__name__)

# CIS Implementation Group inheritance
IG_LEVELS = {"IG1": ["IG1"], "IG2": ["IG1", "IG2"], "IG3": ["IG1", "IG2", "IG3"]}
LAYER_DEFAULT_IG = {"foundation": "IG1", "hardening": "IG2"}


class CAMatcher:
    """Loads the CA policy catalogue and matches each entry against tenant policies."""

    def __init__(self, catalogue_dir: Path | None = None, target_ig: str = "IG1") -> None:
        self._catalogue_dir = catalogue_dir or (
            Path(__file__).parent.parent.parent.parent / "catalogues"
        )
        self._target_ig = target_ig

    def match(
        self,
        tenant_policies: list[dict],
        signals: IdentitySignals | None = None,
    ) -> list[CAPolicyResult]:
        """Match catalogue CA policies against tenant policies."""
        catalogue = self._load_catalogue()
        if not catalogue:
            logger.warning("No catalogue policies loaded")
            return []

        claimed: set[str] = set()
        results: list[CAPolicyResult] = []

        for cat_policy in catalogue:
            result = self._match_one(cat_policy, tenant_policies, claimed, signals)
            results.append(result)

        return results

    def _load_catalogue(self) -> list[dict]:
        """Load and flatten CA catalogue filtered by target IG."""
        path = self._catalogue_dir / "ca_catalogue.json"
        if not path.exists():
            logger.warning("CA catalogue not found: %s", path)
            return []

        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        active_igs = IG_LEVELS.get(self._target_ig, ["IG1"])
        policies = []
        for layer_key, layer in data.get("layers", {}).items():
            default_ig = LAYER_DEFAULT_IG.get(layer_key, "IG1")
            for p in layer.get("policies", []):
                policy_ig = p.get("cis_ig", default_ig)
                if policy_ig in active_igs:
                    policies.append({
                        "id": p.get("id", ""),
                        "name": p.get("name", ""),
                        "title": p.get("title", ""),
                        "target": p.get("target", ""),
                        "default_state": p.get("default_state", ""),
                        "prerequisites": p.get("prerequisites", []),
                        "framework_controls": p.get("framework_controls", {}),
                        "layer": layer_key,
                    })
        return policies

    def _match_one(
        self,
        cat_policy: dict,
        tenant_policies: list[dict],
        claimed: set[str],
        signals: IdentitySignals | None,
    ) -> CAPolicyResult:
        cat_id = cat_policy["id"]
        cat_name = cat_policy["name"]

        # 1. Exact name match
        for tp in tenant_policies:
            tp_name = tp.get("displayName", tp.get("name", ""))
            if tp_name == cat_name and tp_name not in claimed:
                claimed.add(tp_name)
                status = _state_to_status(tp.get("state", ""))
                return CAPolicyResult(
                    catalogue_id=cat_id,
                    catalogue_name=cat_name,
                    status=status,
                    matched_tenant_policy=tp_name,
                    match_confidence=1.0,
                    scope_coverage={},
                    active_exposure=_has_active_exposure(cat_policy, status, signals),
                )

        # 2. Semantic / structural match
        available = [
            tp for tp in tenant_policies
            if tp.get("displayName", tp.get("name", "")) not in claimed
        ]
        best_tp, best_score = self._semantic_match(cat_policy, available)
        if best_tp and best_score >= 3:
            tp_name = best_tp.get("displayName", best_tp.get("name", ""))
            claimed.add(tp_name)
            status = _state_to_status(best_tp.get("state", ""))
            confidence = min(best_score / 6.0, 1.0)
            return CAPolicyResult(
                catalogue_id=cat_id,
                catalogue_name=cat_name,
                status=status,
                matched_tenant_policy=tp_name,
                match_confidence=round(confidence, 2),
                scope_coverage={},
                active_exposure=_has_active_exposure(cat_policy, status, signals),
            )

        # 3. Missing
        return CAPolicyResult(
            catalogue_id=cat_id,
            catalogue_name=cat_name,
            status=CAPolicyStatus.MISSING,
            matched_tenant_policy=None,
            match_confidence=0.0,
            scope_coverage={},
            active_exposure=_has_active_exposure(cat_policy, CAPolicyStatus.MISSING, signals),
        )

    def _semantic_match(
        self, cat_policy: dict, tenant_policies: list[dict]
    ) -> tuple[dict | None, int]:
        """Score tenant policies against a catalogue entry. Return best match + score."""
        cat_id = cat_policy["id"]
        cat_title_lower = cat_policy.get("title", "").lower()
        keywords = _extract_keywords(cat_title_lower)

        best_score = 0
        best_tp = None

        for tp in tenant_policies:
            has_structure = tp.get("conditions") or tp.get("grantControls")
            if has_structure:
                score = _structural_match_score(cat_policy, tp)
            else:
                tp_name = (tp.get("displayName", tp.get("name", "")) or "").lower()
                score = _keyword_match_score(keywords, tp_name, cat_id)

            if score > best_score:
                best_score = score
                best_tp = tp

        return best_tp, best_score


# ── Helpers ───────────────────────────────────────────────────────


def _state_to_status(state: str) -> CAPolicyStatus:
    state_lower = state.lower().strip()
    if state_lower in ("enabled", "on"):
        return CAPolicyStatus.ENFORCED
    if state_lower in ("enabledforreportingbutnotenforced", "report-only", "reportonly"):
        return CAPolicyStatus.REPORT_ONLY
    if state_lower in ("disabled", "off"):
        return CAPolicyStatus.DISABLED
    return CAPolicyStatus.DISABLED


def _extract_keywords(title: str) -> set[str]:
    """Extract meaningful keywords from a CA policy title."""
    stopwords = {"for", "all", "the", "a", "an", "and", "or", "on", "to", "in", "of", "—", "-", "–"}
    words = set(re.findall(r"\w+", title.lower()))
    return words - stopwords


def _keyword_match_score(keywords: set[str], tp_name: str, cat_id: str) -> int:
    """Fallback keyword matching when no structural data available."""
    tp_words = set(re.findall(r"\w+", tp_name.lower()))
    overlap = keywords & tp_words
    return len(overlap)


def _structural_match_score(cat_policy: dict, tp: dict) -> int:
    """Score how well a tenant policy structurally matches a catalogue entry."""
    cat_id = cat_policy["id"]
    cat_title_lower = cat_policy.get("title", "").lower()
    score = 0

    conditions = tp.get("conditions", {}) or {}
    grant_controls = tp.get("grantControls", {}) or {}
    builtin = [c.lower() for c in (grant_controls.get("builtInControls", []) or [])]
    session = tp.get("sessionControls", {}) or {}

    users = conditions.get("users", {}) or {}
    client_app_types = conditions.get("clientAppTypes", []) or []
    risk_levels = conditions.get("signInRiskLevels", []) or []
    user_risk = conditions.get("userRiskLevels", []) or []
    include_users = users.get("includeUsers", []) or []
    include_roles = users.get("includeRoles", []) or []

    # Block policies (CAP*)
    if cat_id.startswith("CAP"):
        if "block" in builtin:
            score += 2
        if "legacy" in cat_title_lower and "exchangeActiveSync" in str(client_app_types):
            score += 2
        if "device code" in cat_title_lower:
            auth_flows = conditions.get("authenticationFlows", {})
            if auth_flows:
                score += 2

    # MFA policies
    if "mfa" in cat_title_lower or "multi-factor" in cat_title_lower:
        if "mfa" in builtin:
            score += 2
        # Scope: all users vs admins
        if "admin" in cat_title_lower and include_roles:
            score += 2
        elif "all users" in cat_title_lower.replace("all user", "all users") and "All" in include_users:
            score += 2
        elif "guest" in cat_title_lower:
            include_guests = users.get("includeGuestsOrExternalUsers", {})
            if include_guests:
                score += 2

    # Risk policies
    if "risk" in cat_title_lower:
        if "sign-in" in cat_title_lower or "sign in" in cat_title_lower:
            if risk_levels:
                score += 3
        if "user" in cat_title_lower and "risk" in cat_title_lower:
            if user_risk:
                score += 3

    # Session controls
    if "session" in cat_title_lower or "frequency" in cat_title_lower or "timeout" in cat_title_lower:
        if session.get("signInFrequency"):
            score += 2
    if "persistence" in cat_title_lower or "browser" in cat_title_lower:
        if session.get("persistentBrowser"):
            score += 2

    # Device compliance
    if "compliant" in cat_title_lower or "device" in cat_title_lower:
        if "compliantDevice" in builtin:
            score += 2

    # Location
    if "location" in cat_title_lower or "country" in cat_title_lower or "countries" in cat_title_lower:
        if conditions.get("locations"):
            score += 2

    # Keyword bonus from display name
    keywords = _extract_keywords(cat_title_lower)
    tp_name = (tp.get("displayName", "") or "").lower()
    tp_words = set(re.findall(r"\w+", tp_name))
    overlap = keywords & tp_words
    if len(overlap) >= 2:
        score += 1

    return score


def _has_active_exposure(
    cat_policy: dict,
    status: CAPolicyStatus,
    signals: IdentitySignals | None,
) -> bool:
    """Determine if a gap has active exposure based on signals."""
    if status == CAPolicyStatus.ENFORCED:
        return False

    if signals is None:
        return True  # Conservative default

    cat_title = cat_policy.get("title", "").lower()
    cat_target = cat_policy.get("target", "").lower()

    # Guest-scoped policies: no exposure if no guests
    if "guest" in cat_title or "guest" in cat_target:
        if signals.guest.total_guests == 0:
            return False

    # MFA: active exposure if users exist without MFA
    if "mfa" in cat_title:
        if signals.mfa.total_users > 0 and signals.mfa.mfa_registered < signals.mfa.total_users:
            return True
        if signals.mfa.total_users == 0:
            return False

    # Risk: active exposure if risky users/sign-ins exist
    if "risk" in cat_title:
        if signals.risk.risky_users_high > 0 or signals.risk.high_risk_sign_ins_7d > 0:
            return True
        return False

    # Default: active exposure for missing/report-only
    return status in (CAPolicyStatus.MISSING, CAPolicyStatus.REPORT_ONLY)
