"""Draft Conditional Access policies for missing CA policy gaps.

Two modes:
1. Deterministic: well-known block policies (CAP001-004) — no LLM needed
2. LLM-based: complex policies — prompt LLM with catalogue context

Draft policies are ALWAYS set to reportOnly state.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from identity_agent.models.gaps import IdentityGap

logger = logging.getLogger(__name__)


# Well-known deterministic policy drafts (CAP block policies)
DETERMINISTIC_DRAFTS: dict[str, dict] = {
    "CAP001": {
        "displayName": "CAP001-All-BlockLegacyAuthentication-v1.0",
        "state": "enabledForReportingButNotEnforced",
        "conditions": {
            "users": {"includeUsers": ["All"], "excludeGroups": []},
            "applications": {"includeApplications": ["All"]},
            "clientAppTypes": ["exchangeActiveSync", "other"],
        },
        "grantControls": {"operator": "OR", "builtInControls": ["block"]},
    },
    "CAP002": {
        "displayName": "CAP002-All-BlockExchangeActiveSync-v1.0",
        "state": "enabledForReportingButNotEnforced",
        "conditions": {
            "users": {"includeUsers": ["All"], "excludeGroups": []},
            "applications": {"includeApplications": ["All"]},
            "clientAppTypes": ["exchangeActiveSync"],
        },
        "grantControls": {"operator": "OR", "builtInControls": ["block"]},
    },
    "CAP003": {
        "displayName": "CAP003-All-BlockDeviceCodeFlow-v1.0",
        "state": "enabledForReportingButNotEnforced",
        "conditions": {
            "users": {"includeUsers": ["All"], "excludeGroups": []},
            "applications": {"includeApplications": ["All"]},
            "clientAppTypes": ["all"],
            "authenticationFlows": {"transferMethods": "deviceCodeFlow"},
        },
        "grantControls": {"operator": "OR", "builtInControls": ["block"]},
    },
    "CAP004": {
        "displayName": "CAP004-All-BlockAuthenticationTransfer-v1.0",
        "state": "enabledForReportingButNotEnforced",
        "conditions": {
            "users": {"includeUsers": ["All"], "excludeGroups": []},
            "applications": {"includeApplications": ["All"]},
            "clientAppTypes": ["all"],
            "authenticationFlows": {"transferMethods": "authenticationTransfer"},
        },
        "grantControls": {"operator": "OR", "builtInControls": ["block"]},
    },
}

LLM_SYSTEM_PROMPT = """You are a Microsoft 365 Conditional Access specialist.
Given a missing catalogue CA policy and its description, generate a complete
Microsoft Graph API POST body for deploying this policy.

RULES:
- state MUST be "enabledForReportingButNotEnforced" (report-only)
- displayName MUST match the catalogue policy name exactly
- Return a single JSON object (the policy_body), no markdown fences
- Use valid Graph API enums for builtInControls, clientAppTypes, etc.
"""


class CADrafter:
    """Generates draft CA policy JSON for missing CA policies."""

    def __init__(
        self,
        llm: Any | None = None,
        catalogue_dir: Path | None = None,
    ) -> None:
        self._llm = llm
        self._catalogue_dir = catalogue_dir

    async def draft(self, gap: IdentityGap) -> dict | None:
        """Generate a draft CA policy for a missing CA policy gap.

        Returns the policy body dict, or None if drafting fails.
        """
        catalogue_ref = gap.catalogue_ref
        if not catalogue_ref:
            return None

        # Try deterministic first
        if catalogue_ref in DETERMINISTIC_DRAFTS:
            return DETERMINISTIC_DRAFTS[catalogue_ref].copy()

        # LLM-based drafting
        if self._llm is None:
            return None

        return await self._llm_draft(gap)

    async def _llm_draft(self, gap: IdentityGap) -> dict | None:
        """Use LLM to generate a CA policy draft."""
        user_prompt = (
            f"Generate a Graph API POST body for this missing Conditional Access policy:\n\n"
            f"Catalogue ID: {gap.catalogue_ref}\n"
            f"Policy name: {gap.title}\n"
            f"Description: {gap.description}\n"
            f"Severity: {gap.severity.value}\n\n"
            f"The displayName must be exactly: {gap.title}\n"
            f"The state must be: enabledForReportingButNotEnforced"
        )

        try:
            raw = await self._llm.complete(system=LLM_SYSTEM_PROMPT, user=user_prompt)
            draft = self._parse_and_validate(raw, gap.title)
            return draft
        except Exception as exc:
            logger.warning("LLM CA draft failed for %s: %s", gap.catalogue_ref, exc)
            return None

    def _parse_and_validate(self, raw: str, expected_name: str) -> dict | None:
        """Parse LLM output and validate the policy draft."""
        cleaned = re.sub(r"```(?:json)?\s*", "", raw).strip()
        cleaned = re.sub(r"```\s*$", "", cleaned).strip()

        try:
            draft = json.loads(cleaned)
        except json.JSONDecodeError:
            # Try to extract JSON object
            match = re.search(r"\{[\s\S]*\}", cleaned)
            if match:
                try:
                    draft = json.loads(match.group())
                except json.JSONDecodeError:
                    return None
            else:
                return None

        if not isinstance(draft, dict):
            return None

        # Validate required fields
        if draft.get("state") != "enabledForReportingButNotEnforced":
            draft["state"] = "enabledForReportingButNotEnforced"

        if "conditions" not in draft:
            return None

        return draft
