"""Main orchestrator for the Identity Security Agent."""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from identity_agent.analyse.ca_matcher import CAMatcher
from identity_agent.analyse.gap_analyser import GapAnalyser
from identity_agent.analyse.scorer import Scorer
from identity_agent.analyse.signals import SignalBuilder
from identity_agent.auth import GraphAuthProvider
from identity_agent.config import AgentConfig
from identity_agent.ingest.access_reviews import AccessReviewsIngestor
from identity_agent.ingest.app_registrations import AppRegistrationsIngestor
from identity_agent.ingest.auth_methods import AuthMethodsIngestor
from identity_agent.ingest.base import BaseIngestor
from identity_agent.ingest.break_glass import BreakGlassIngestor
from identity_agent.ingest.conditional_access import ConditionalAccessIngestor
from identity_agent.ingest.directory_roles import DirectoryRolesIngestor
from identity_agent.ingest.guests import GuestsIngestor
from identity_agent.ingest.hardening import HardeningIngestor
from identity_agent.ingest.mfa_registration import MFARegistrationIngestor
from identity_agent.ingest.pim import PIMIngestor
from identity_agent.ingest.risky_users import RiskyUsersIngestor
from identity_agent.ingest.sign_in_risk import SignInRiskIngestor
from identity_agent.models.assessment import AssessmentMetadata, IdentityAssessment
from identity_agent.output.serialiser import AssessmentSerialiser
from identity_agent.output.store import SQLiteStore
from identity_agent.recommend.anthropic_backend import AnthropicBackend
from identity_agent.recommend.ca_drafter import CADrafter
from identity_agent.recommend.generator import RecommendationGenerator
from identity_agent.recommend.pim_drafter import PIMDrafter

logger = logging.getLogger(__name__)

# Map ingestor class to result key
INGESTOR_REGISTRY: list[tuple[str, type[BaseIngestor]]] = [
    ("conditional_access", ConditionalAccessIngestor),
    ("mfa_registration", MFARegistrationIngestor),
    ("directory_roles", DirectoryRolesIngestor),
    ("risky_users", RiskyUsersIngestor),
    ("sign_in_risk", SignInRiskIngestor),
    ("pim", PIMIngestor),
    ("app_registrations", AppRegistrationsIngestor),
    ("guests", GuestsIngestor),
    ("access_reviews", AccessReviewsIngestor),
    ("auth_methods", AuthMethodsIngestor),
    ("break_glass", BreakGlassIngestor),
    ("hardening", HardeningIngestor),
]


class IdentityAgent:
    """Orchestrates ingest -> analyse -> recommend pipeline."""

    def __init__(self, config: AgentConfig) -> None:
        self._config = config
        self._catalogue_dir = (
            Path(__file__).parent.parent.parent / "catalogues"
        )

    async def run(self) -> dict[str, Any]:
        """Execute a full identity assessment. Returns serialised IdentityAssessment."""
        t0 = time.perf_counter()
        errors: list[str] = []
        warnings: list[str] = []

        # ── 1. Auth ──────────────────────────────────────────────
        auth = GraphAuthProvider(
            tenant_id=self._config.tenant_id,
            client_id=self._config.auth.client_id,
            client_secret=self._config.auth.client_secret,
        )

        # ── 2. Ingest (parallel) ─────────────────────────────────
        logger.info("Starting ingest phase (%d ingestors)", len(INGESTOR_REGISTRY))
        t_ingest = time.perf_counter()

        ingestors: list[tuple[str, BaseIngestor]] = []
        for name, cls in INGESTOR_REGISTRY:
            ingestors.append((
                name,
                cls(
                    auth=auth,
                    base_url=self._config.graph_api.base_url,
                    beta_url=self._config.graph_api.beta_url,
                    timeout=self._config.graph_api.timeout_seconds,
                    max_retries=self._config.graph_api.max_retries,
                    page_size=self._config.graph_api.page_size,
                ),
            ))

        results = await asyncio.gather(
            *(ing.ingest() for _, ing in ingestors),
            return_exceptions=True,
        )

        raw_data: dict[str, dict] = {}
        total_api_calls = 0
        ingestors_run: list[str] = []

        for (name, ing), result in zip(ingestors, results):
            if isinstance(result, Exception):
                msg = f"{name}: ingest failed: {result}"
                logger.error(msg)
                errors.append(msg)
                raw_data[name] = {}
            else:
                raw_data[name] = result
            total_api_calls += ing.api_calls
            errors.extend(ing.errors)
            ingestors_run.append(ing.name)

        logger.info("Ingest complete in %.1fs (%d API calls)", time.perf_counter() - t_ingest, total_api_calls)

        # Detect P2 license
        p2_detected = (
            raw_data.get("pim", {}).get("available", False)
            or raw_data.get("risky_users", {}).get("available", False)
        )

        # ── 3. Build signals ─────────────────────────────────────
        signal_builder = SignalBuilder()
        signals = signal_builder.build(raw_data)
        analysis_dict = signal_builder.build_analysis_dict(raw_data)

        # ── 4. CA matching ───────────────────────────────────────
        ca_matcher = CAMatcher(catalogue_dir=self._catalogue_dir)
        tenant_policies = raw_data.get("conditional_access", {}).get("policies", [])
        ca_results = ca_matcher.match(tenant_policies, signals)

        # ── 5. Gap analysis ──────────────────────────────────────
        gap_analyser = GapAnalyser(catalogue_dir=self._catalogue_dir)
        gaps, layer_coverages = gap_analyser.analyse(signals, ca_results, analysis_dict)

        # ── 6. Scoring ───────────────────────────────────────────
        scorer = Scorer()
        identity_score, breakdown = scorer.score(signals, gaps, ca_results, layer_coverages)

        # ── 7. Recommendations (LLM) ────────────────────────────
        try:
            llm = AnthropicBackend(
                model=self._config.llm.model,
                max_tokens=self._config.llm.max_tokens,
            )
            generator = RecommendationGenerator(llm)
            recommendations = await generator.generate(gaps, signals)

            # Attach CA policy drafts for missing CA policy gaps
            ca_drafter = CADrafter(llm=llm, catalogue_dir=self._catalogue_dir)
            pim_drafter = PIMDrafter()
            for rec in recommendations:
                for gap_id in rec.gap_ids:
                    matching = [g for g in gaps if g.id == gap_id]
                    if not matching:
                        continue
                    gap = matching[0]

                    # CA policy drafts
                    if rec.ca_policy_draft is None and gap.domain.value == "ca_policy" and gap.gap_type.value == "missing":
                        draft = await ca_drafter.draft(gap)
                        if draft:
                            rec.ca_policy_draft = draft
                        break

                    # PIM policy drafts
                    if rec.pim_policy_draft is None and gap.domain.value == "pim":
                        draft = pim_drafter.draft(gap)
                        if draft:
                            rec.pim_policy_draft = draft
                        operator_input = pim_drafter.get_required_operator_input(gap)
                        if operator_input:
                            rec.required_operator_input = operator_input
                        break
        except Exception as exc:
            msg = f"Recommendation generation failed: {exc}"
            logger.error(msg)
            errors.append(msg)
            recommendations = []

        # ── 8. Assemble assessment ───────────────────────────────
        assessment = IdentityAssessment(
            tenant_id=self._config.tenant_id,
            timestamp=datetime.now(timezone.utc),
            identity_score=identity_score,
            scoring_breakdown=breakdown,
            ca_policy_results=ca_results,
            signals=signals,
            gaps=gaps,
            recommendations=recommendations,
            metadata=AssessmentMetadata(
                duration_seconds=round(time.perf_counter() - t0, 2),
                api_calls_made=total_api_calls,
                errors=errors,
                warnings=warnings,
                ingestors_run=ingestors_run,
                p2_license_detected=p2_detected,
            ),
        )

        # ── 9. Store ─────────────────────────────────────────────
        try:
            store = SQLiteStore(self._config.storage.sqlite_path)
            await store.save(assessment)
        except Exception as exc:
            logger.warning("Failed to save assessment: %s", exc)

        logger.info(
            "Assessment complete: score=%.1f, gaps=%d, recommendations=%d (%.1fs)",
            identity_score, len(gaps), len(recommendations),
            time.perf_counter() - t0,
        )

        return AssessmentSerialiser.to_dict(assessment)
