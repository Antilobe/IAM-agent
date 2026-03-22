"""Tests for SQLite assessment store."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from identity_agent.models.assessment import (
    AssessmentMetadata,
    IdentityAssessment,
    ScoringBreakdown,
)
from identity_agent.output.store import SQLiteStore


@pytest.fixture
def sample_assessment() -> IdentityAssessment:
    return IdentityAssessment(
        tenant_id="test-tenant-001",
        timestamp=datetime(2026, 3, 22, 12, 0, 0, tzinfo=timezone.utc),
        identity_score=75.5,
        scoring_breakdown=ScoringBreakdown(ca_policy_score=80.0, mfa_score=70.0),
        metadata=AssessmentMetadata(agent_version="0.1.0"),
    )


class TestSQLiteStore:
    @pytest.mark.asyncio
    async def test_save_and_load(self, tmp_path, sample_assessment: IdentityAssessment) -> None:
        db_path = str(tmp_path / "test.db")
        store = SQLiteStore(db_path)

        assessment_id = await store.save(sample_assessment)
        assert assessment_id is not None

        loaded = await store.load(assessment_id)
        assert loaded is not None
        assert loaded.tenant_id == "test-tenant-001"
        assert loaded.identity_score == 75.5

    @pytest.mark.asyncio
    async def test_load_nonexistent(self, tmp_path) -> None:
        store = SQLiteStore(str(tmp_path / "test.db"))
        result = await store.load("nonexistent-id")
        assert result is None

    @pytest.mark.asyncio
    async def test_list_assessments(self, tmp_path, sample_assessment: IdentityAssessment) -> None:
        db_path = str(tmp_path / "test.db")
        store = SQLiteStore(db_path)

        await store.save(sample_assessment)
        await store.save(sample_assessment)

        results = await store.list_assessments("test-tenant-001")
        assert len(results) == 2
        assert all(r["identity_score"] == 75.5 for r in results)

    @pytest.mark.asyncio
    async def test_list_with_limit(self, tmp_path, sample_assessment: IdentityAssessment) -> None:
        db_path = str(tmp_path / "test.db")
        store = SQLiteStore(db_path)

        for _ in range(5):
            await store.save(sample_assessment)

        results = await store.list_assessments("test-tenant-001", limit=3)
        assert len(results) == 3
