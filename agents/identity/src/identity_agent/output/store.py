"""Persistence layer — SQLite behind an interface for future swap."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, runtime_checkable

import aiosqlite

from identity_agent.models.assessment import IdentityAssessment
from identity_agent.output.serialiser import AssessmentSerialiser


@runtime_checkable
class AssessmentStore(Protocol):
    """Storage interface — implement for SQLite, Azure Table Storage, Cosmos DB, etc."""

    async def save(self, assessment: IdentityAssessment) -> str: ...
    async def load(self, assessment_id: str) -> IdentityAssessment | None: ...
    async def list_assessments(self, tenant_id: str, limit: int = 10) -> list[dict]: ...


_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS assessments (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    identity_score REAL NOT NULL,
    assessment_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

_INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_tenant_ts ON assessments(tenant_id, timestamp DESC);
"""


class SQLiteStore:
    """SQLite implementation of AssessmentStore."""

    def __init__(self, db_path: str = "./data/identity_agent.db") -> None:
        self._db_path = db_path
        self._tables_created = False

    async def _ensure_tables(self, db: aiosqlite.Connection) -> None:
        if not self._tables_created:
            await db.execute(_CREATE_SQL)
            await db.execute(_INDEX_SQL)
            await db.commit()
            self._tables_created = True

    async def save(self, assessment: IdentityAssessment) -> str:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        assessment_id = str(uuid.uuid4())

        async with aiosqlite.connect(self._db_path) as db:
            await self._ensure_tables(db)
            await db.execute(
                "INSERT INTO assessments (id, tenant_id, timestamp, identity_score, assessment_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    assessment_id,
                    assessment.tenant_id,
                    assessment.timestamp.isoformat(),
                    assessment.identity_score,
                    AssessmentSerialiser.to_json(assessment),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            await db.commit()

        return assessment_id

    async def load(self, assessment_id: str) -> IdentityAssessment | None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)

        async with aiosqlite.connect(self._db_path) as db:
            await self._ensure_tables(db)
            cursor = await db.execute(
                "SELECT assessment_json FROM assessments WHERE id = ?",
                (assessment_id,),
            )
            row = await cursor.fetchone()

        if row is None:
            return None
        return AssessmentSerialiser.from_json(row[0])

    async def list_assessments(self, tenant_id: str, limit: int = 10) -> list[dict]:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)

        async with aiosqlite.connect(self._db_path) as db:
            await self._ensure_tables(db)
            cursor = await db.execute(
                "SELECT id, timestamp, identity_score FROM assessments "
                "WHERE tenant_id = ? ORDER BY timestamp DESC LIMIT ?",
                (tenant_id, limit),
            )
            rows = await cursor.fetchall()

        return [
            {"id": r[0], "timestamp": r[1], "identity_score": r[2]}
            for r in rows
        ]
