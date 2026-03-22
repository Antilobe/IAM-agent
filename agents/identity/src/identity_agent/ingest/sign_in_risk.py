"""Ingestor: Sign-in risk policies and recent sign-in logs."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from identity_agent.ingest.base import BaseIngestor


class SignInRiskIngestor(BaseIngestor):
    async def ingest(self) -> dict[str, Any]:
        # CA policies filtered for risk conditions are derived from
        # ConditionalAccessIngestor data at the analysis layer.
        # Here we fetch raw sign-in logs for the last 7 days.
        cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
        sign_ins = await self._get_all_pages(
            f"/auditLogs/signIns?$filter=createdDateTime ge {cutoff}"
            "&$select=id,userPrincipalName,riskLevelDuringSignIn,"
            "riskLevelAggregated,riskState,status,createdDateTime"
        )
        return {"sign_ins_7d": sign_ins}
