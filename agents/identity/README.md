# Identity Security Agent

The first specialist in the Rippley Security Network. Performs automated posture
assessment of Microsoft Entra ID (Azure AD) tenants via Microsoft Graph API.

## What it does

1. **Ingest** — pulls identity configuration and telemetry from Graph API
2. **Analyse** — deterministically identifies gaps against a best-practice catalogue
3. **Score** — computes a 0–100 identity score with per-domain breakdown
4. **Recommend** — uses an LLM to enrich gaps with human-readable findings,
   remediation steps, and (where applicable) draft Conditional Access policies

## Required Graph API Permissions (Application)

| Permission | Type | Used by |
|---|---|---|
| `Policy.Read.All` | Application | Conditional Access, Authorization Policy, Security Defaults |
| `UserAuthenticationMethod.Read.All` | Application | MFA registration details, break glass MFA check |
| `RoleManagement.Read.All` | Application | Directory roles, PIM eligibility/assignment schedules, role management policies |
| `IdentityRiskyUser.Read.All` | Application | Risky users, break glass risk level (requires P2) |
| `AuditLog.Read.All` | Application | Sign-in logs |
| `Application.Read.All` | Application | App registrations, service principals |
| `User.Read.All` | Application | Guest users, privileged user immutableId (hybrid detection) |
| `AccessReview.Read.All` | Application | Access reviews (requires license) |
| `Directory.Read.All` | Application | Named locations, auth strengths, group membership |
| `Organization.Read.All` | Application | Tenant settings (LinkedIn integration) |
| `RoleManagementPolicy.Read.Directory` | Application | PIM activation policies (duration, MFA, approval) |

> **Least privilege**: register one app per agent. Do not share registrations
> across agents in the security network.

## Quick start

```bash
cd agents/identity
cp .env.template .env          # fill in credentials
pip install -e ".[dev]"
python scripts/run.py --tenant-id <TENANT_ID>
```

## Configuration

- `config/default.yaml` — main configuration (Graph API, auth, LLM, storage)
- `config/scoring_weights.yaml` — tunable scoring weights per domain

## Architecture

```
src/identity_agent/
  ingest/      — 9 Graph API ingestors (parallelised with asyncio.gather)
  analyse/     — deterministic gap analysis, CA policy matching, scoring
  recommend/   — LLM-enriched recommendations, CA policy drafting
  models/      — Pydantic v2 domain models
  output/      — SQLite persistence, JSON serialisation
```

## LLM Backend

The recommendation layer abstracts LLM access behind a `Protocol`:

```python
class LLMBackend(Protocol):
    async def complete(self, system: str, user: str) -> str: ...
```

`AnthropicBackend` is the default. A `LocalBackend` can be added for offline
client deployments where data cannot leave the network.
