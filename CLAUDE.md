# CLAUDE.md — SecureSync by NEXO AI
> This file is the primary instruction set for Claude Code.
> Read ALL of it before writing a single line of code.

---

## Project Overview

**SecureSync** is an automated security audit platform for Swiss MSPs and MSSPs, built by **NEXO AI**.
It is a Lywand-inspired platform using open-source security tools as its scanning backbone,
orchestrated by a custom Python/TypeScript application layer.

**This is NOT a toy project.** It is production-bound, multi-tenant, and security-critical.
Every decision must reflect that.

---

## Read These Files First

Before implementing anything, read and internalize:

```
docs/tech-stack.md       → All technologies, versions, and why each was chosen
docs/features.md         → Full feature specification (what to build)
docs/architecture.md     → System design, data model, component interactions
docs/design.md           → UI/UX design system, colours, components
docs/sources.md          → Official documentation and API references for all tools
docs/phases.md           → Implementation roadmap (which phase you are in)
```

---

## Repository Structure

```
securesync/
├── CLAUDE.md                           ← you are here
├── docker-compose.yml                  ← full stack orchestration
├── docker-compose.dev.yml              ← dev overrides (hot reload)
├── .env                                ← secrets (never commit)
├── .env.example                        ← template (commit this)
├── .gitignore
├── nginx/
│   ├── nginx.conf
│   └── conf.d/
│       ├── platform.conf
│       └── wazuh.conf
├── docs/
│   ├── tech-stack.md
│   ├── features.md
│   ├── architecture.md
│   ├── design.md
│   ├── sources.md
│   └── phases.md
├── platform/                           ← FastAPI backend (Python)
│   ├── Dockerfile
│   ├── pyproject.toml
│   ├── alembic.ini
│   ├── alembic/
│   │   └── versions/
│   ├── app/
│   │   ├── main.py
│   │   ├── core/
│   │   │   ├── config.py               ← Pydantic Settings
│   │   │   ├── security.py             ← JWT, password hashing
│   │   │   ├── database.py             ← SQLAlchemy async engine
│   │   │   ├── celery_app.py           ← Celery factory
│   │   │   └── dependencies.py         ← FastAPI dependency injection
│   │   ├── api/
│   │   │   └── v1/
│   │   │       ├── router.py
│   │   │       ├── auth.py
│   │   │       ├── tenants.py
│   │   │       ├── assets.py
│   │   │       ├── scans.py
│   │   │       ├── findings.py
│   │   │       ├── ratings.py
│   │   │       ├── reports.py
│   │   │       └── webhooks.py
│   │   ├── models/                     ← SQLAlchemy ORM models
│   │   │   ├── base.py
│   │   │   ├── tenant.py
│   │   │   ├── user.py
│   │   │   ├── asset.py
│   │   │   ├── scan_job.py
│   │   │   ├── finding.py
│   │   │   └── rating.py
│   │   ├── schemas/                    ← Pydantic request/response schemas
│   │   │   ├── tenant.py
│   │   │   ├── scan.py
│   │   │   ├── finding.py
│   │   │   └── rating.py
│   │   ├── services/
│   │   │   ├── rating_engine.py        ← A–F score calculator
│   │   │   ├── normalizer.py           ← unified finding schema
│   │   │   └── report_generator.py     ← WeasyPrint PDF
│   │   ├── integrations/
│   │   │   ├── wazuh.py
│   │   │   ├── openvas.py
│   │   │   ├── zap.py
│   │   │   ├── nuclei.py
│   │   │   ├── defectdojo.py
│   │   │   ├── epss.py
│   │   │   ├── hibp.py
│   │   │   ├── nvd.py
│   │   │   └── ninjaone.py
│   │   └── tasks/
│   │       ├── scan_tasks.py           ← Celery task definitions
│   │       └── scheduler.py            ← APScheduler recurring jobs
│   └── tests/
│       ├── conftest.py
│       ├── unit/
│       └── integration/
├── frontend/                           ← Next.js 14 (TypeScript)
│   ├── Dockerfile
│   ├── package.json
│   ├── next.config.ts
│   ├── tailwind.config.ts
│   ├── tsconfig.json
│   ├── src/
│   │   ├── app/
│   │   │   ├── (dashboard)/
│   │   │   │   ├── layout.tsx
│   │   │   │   ├── page.tsx
│   │   │   │   ├── customers/
│   │   │   │   ├── scans/
│   │   │   │   ├── findings/
│   │   │   │   └── reports/
│   │   │   ├── (auth)/
│   │   │   │   ├── login/
│   │   │   │   └── layout.tsx
│   │   │   ├── api/
│   │   │   │   └── auth/[...nextauth]/route.ts
│   │   │   ├── layout.tsx
│   │   │   └── globals.css
│   │   ├── components/
│   │   │   ├── ui/                     ← shadcn/ui components
│   │   │   ├── RatingGauge/
│   │   │   ├── HouseAnalogy/
│   │   │   ├── FindingsTable/
│   │   │   ├── ScanWizard/
│   │   │   ├── TrendGraph/
│   │   │   └── ScanProgress/
│   │   ├── lib/
│   │   │   ├── api/                    ← TanStack Query hooks
│   │   │   ├── utils.ts
│   │   │   └── constants.ts
│   │   └── types/
│   │       └── index.ts
│   └── tests/
│       └── e2e/                        ← Playwright tests
├── oss-stack/                          ← OSS tool configs (no custom code)
│   ├── wazuh/
│   │   └── docker-compose.yml
│   ├── greenbone/
│   │   └── docker-compose.yml
│   ├── defectdojo/
│   │   └── docker-compose.yml
│   └── zap/
│       └── docker-compose.yml
└── .github/
    └── workflows/
        ├── ci.yml
        └── deploy.yml
```

---

## Coding Standards

### Python (Platform API)
- Python 3.12, fully typed (mypy strict where feasible)
- `ruff` for linting AND formatting (replaces black + flake8)
- All async: use `async def` everywhere in FastAPI routes + services
- SQLAlchemy 2.0 style: `select(Model).where(...)`, no legacy `query()`
- Pydantic v2: use `model_validator`, `field_validator` — not v1 patterns
- Every route must have a Pydantic response model — no `dict` returns
- Structured logging with `structlog` — no bare `print()` or `logging.info()`
- Retry logic on all external API calls via `tenacity`
- Never hardcode credentials — always via `app.core.config.Settings`

### TypeScript (Frontend)
- Next.js 14 App Router exclusively — no `pages/` directory
- Strict TypeScript: `"strict": true` in tsconfig
- All data fetching via TanStack Query — no raw `fetch()` in components
- shadcn/ui for all base components — don't reinvent buttons/inputs
- Tailwind for all styling — no inline styles, no CSS modules
- `zod` for all form validation
- Server Components by default — only add `"use client"` when needed

### Git Commit Messages
```
feat(scans): add nuclei integration with JSONL parsing
fix(rating): correct EPSS weight calculation
chore(deps): bump python-gvm to 24.1.0
test(api): add integration tests for scan endpoints
docs(arch): update component interaction diagrams
```

### Error Handling
- All external API calls: catch exceptions, log with structlog, return typed error response
- Never expose internal stack traces to API consumers
- Use custom exception classes in `app/core/exceptions.py`
- Frontend: TanStack Query error states + toast notifications

---

## Testing Requirements

### Python Tests (pytest)
Every file in `app/` must have corresponding tests in `tests/`.

```
tests/
├── conftest.py                ← shared fixtures (db, client, auth)
├── unit/
│   ├── test_rating_engine.py  ← test A–F calculation logic
│   ├── test_normalizer.py     ← test finding normalization
│   ├── test_epss_client.py    ← mock EPSS API responses
│   └── test_models.py         ← SQLAlchemy model validation
└── integration/
    ├── test_api_auth.py        ← login, token refresh, JWT validation
    ├── test_api_tenants.py     ← CRUD, multi-tenant isolation
    ├── test_api_scans.py       ← scan job creation, status polling
    ├── test_api_findings.py    ← finding CRUD, filtering
    └── test_api_reports.py     ← PDF generation
```

Run: `pytest --cov=app --cov-report=term-missing -v`
Target: **>= 80% coverage** on `app/services/` and `app/api/`

#### Key Test Cases (must exist):
- `test_tenant_isolation`: user A cannot access tenant B data
- `test_rating_calculation`: known input findings → expected A–F grade
- `test_finding_deduplication`: same CVE + same asset = one finding
- `test_external_api_retry`: EPSS API 429 → retry with backoff

### Frontend Tests (Playwright E2E)
```
tests/e2e/
├── auth.spec.ts          ← login, logout, session expiry
├── dashboard.spec.ts     ← KPI cards, customer list loads
├── scan.spec.ts          ← create scan, view progress, view results
├── findings.spec.ts      ← filter, status change, false positive
└── report.spec.ts        ← generate PDF, download works
```

Run: `npx playwright test`

---

## Environment Variables

All required vars are in `.env.example`. Never commit `.env`.
Load via `pydantic-settings` in `app/core/config.py`.

Critical vars:
```
DATABASE_URL, REDIS_URL, SECRET_KEY, JWT_ALGORITHM
WAZUH_API_URL, WAZUH_USERNAME, WAZUH_PASSWORD
GREENBONE_HOST, GREENBONE_USERNAME, GREENBONE_PASSWORD
ZAP_API_KEY, ZAP_URL
DEFECTDOJO_URL, DEFECTDOJO_API_KEY
EPSS_API_URL, NVD_API_KEY, HIBP_API_KEY
NINJAONE_CLIENT_ID, NINJAONE_CLIENT_SECRET, NINJAONE_API_URL
NEXTAUTH_SECRET, NEXTAUTH_URL
```

---

## Docker Rules

- Every service has its own `Dockerfile`
- Multi-stage builds for production images (builder + runtime)
- No `latest` tags in production — always pin versions
- `docker-compose.yml` = production config
- `docker-compose.dev.yml` = dev overrides (volume mounts, debug ports)
- Health checks on every service

---

## What NOT to Do

- ❌ Do not use `requests` library — use `httpx` (async)
- ❌ Do not use `flask` — this is a FastAPI project
- ❌ Do not use `pages/` router in Next.js — App Router only
- ❌ Do not write the Wazuh agent from scratch — it exists, deploy it
- ❌ Do not expose PostgreSQL, Redis, or scanner ports to the public internet
- ❌ Do not skip the multi-tenant isolation middleware
- ❌ Do not return raw SQLAlchemy model objects from API endpoints
- ❌ Do not commit `.env` or any secrets
- ❌ Do not use `any` in TypeScript — be explicit
- ❌ Do not use `print()` in Python — use `structlog`

---

## Phase Awareness

Always check `docs/phases.md` for the current phase.
Only implement features specified for the current phase.
Do not implement Phase 3 features when working on Phase 1.

When in doubt: **implement the simpler thing correctly** rather than the complex thing poorly.

---

## Integration Reference

When implementing any scanner integration, the pattern is:

```python
# app/integrations/example.py
import httpx
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential
from app.schemas.finding import NormalizedFinding

logger = structlog.get_logger()

class ExampleClient:
    def __init__(self, base_url: str, api_key: str):
        self.client = httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=30.0
        )

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def get_findings(self, target: str) -> list[NormalizedFinding]:
        try:
            response = await self.client.get(f"/scan/{target}")
            response.raise_for_status()
            return self._normalize(response.json())
        except httpx.HTTPStatusError as e:
            logger.error("example_api_error", status=e.response.status_code, target=target)
            raise

    def _normalize(self, raw: dict) -> list[NormalizedFinding]:
        # Always map to NormalizedFinding schema
        ...
```

---

## Rating Engine Contract

```python
# app/services/rating_engine.py

def calculate_rating(findings: list[NormalizedFinding], questionnaire: dict | None = None) -> Rating:
    """
    Input:  List of normalized findings + optional questionnaire responses
    Output: Rating object with overall_grade (A-F) and category scores (0-100)

    Weights:
      patch_management:    0.25
      network_exposure:    0.20
      web_security:        0.15
      endpoint_security:   0.15
      email_security:      0.10
      credential_exposure: 0.10
      ransomware_readiness: 0.05

    Grade thresholds:
      A: 90-100
      B: 75-89
      C: 60-74
      D: 45-59
      E: 25-44
      F: 0-24
    """
```

This is the core business logic. Test it exhaustively.
