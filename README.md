# SecureSync

**Automated security-audit platform for Swiss MSPs / MSSPs — by [NEXO AI](https://nexo-ai.ch).**

SecureSync is a Lywand-inspired, open-source-stack security-audit platform.
A thin Python/TypeScript orchestration layer sits on top of battle-tested
OSS scanners (Wazuh, Greenbone/OpenVAS, OWASP ZAP, Nuclei, DefectDojo),
enriches findings with EPSS and HIBP data, and produces white-labelled PDF
reports per customer.

---

## Features

- **Multi-tenant:** MSP → customer hierarchy, per-tenant RBAC
  (platform_admin, msp_admin, msp_technician, customer_readonly).
- **Four scan types:** external network (OpenVAS), web application (ZAP),
  fast template (Nuclei), endpoint agent (Wazuh).
- **Dedup across scanners** via DefectDojo.
- **Enrichment:** EPSS (FIRST.org) for exploitation probability,
  HIBP for credential breach exposure.
- **A–F security rating** — 7 weighted categories, tenant-wide, trend
  history per scan.
- **PDF reports:** customer-facing Executive + MSP-internal Technical.
- **White-label custom domains** with DNS-TXT verification + Let's Encrypt.
- **Scheduled scans:** per-tenant cron + maintenance-window blackouts.
- **RMM sync:** auto-tickets Critical/High findings into NinjaOne.
- **Hardening:** per-IP rate-limit, append-only audit log, strict CSP,
  HSTS, Sentry for errors + APM.

---

## Architecture at a glance

```
┌──────────────────────┐   ┌──────────────────────┐
│   Next.js frontend   │   │   Wazuh Agents       │
│   (port 3000)        │   │   (customer hosts)   │
└──────────┬───────────┘   └──────────┬───────────┘
           │ HTTPS                     │ 1514 / 1515
           ▼                           ▼
┌─────────────────────────────────────────────────┐
│                 Nginx (443)                      │
│  + per-tenant white-label vhosts                 │
└──────────┬──────────────────────┬────────────────┘
           │                      │
           ▼                      ▼
┌──────────────────┐   ┌─────────────────────────┐
│  FastAPI API     │   │   Scanner cluster        │
│  Celery worker   │   │   OpenVAS / ZAP /        │
│  Celery beat     │   │   Nuclei / Wazuh /       │
│                  │   │   DefectDojo             │
└────┬────┬────────┘   └─────────────────────────┘
     │    │
     ▼    ▼
  Postgres  Redis
   (16)     (7)
```

Full diagram + component interactions: [docs/architecture.md](docs/architecture.md).

---

## Project layout

```
securesync/
├── platform/          FastAPI API + Celery tasks + templates + tests
├── frontend/          Next.js 14 (App Router) — scaffolded separately
├── oss-stack/         Docker Compose for Wazuh, Greenbone, DefectDojo, ZAP
├── nginx/             Reverse proxy config + per-tenant vhost template
├── infra/nginx/       Vhost generator + certbot helpers
├── docs/              tech-stack, features, architecture, design, mocks
├── .github/workflows/ CI (tests + lint) + Deploy (build + SSH)
└── docker-compose.yml Production stack composition
```

---

## Quickstart — local development

**Prerequisites:** Python 3.12, Docker, Node 20 (for frontend), uv (recommended).

1. **Clone + env:**
   ```bash
   git clone <this-repo>
   cd securesync
   cp .env.example .env
   # Fill in SECRET_KEY, POSTGRES_PASSWORD, REDIS_PASSWORD, NEXTAUTH_SECRET at minimum:
   #   openssl rand -hex 32
   ```

2. **Bring up Postgres + Redis:**
   ```bash
   docker compose -f docker-compose.dev.yml up -d
   # Dev-compose maps Postgres → host :55432 and Redis → host :56379 so a
   # system Postgres on :5432 can't steal the connection.
   ```

3. **Backend setup:**
   ```bash
   cd platform
   uv venv .venv
   uv pip install -e ".[dev]"

   # Apply migrations
   DATABASE_URL="postgresql+psycopg://securesync:<your-password>@127.0.0.1:55432/securesync" \
   SECRET_KEY=<hex32> REDIS_URL="redis://:<your-password>@127.0.0.1:56379/0" \
   python -m alembic upgrade head

   # Seed initial MSP + platform admin (prints random password to stdout)
   python -m scripts.seed

   # Start the dev server — Windows-friendly launcher
   python run_dev.py             # http://localhost:8000/docs
   ```

4. **Frontend setup** (first-time scaffold, one-off):
   ```bash
   cd frontend
   npx create-next-app@14 . --typescript --tailwind --app --src-dir --eslint --import-alias "@/*"
   npx shadcn@latest init
   npm install @tanstack/react-query@5 recharts@2 framer-motion@11 react-hook-form@7 zod@3 next-auth@5 lucide-react
   npm install -D @playwright/test && npx playwright install --with-deps
   npm run dev                    # http://localhost:3000
   ```

5. **Optional — scanner containers:**
   ```bash
   docker compose -f oss-stack/greenbone/docker-compose.yml up -d  # ~1 GB, ~30 min feed sync
   docker compose -f oss-stack/wazuh/docker-compose.yml up -d      # ~2 GB RAM
   ```

---

## Configuration

All runtime config is read from environment variables by Pydantic Settings
in [platform/app/core/config.py](platform/app/core/config.py). The template
is [.env.example](.env.example) — copy to `.env` and fill in. The
`.gitignore` covers `.env` and `.env.*` so the file stays local-only.

**Required for dev:**
- `SECRET_KEY` (≥ 32 chars)
- `POSTGRES_PASSWORD`
- `REDIS_PASSWORD`
- `DATABASE_URL` / `REDIS_URL` (derived from the above)

**Required for production:** all of the above + `NEXTAUTH_SECRET`,
`WAZUH_PASSWORD`, `GREENBONE_PASSWORD`, `ZAP_API_KEY`, `DEFECTDOJO_*`,
`SENTRY_DSN_BACKEND`, etc.

**Per-feature optional:** NinjaOne credentials, HIBP API key, SMTP for
invitation emails.

---

## Testing

```bash
cd platform

# Unit tests — no services needed
pytest tests/unit -v

# Integration tests — need Postgres + Redis from docker-compose.dev.yml
TEST_DATABASE_URL="postgresql+psycopg://securesync:<pw>@127.0.0.1:55432/securesync_test" \
TEST_REDIS_URL="redis://:<pw>@127.0.0.1:56379/15" \
pytest tests/integration -v
```

The CI workflow ([.github/workflows/ci.yml](.github/workflows/ci.yml))
runs the same suite on every push / PR against `main` or `develop`.

Mocks used in tests (network APIs, subprocesses, WeasyPrint native libs)
are registered in [docs/mocks.md](docs/mocks.md) — every mock lists its
inline header location and the exact change needed to swap it for the
real implementation in CI / staging.

---

## Deployment

Production stack lives in [docker-compose.yml](docker-compose.yml). The
[.github/workflows/deploy.yml](.github/workflows/deploy.yml) workflow
builds + pushes images to GHCR and SSH-deploys on every merge to `main`.

Required GitHub secrets for auto-deploy: `SERVER_HOST`, `SERVER_USER`,
`SERVER_SSH_KEY`, plus production `.env` values mounted on the server
under `/opt/securesync/.env`.

Step-by-step production setup including SSL + per-tenant white-label
domains is in [infra/nginx/README.md](infra/nginx/README.md). Wazuh /
Greenbone stack setup is in the respective [oss-stack/](oss-stack/)
READMEs.

---

## Development phases

Follows a 5-phase roadmap in [docs/phases.md](docs/phases.md):

- **Phase 1** — Foundation: API + DB + auth + first scanner (Nuclei) ✅
- **Phase 2** — Core scanning: OpenVAS + ZAP + Wazuh + DefectDojo + EPSS/HIBP ✅
- **Phase 3** — Intelligence: rating engine + PDF reports + user invitations ✅
- **Phase 4** — Production hardening: NinjaOne + Nginx + scheduling + rate-limit + CI/CD ✅
- **Phase 5** — Post-launch: M365, Autotask PSA, multi-region, AI remediation hints (planned)

---

## Security posture

- **Multi-tenant isolation** enforced at 4 layers: JWT claim, API dependency
  (`assert_tenant_access`), SQLAlchemy queries filter by `tenant_id`,
  Wazuh agent groups + DefectDojo products scoped per tenant.
- **No secrets in the repo.** Every sensitive value comes from env or a
  secret manager. `.gitignore` covers `.env*`, cert files, credentials.
- **Append-only audit log** of mutating actions (tenant create, finding
  status change, report download, login success/failure).
- **Per-IP rate-limit** on `/auth/login` (5 attempts / 60 s).
- **Nginx layer:** TLS 1.2+, HSTS, strict CSP, CSRF-safe X-Frame-Options.
- **App layer:** defence-in-depth security headers, timing-safe password
  verification, JWT with required-claim enforcement.

---

## Contributing

1. Read [CLAUDE.md](CLAUDE.md) — project conventions + do-not-do list.
2. Branch from `develop`, open PR against `develop`.
3. CI must pass (`ruff check` + `ruff format --check` + `pytest`).
4. For new integrations / endpoints, add both a unit test (pure logic)
   and an integration test (API contract). Aim for ≥ 80 % coverage on
   `app/services/` and `app/api/`.