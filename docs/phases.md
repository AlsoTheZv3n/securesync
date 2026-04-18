# SecureSync — Implementation Phases
> NEXO AI | Step-by-step roadmap from zero to production

---

## Phase Overview

```
Phase 1: Foundation (Weeks 1–4)      → Working API + DB + Auth + Nuclei scan
Phase 2: Core Scanning (Weeks 5–10)  → OpenVAS + ZAP + Wazuh Agent + DefectDojo
Phase 3: Intelligence (Weeks 11–14)  → Rating Engine + EPSS + Reports + Portal
Phase 4: Production (Weeks 15–18)    → White-Label + NinjaOne + CI/CD + Hardening
Phase 5: Scale (Post-launch)         → M365 + Autotask + Multi-region + Analytics
```

---

## Phase 1: Foundation
**Goal**: Infrastructure is up, API works, one scanner produces findings in the DB.
**Duration**: ~4 weeks
**MVP Test**: Run a Nuclei scan via API call, see results in PostgreSQL, display in a basic table.

---

### Step 1.1 — Project Setup (Day 1–2)

**Tasks:**
1. Initialize git repo: `git init`, add `.gitignore`, initial commit
2. Create directory structure as defined in `CLAUDE.md`
3. Setup Python project:
   ```bash
   cd platform
   python -m venv .venv
   pip install uv
   uv pip install fastapi uvicorn[standard] pydantic pydantic-settings sqlalchemy asyncpg alembic
   ```
4. Setup Next.js project:
   ```bash
   cd frontend
   npx create-next-app@latest . --typescript --tailwind --app --src-dir
   npx shadcn@latest init
   ```
5. Create `.env.example` with all required variables (empty values)
6. Create `docker-compose.dev.yml` with PostgreSQL + Redis only

**Deliverable**: `docker-compose up` starts PostgreSQL and Redis. FastAPI starts locally. Next.js starts locally.

**Acceptance Criteria:**
- [ ] `GET /health` returns `{"status": "ok"}`
- [ ] PostgreSQL connection works (alembic can connect)
- [ ] Redis connection works (Celery can connect)
- [ ] Next.js home page loads at `localhost:3000`

---

### Step 1.2 — Database + Models (Day 3–5)

**Tasks:**
1. Create `app/core/database.py` with async SQLAlchemy engine + session factory
2. Create all SQLAlchemy models: `Tenant`, `User`, `Asset`, `ScanJob`, `Finding`, `Rating`
   - Reference data model in `docs/architecture.md`
   - Use UUIDs as primary keys
   - Add `created_at` / `updated_at` timestamps on all models
3. Create first Alembic migration: `alembic revision --autogenerate -m "initial_schema"`
4. Run migration: `alembic upgrade head`
5. Create `app/core/config.py` with Pydantic Settings (all vars from `.env`)

**Deliverable**: Full DB schema created. All tables exist with correct columns.

**Acceptance Criteria:**
- [ ] `alembic upgrade head` runs without errors
- [ ] All 6 tables exist in PostgreSQL
- [ ] Foreign key constraints work correctly
- [ ] `alembic downgrade -1` rolls back cleanly

---

### Step 1.3 — Authentication (Day 6–9)

**Tasks:**
1. Create `app/core/security.py`:
   - `hash_password(password: str) -> str`
   - `verify_password(plain: str, hashed: str) -> bool`
   - `create_access_token(data: dict, expires_delta: timedelta) -> str`
   - `decode_token(token: str) -> dict`
2. Create `app/api/v1/auth.py`:
   - `POST /auth/login` → returns `{access_token, refresh_token, token_type}`
   - `POST /auth/refresh` → refreshes access token
   - `POST /auth/logout` → blacklist token in Redis
3. Create `app/core/dependencies.py`:
   - `get_current_user(token)` → returns User or raises 401
   - `get_tenant(user)` → returns Tenant, enforces isolation
4. Seed a test MSP admin user in DB
5. Next.js: implement login page with Auth.js (next-auth)
   - JWT session strategy
   - Store access token in session, include in all API calls

**Deliverable**: Login works end-to-end from Next.js → API → DB.

**Acceptance Criteria:**
- [ ] `POST /auth/login` with valid credentials returns JWT
- [ ] Protected routes return 401 without token
- [ ] User from Tenant A cannot access Tenant B data (write test)
- [ ] Next.js login form works, session persists across page reload
- [ ] Token refresh works when access token expires

---

### Step 1.4 — Tenant & Asset CRUD (Day 10–13)

**Tasks:**
1. Create `app/api/v1/tenants.py`:
   - `GET /tenants` — list all tenants (MSP admin only)
   - `POST /tenants` — create new customer tenant
   - `GET /tenants/{id}` — get tenant detail
   - `PATCH /tenants/{id}` — update (name, branding)
   - `DELETE /tenants/{id}` — soft delete
2. Create `app/api/v1/assets.py`:
   - `GET /assets` — list assets for current tenant
   - `POST /assets` — register new asset (domain / IP / agent)
   - `PATCH /assets/{id}` — update tags, metadata
   - `DELETE /assets/{id}` — remove asset
3. Pydantic schemas for all request/response shapes
4. Next.js: Customer list page + "Add Customer" modal

**Deliverable**: MSP can create customers and register their domains via the UI.

**Acceptance Criteria:**
- [ ] MSP admin can create a customer tenant
- [ ] MSP admin can add a domain as an external asset
- [ ] Tenant isolation: GET /assets only returns current tenant's assets
- [ ] UI shows customer list with basic info

---

### Step 1.5 — Nuclei Integration + Scan Jobs (Day 14–21)

**Tasks:**
1. Install Nuclei in scanner container or run via Docker-in-Docker
2. Create `app/integrations/nuclei.py`:
   - `run_scan(target: str, tags: list[str]) -> list[NormalizedFinding]`
   - Parse JSONL output line by line
   - Map to `NormalizedFinding` schema
3. Create `app/services/normalizer.py`:
   - Define `NormalizedFinding` dataclass
   - Fields: `cve_id`, `title`, `severity`, `asset`, `cvss_score`, `source`, `description`, `evidence`
4. Setup Celery:
   - `app/core/celery_app.py` — factory
   - `app/tasks/scan_tasks.py` — `run_external_scan` task
5. Create `app/api/v1/scans.py`:
   - `POST /scans` — create scan job, enqueue Celery task
   - `GET /scans` — list scan jobs for tenant
   - `GET /scans/{id}` — get scan status + progress
6. Create `app/api/v1/findings.py`:
   - `GET /findings` — list findings (filterable by severity, status, asset)
   - `GET /findings/{id}` — finding detail
   - `PATCH /findings/{id}` — update status (open/resolved/false_positive)
7. Next.js: Scan wizard + findings table (basic)

**Deliverable**: Full scan → findings pipeline works.

**Acceptance Criteria:**
- [ ] `POST /scans` enqueues Celery task
- [ ] Nuclei runs against target, output parsed
- [ ] Findings stored in PostgreSQL with correct severity mapping
- [ ] `GET /findings` returns paginated, filterable results
- [ ] UI shows finding list with severity badges
- [ ] Scan status updates (queued → running → completed)

---

### Phase 1 Complete Checklist

- [ ] Docker Compose starts entire dev stack in one command
- [ ] Auth works end-to-end
- [ ] Multi-tenant isolation verified by tests
- [ ] Nuclei scan produces real findings from a test target
- [ ] `pytest` passes with >80% coverage on implemented modules
- [ ] Basic Next.js UI shows customers, scans, findings

---

## Phase 2: Core Scanning
**Goal**: All major scanners integrated. Wazuh agent collecting internal data.
**Duration**: ~6 weeks

---

### Step 2.1 — Greenbone/OpenVAS Integration (Week 5–6)

**Tasks:**
1. Add Greenbone Community Edition to `docker-compose.yml`
   - Use official Greenbone Docker Compose: https://greenbone.github.io/docs/latest/22.4/container/
   - Wait for feed sync to complete before first scan (~30 min)
2. Create `app/integrations/openvas.py`:
   - `GreenBoneClient` class using `python-gvm`
   - `create_target(name, hosts) -> str` (returns target ID)
   - `create_scan(target_id, config="Full and fast") -> str` (returns task ID)
   - `poll_scan_status(task_id) -> str` (Running/Done/Failed)
   - `get_results(task_id) -> list[NormalizedFinding]`
   - Parse GMP XML report → NormalizedFinding
3. Add `openvas` scan type to Celery task
4. Celery workflow: create target → start scan → poll every 30s → parse results → store

**Acceptance Criteria:**
- [ ] `docker-compose up` starts Greenbone and feed sync completes
- [ ] Python GMP connection works (authenticated)
- [ ] Test scan against a local test VM produces CVE findings
- [ ] Results stored correctly in PostgreSQL
- [ ] CVSS scores mapped correctly

---

### Step 2.2 — OWASP ZAP Integration (Week 6–7)

**Tasks:**
1. Add ZAP daemon to `docker-compose.yml`:
   ```yaml
   zap:
     image: ghcr.io/zaproxy/zaproxy:stable
     command: zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.key=${ZAP_API_KEY}
   ```
2. Create `app/integrations/zap.py`:
   - `ZAPClient` class using `zapv2`
   - `spider(target) -> scan_id`
   - `active_scan(target) -> scan_id`
   - `poll_status(scan_id) -> int` (0-100 progress)
   - `get_alerts(target) -> list[NormalizedFinding]`
   - Map ZAP risk levels: High/Medium/Low/Informational → severity
3. Add `web_app` scan type to Celery task
4. Celery: spider → wait → active scan → wait → get alerts → normalize → store

**Acceptance Criteria:**
- [ ] ZAP daemon starts and API is reachable
- [ ] Spider discovers endpoints on test web app
- [ ] Active scan finds at least one vulnerability on a deliberately vulnerable app (DVWA)
- [ ] Findings stored with correct severity

---

### Step 2.3 — DefectDojo Integration (Week 7–8)

**Tasks:**
1. Add DefectDojo to `docker-compose.yml` (use official compose)
2. Create `app/integrations/defectdojo.py`:
   - `DefectDojoClient` class
   - `create_product(tenant_name) -> product_id` (called on tenant creation)
   - `create_engagement(product_id, scan_name) -> engagement_id`
   - `import_scan(engagement_id, scan_type, file_path) -> int` (returns finding count)
   - `get_findings(product_id) -> list[NormalizedFinding]`
3. Update scan pipeline: after each scanner completes, export results file → upload to DefectDojo
4. Fetch deduplicated findings from DefectDojo → store in PostgreSQL findings table
5. Store DefectDojo `finding_id` for bidirectional sync

**Acceptance Criteria:**
- [ ] DefectDojo starts and API is accessible
- [ ] New customer tenant auto-creates DefectDojo product
- [ ] Nuclei results import to DefectDojo correctly
- [ ] OpenVAS results import to DefectDojo correctly
- [ ] Duplicate findings (same CVE, same host, multiple scanners) deduplicated

---

### Step 2.4 — Wazuh Deployment + Agent (Week 8–10)

**Tasks:**
1. Deploy Wazuh stack (`oss-stack/wazuh/docker-compose.yml`):
   - `wazuh.manager`, `wazuh.indexer`, `wazuh.dashboard`
   - Configure Manager API credentials
2. Create `app/integrations/wazuh.py`:
   - `WazuhClient` class with JWT auth
   - `create_agent_group(tenant_id) -> str`
   - `get_agents(group_name) -> list[Agent]`
   - `get_vulnerabilities(agent_id) -> list[NormalizedFinding]`
   - `get_sca_results(agent_id) -> list[SCAResult]`
   - `get_inventory(agent_id) -> SoftwareInventory`
3. Celery scheduled task: poll Wazuh API every 1 hour per tenant → fetch new vulns → store
4. Create agent enrollment flow in UI:
   - Display Wazuh manager URL + enrollment key per customer
   - Show "Download Agent Installer" button (Windows MSI / Debian pkg / etc.)
5. Next.js: Agent status page showing enrolled endpoints

**Acceptance Criteria:**
- [ ] Wazuh Manager starts and API responds
- [ ] Enroll a test Windows agent → appears in Manager
- [ ] Vulnerabilities from agent appear in SecureSync findings
- [ ] Agent grouped correctly per customer tenant
- [ ] UI shows enrolled agents with status (active/inactive)

---

### Step 2.5 — EPSS + HIBP Enrichment (Week 9–10)

**Tasks:**
1. Create `app/integrations/epss.py`:
   - `get_epss_scores(cve_ids: list[str]) -> dict[str, float]`
   - Batch up to 100 CVEs per request
   - Cache results in Redis (TTL: 24h)
2. Create `app/integrations/hibp.py`:
   - `check_emails(emails: list[str], tenant_id: str) -> list[BreachResult]`
   - Rate limit: 1 req/1500ms via asyncio sleep + queue
3. Enrich findings after scan completes: add EPSS score to each CVE finding
4. Store EPSS score in `findings.epss_score` column
5. Add HIBP check as optional scan type on assets with email addresses

**Acceptance Criteria:**
- [ ] EPSS scores fetched and stored for all CVE findings
- [ ] HIBP check works with rate limiting
- [ ] Findings table shows EPSS percentile
- [ ] Redis caching prevents redundant EPSS API calls

---

### Phase 2 Complete Checklist

- [ ] All 3 external scanners produce findings (Nuclei + OpenVAS + ZAP)
- [ ] Wazuh agent enrolled on at least 1 test machine, findings flowing
- [ ] DefectDojo deduplication working
- [ ] EPSS scores on all CVE findings
- [ ] HIBP breach check working
- [ ] Full scan (all scanners) completes for a test customer in <15 minutes

---

## Phase 3: Intelligence & Reporting
**Goal**: Rating engine live, PDF reports generated, customer portal accessible.
**Duration**: ~4 weeks

---

### Step 3.1 — Rating Engine (Week 11–12)

**Tasks:**
1. Implement `app/services/rating_engine.py` per contract in `CLAUDE.md`
2. Unit test exhaustively:
   - 0 critical findings → expected score
   - 5 critical CVE findings → expected score
   - All categories failing → F rating
   - All categories passing → A rating
3. Store rating after each completed scan in `ratings` table
4. Create `app/api/v1/ratings.py`:
   - `GET /ratings/current/{tenant_id}` → latest rating
   - `GET /ratings/history/{tenant_id}` → last N ratings for trend graph
5. Next.js: `RatingGauge` component (see `docs/design.md`)
6. Next.js: `TrendGraph` component (Recharts)
7. Next.js: House Analogy SVG component

**Acceptance Criteria:**
- [ ] Rating calculated correctly for test data (unit tested)
- [ ] Rating updates after each scan
- [ ] Trend graph shows history over last 10 scans
- [ ] House Analogy renders with correct colour states
- [ ] All rating UI components match design spec

---

### Step 3.2 — PDF Reports (Week 12–13)

**Tasks:**
1. Create Jinja2 templates:
   - `templates/report_executive.html` — customer-facing (see `docs/design.md`)
   - `templates/report_technical.html` — MSP internal
2. Create `app/services/report_generator.py`:
   - `generate_executive_report(tenant_id, scan_job_id) -> bytes`
   - `generate_technical_report(tenant_id, scan_job_id) -> bytes`
   - Use WeasyPrint to convert HTML → PDF
3. Create `app/api/v1/reports.py`:
   - `POST /reports/generate` — trigger report generation
   - `GET /reports/{id}/download` — stream PDF bytes
   - `GET /reports` — list past reports for tenant
4. Next.js: Report generation button + report list + download link

**Acceptance Criteria:**
- [ ] Executive PDF generates in <10 seconds
- [ ] PDF includes customer logo (if uploaded)
- [ ] PDF includes rating badge, house analogy, top findings
- [ ] Technical PDF includes full finding list with CVE IDs
- [ ] Download works from Next.js

---

### Step 3.3 — Customer Portal (Week 13–14)

**Tasks:**
1. Add `customer_readonly` role to auth system
2. Create separate layout for customer portal (lighter theme)
3. Customer portal routes (read-only):
   - `/portal/overview` — rating + house analogy
   - `/portal/findings` — findings list (no status change allowed)
   - `/portal/reports` — download their reports
4. Invitation flow: MSP sends email → customer sets password → read-only access
5. White-label: apply tenant's custom colours/logo to portal

**Acceptance Criteria:**
- [ ] Customer readonly user cannot trigger scans
- [ ] Customer readonly user cannot see other tenant data
- [ ] Customer portal shows tenant branding
- [ ] Customer can download their reports

---

## Phase 4: Production Hardening
**Goal**: Deployment-ready. Real customers can use it.
**Duration**: ~4 weeks

---

### Step 4.1 — NinjaOne Integration (Week 15)

**Tasks:**
1. Implement `app/integrations/ninjaone.py`:
   - OAuth 2.0 client credentials flow
   - `get_devices() -> list[Device]`
   - `create_ticket(finding: NormalizedFinding, device_id: str) -> str`
   - `sync_ticket_status(ninjaone_ticket_id, finding_id)`
2. Settings UI: NinjaOne API credentials per tenant
3. Auto-ticket: create NinjaOne ticket when Critical/High finding discovered
4. Bidirectional sync: Celery task polls NinjaOne for resolved tickets

---

### Step 4.2 — Nginx + SSL + White-Label Domains (Week 15–16)

**Tasks:**
1. Configure Nginx reverse proxy (see `nginx/nginx.conf`)
2. Setup Certbot for automatic SSL
3. Support custom domains per tenant:
   - Nginx dynamic vhost from PostgreSQL (or template generation)
   - Certbot auto-cert for new custom domains
4. Add domain verification step in tenant settings

---

### Step 4.3 — Scan Scheduling (Week 16)

**Tasks:**
1. Implement APScheduler in `app/tasks/scheduler.py`
2. Tenant-level scan schedules (daily/weekly/monthly)
3. Schedule stored in PostgreSQL per tenant
4. UI: scan schedule configuration per customer
5. Maintenance window support (no scans during specified hours)

---

### Step 4.4 — Security Hardening (Week 17)

**Tasks:**
1. API rate limiting per tenant per endpoint (Redis)
2. Input validation: sanitize all scan targets before passing to subprocess
3. HTTPS-only enforcement (HSTS header)
4. Security headers: CSP, X-Frame-Options, X-Content-Type-Options
5. Audit log: log all privileged actions with user + timestamp
6. Penetration test own platform with Nuclei + ZAP before launch

---

### Step 4.5 — CI/CD + Monitoring (Week 18)

**Tasks:**
1. GitHub Actions:
   - `ci.yml`: run pytest + eslint + playwright on every PR
   - `deploy.yml`: build Docker images → push to registry → SSH deploy on merge to main
2. Health check endpoints for all services
3. Uptime monitoring (UptimeRobot or self-hosted)
4. Error alerting (Sentry for Python + Next.js)

---

## Phase 5: Scale (Post-Launch)

Future features (not in initial scope):
- Microsoft 365 security integration (Secure Score, MFA status, OAuth app audit)
- Autotask PSA integration
- Multi-region deployment (CH-East + EU-West)
- AI-powered remediation suggestions (Claude API)
- Customer questionnaire for non-technical controls (backup, security awareness)
- CIS Benchmark detailed reporting
- Compliance mapping (DSGVO/GDPR, ISO 27001, NIS2)

---

## Phase Decision Criteria

| Phase | Move to next when... |
|---|---|
| 1 → 2 | Nuclei scan works E2E, auth solid, tests passing |
| 2 → 3 | All scanners integrated, Wazuh agent enrolled on test machine |
| 3 → 4 | Rating correct, PDF generates, customer portal accessible |
| 4 → 5 | First paying customer live on the platform |
