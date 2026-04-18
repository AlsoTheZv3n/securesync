# SecureSync — Architecture
> NEXO AI | System Design & Component Interactions

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    NEXO AI SecureSync Platform                              │
├──────────────────────────────────┬──────────────────────────────────────────┤
│         PUBLIC INTERNET          │           CUSTOMER NETWORKS               │
│                                  │                                            │
│  ┌────────────────────────────┐  │  ┌─────────────────────────────────────┐  │
│  │     Next.js Frontend       │  │  │         Wazuh Agents                │  │
│  │  (White-Label Dashboard)   │  │  │  Windows · Linux · macOS            │  │
│  │  Port 3000 → Nginx:443     │  │  │  ✓ Software Inventory               │  │
│  └───────────┬────────────────┘  │  │  ✓ CVE Detection                    │  │
│              │ HTTPS             │  │  ✓ Patch Status                      │  │
│  ┌───────────▼────────────────┐  │  │  ✓ CIS Benchmarks                   │  │
│  │     FastAPI Platform API   │  │  │  ✓ FIM / AV / Firewall              │  │
│  │  Port 8000 → Nginx:443     │  │  └──────────────┬──────────────────────┘  │
│  │  Multi-Tenant · JWT Auth   │  │                 │ HTTPS:1514/55000        │
│  │  Rating Engine · Reports   │  │  ┌──────────────▼──────────────────────┐  │
│  └──┬──────┬──────┬───────────┘  │  │         Wazuh Manager               │  │
│     │      │      │              │  │  Port 1514 (agent) · 55000 (API)     │  │
│     │      │      │              │  │  Vulnerability Correlation + CTI     │  │
│     ▼      ▼      ▼              │  └─────────────────────────────────────┘  │
│  ┌────┐ ┌────┐ ┌─────────────┐  │                                            │
│  │ PG │ │Redis│ │OSS Scanner  │  └────────────────────────────────────────────┘
│  │ DB │ │+   │ │Cluster      │
│  │    │ │Celery│ │             │
│  └────┘ └────┘ │ ┌─────────┐ │
│                 │ │Greenbone│ │
│                 │ │OpenVAS  │ │   ──► Scans EXTERNAL targets over internet
│                 │ └─────────┘ │
│                 │ ┌─────────┐ │
│                 │ │OWASP ZAP│ │   ──► Scans WEB APPS over internet
│                 │ └─────────┘ │
│                 │ ┌─────────┐ │
│                 │ │ Nuclei  │ │   ──► Fast template scans over internet
│                 │ └─────────┘ │
│                 │ ┌─────────┐ │
│                 │ │DefectDojo│ │  ──► Aggregates all scanner results
│                 │ └─────────┘ │
│                 └─────────────┘
│
│  ┌──────────────────────────────┐
│  │        External APIs         │
│  │  EPSS · HIBP · NVD · NinjaOne│
│  └──────────────────────────────┘
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Component Interaction Flow

### Flow 1: External Scan Job

```
MSP Technician (Frontend)
        │
        │ POST /api/v1/scans  {target_id, scan_type, profile}
        ▼
FastAPI Platform API
        │
        │ Creates ScanJob record in PostgreSQL
        │ Enqueues Celery task
        ▼
Celery Worker
        │
        ├──► Nuclei subprocess → parse JSONL → normalize findings
        │
        ├──► ZAP API: spider → active scan → get alerts → normalize
        │
        └──► Greenbone GMP: create task → wait → get report XML → parse
                │
                ▼
        All findings → POST /api/v2/import-scan/ to DefectDojo
                │
                ▼
        DefectDojo deduplicates + stores canonical finding list
                │
                ▼
        Celery: fetch deduplicated findings from DefectDojo
                │
                ├──► Enrich each CVE: EPSS API + NVD API
                │
                └──► Store enriched findings in PostgreSQL
                        │
                        ▼
                Rating Engine calculates A–F score
                        │
                        ▼
                PostgreSQL: update ScanJob.status = "completed"
                        │
                        ▼
                Webhook/Email notification → MSP + Customer (if configured)
```

### Flow 2: Internal Scan (Agent-Based)

```
Wazuh Agent (Customer Endpoint)
        │
        │ Continuous: software inventory, patch status, FIM events
        │ Periodic: SCA checks (CIS benchmarks)
        ▼
Wazuh Manager
        │
        │ Correlates inventory with CVE database (CTI feed)
        │ Generates vulnerability alerts
        ▼
FastAPI Platform API (via Wazuh REST API polling)
        │
        │ Celery scheduled task: fetch new alerts per agent group
        ▼
        Normalize Wazuh findings → PostgreSQL
        │
        └──► Merge with external scan findings for unified rating
```

### Flow 3: Report Generation

```
MSP requests report (Frontend button / scheduled)
        │
        ▼
FastAPI: collect all findings + rating for tenant
        │
        ├──► Fetch rating history (last N scans)
        │
        ├──► Build House Analogy data model
        │
        └──► Render Jinja2 HTML template with tenant branding
                │
                ▼
        WeasyPrint: HTML → PDF bytes
                │
                ▼
        Store PDF in PostgreSQL (bytea) or S3
                │
                ▼
        Return download URL / email attachment
```

---

## Data Model (Simplified)

```
tenants
├── id (UUID)
├── name
├── slug (for subdomain)
├── logo_url
├── primary_color
├── custom_domain
└── msp_id (FK → tenants, self-referential for MSP→Customer)

users
├── id (UUID)
├── email
├── hashed_password
├── role (platform_admin | msp_admin | msp_tech | customer_readonly)
├── tenant_id (FK → tenants)
└── mfa_secret

assets
├── id (UUID)
├── tenant_id (FK → tenants)
├── type (external_domain | external_ip | internal_endpoint)
├── value (hostname / IP / agent_id)
├── tags (JSONB)
└── wazuh_agent_id

scan_jobs
├── id (UUID)
├── tenant_id (FK → tenants)
├── asset_id (FK → assets)
├── scan_type (external_full | web_app | internal | fast)
├── status (queued | running | completed | failed)
├── started_at / completed_at
└── celery_task_id

findings
├── id (UUID)
├── tenant_id (FK → tenants)
├── scan_job_id (FK → scan_jobs)
├── asset_id (FK → assets)
├── cve_id
├── title
├── severity (critical | high | medium | low | info)
├── cvss_score (NUMERIC)
├── epss_score (NUMERIC)
├── status (open | in_progress | resolved | accepted | false_positive)
├── source (openvas | zap | nuclei | wazuh)
├── raw_data (JSONB)
└── defectdojo_id

ratings
├── id (UUID)
├── tenant_id (FK → tenants)
├── scan_job_id (FK → scan_jobs)
├── overall_grade (A–F)
├── patch_score (NUMERIC)
├── network_score (NUMERIC)
├── web_score (NUMERIC)
├── endpoint_score (NUMERIC)
├── email_score (NUMERIC)
├── breach_score (NUMERIC)
├── ransomware_score (NUMERIC)
└── calculated_at

reports
├── id (UUID)
├── tenant_id (FK → tenants)
├── type (executive | technical)
├── generated_at
├── pdf_data (BYTEA) -- or S3 key
└── scan_job_id (FK → scan_jobs)
```

---

## Network & Port Map

```
HOST (your server: 192.168.1.50 or cloud VM)
│
├── :80   → Nginx → redirect to :443
├── :443  → Nginx → SSL termination
│           ├── /api/*          → FastAPI :8000
│           ├── /               → Next.js :3000
│           └── /wazuh/*        → Wazuh Dashboard :443 (internal)
│
├── :8000  FastAPI (internal only, not exposed)
├── :3000  Next.js (internal only, not exposed)
├── :5432  PostgreSQL (internal only)
├── :6379  Redis (internal only)
│
├── :9392  Greenbone Web UI (internal only, admin access)
├── :8080  OWASP ZAP API (internal only)
├── :80    DefectDojo (internal only)
│
└── :55000 Wazuh Manager REST API (internal only)
    :1514  Wazuh Agent communication (exposed to customer networks)
    :1515  Wazuh Agent enrollment (exposed to customer networks)
```

---

## Multi-Tenant Isolation Strategy

```
Tenant A (customer.a.com)          Tenant B (customer.b.com)
         │                                  │
         │ JWT: {tenant_id: "aaa"}          │ JWT: {tenant_id: "bbb"}
         ▼                                  ▼
    FastAPI Middleware: extract tenant_id from JWT
         │
         ▼
    All DB queries: WHERE tenant_id = :tenant_id
         │
    Wazuh: Agent Group "tenant-aaa" vs "tenant-bbb"
         │
    Greenbone: Separate GVM targets per tenant
         │
    DefectDojo: Separate Product per tenant
```

No tenant can ever see another tenant's data. Enforced at:
1. API middleware (JWT tenant claim)
2. All SQLAlchemy queries (tenant_id filter)
3. Wazuh agent group names (prefixed with tenant_id)
4. DefectDojo product scope

---

## Deployment Topology

### Single-Server (MVP / Self-Hosted)
```
Ubuntu 24.04 VM (min. 16GB RAM, 8 vCPU, 200GB SSD)
├── docker-compose up (all services)
├── Nginx (host-level or containerized)
└── Certbot for SSL
```

### Distributed (Production / Scale)
```
VM-1: Platform API + Frontend + PostgreSQL + Redis
VM-2: Wazuh Manager + Indexer
VM-3: Scanner Cluster (Greenbone + ZAP + Nuclei + DefectDojo)
CDN: Cloudflare (SSL, WAF, DDoS)
```

---

## Security Considerations

- All inter-service communication via Docker internal network (not exposed)
- Wazuh agent ↔ manager: TLS 1.2+, certificate-based enrollment
- Platform API: HTTPS only, HSTS headers
- JWT: RS256 algorithm, 15min access token, 7d refresh token
- All scan jobs run in isolated Celery workers
- Nuclei/Nmap subprocess output sanitized before parsing
- Customer data never leaves EU (Swiss hosting: Exoscale / Infomaniak)
- API rate limiting via Redis (per-tenant, per-endpoint)
- HMAC-signed webhooks (SHA-256)
- Secrets via `.env` file — never hardcoded, never in git
