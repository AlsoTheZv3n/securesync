# SecureSync — Tech Stack
> NEXO AI | Automated Security Audit Platform for Swiss MSPs/MSSPs

---

## Overview

SecureSync is built on a **hybrid architecture**: a thin custom orchestration layer (Python/TypeScript) sitting on top of a cluster of battle-tested open-source security tools. The philosophy is: don't reinvent the wheel — integrate, normalize, and present.

---

## Frontend

| Technology | Version | Purpose |
|---|---|---|
| **Next.js** | 14 (App Router) | SSR/SSG, routing, API routes |
| **TypeScript** | 5.x | Type safety across all frontend code |
| **Tailwind CSS** | 3.x | Utility-first styling |
| **shadcn/ui** | latest | Accessible component library |
| **TanStack Query** | 5.x | Data fetching, caching, background refetch |
| **Recharts** | 2.x | Security rating charts, trend graphs |
| **Framer Motion** | 11.x | Animations (House Analogy visualisation) |
| **React Hook Form** | 7.x | Scan wizard, settings forms |
| **Zod** | 3.x | Schema validation frontend + shared |
| **next-auth** | 5.x | Authentication, JWT sessions |

**Why Next.js**: SSR for white-label customer report pages, App Router for nested layouts per tenant, API routes for lightweight BFF (Backend-for-Frontend) calls.

---

## Platform API (Orchestration Layer)

| Technology | Version | Purpose |
|---|---|---|
| **Python** | 3.12 | Primary backend language |
| **FastAPI** | 0.111+ | REST API, OpenAPI docs auto-generation |
| **Pydantic v2** | 2.x | Request/response validation, settings |
| **SQLAlchemy** | 2.x | ORM with async support |
| **Alembic** | 1.x | Database migrations |
| **Celery** | 5.x | Async task queue for scan orchestration |
| **APScheduler** | 3.x | Recurring scan scheduling (cron-style) |
| **WeasyPrint** | 62.x | PDF report generation from HTML/CSS |
| **Jinja2** | 3.x | Report HTML templates |
| **httpx** | 0.27+ | Async HTTP client for external API calls |
| **python-jose** | 3.x | JWT encoding/decoding |
| **passlib** | 1.x | Password hashing (bcrypt) |
| **python-gvm** | 24.x | OpenVAS/Greenbone GMP socket client |
| **python-nmap** | 0.7.x | Nmap subprocess wrapper |

---

## OSS Security Tools (Deployed, Not Written)

### Wazuh — Endpoint Agent + SIEM
| Component | Language | Role |
|---|---|---|
| Wazuh Agent | **C/C++** | Deployed on customer endpoints |
| Wazuh Manager | **C/C++** | Collects + correlates agent data |
| Wazuh Indexer | Java (OpenSearch) | Stores and indexes security events |
| Wazuh Dashboard | TypeScript | Built-in visualisation (optional, we replace with custom) |

Wazuh covers: Software inventory, CVE detection via CTI, CIS Benchmarks, FIM, Patch Status, Firewall Check, Antivirus Status.
> GitHub: https://github.com/wazuh/wazuh

### Greenbone / OpenVAS — Network CVE Scanner
| Component | Language | Role |
|---|---|---|
| gvmd | **C** | Vulnerability Manager Daemon |
| openvas-scanner | **C** | Actual scanning engine |
| gsa | TypeScript | Web interface (not used, we use API) |
| Community Feed | — | 120,000+ CVE checks, daily updates |

> GitHub: https://github.com/greenbone/openvas-scanner

### OWASP ZAP — Web Application DAST Scanner
| Component | Language | Role |
|---|---|---|
| ZAP Daemon | **Java (JVM)** | Headless mode, REST API exposed |
| ZAP API | Java | Used via Python `zapv2` client |

Covers: OWASP Top 10, XSS, SQLi, SSRF, misconfigurations, auth issues.
> GitHub: https://github.com/zaproxy/zaproxy

### Nuclei — Fast Template-Based Scanner
| Component | Language | Role |
|---|---|---|
| Nuclei binary | **Go** | Single binary, no runtime dependency |
| Nuclei Templates | YAML | 9,000+ community templates |

Covers: CVEs, exposed panels, misconfigs, subdomain takeover, tech detection.
> GitHub: https://github.com/projectdiscovery/nuclei

### DefectDojo — Vulnerability Aggregator
| Component | Language | Role |
|---|---|---|
| DefectDojo | **Python (Django)** | Deduplication, normalization, 200+ tool imports |

Receives findings from all scanners, deduplicates, enriches with EPSS/KEV data.
> GitHub: https://github.com/DefectDojo/django-DefectDojo

### osquery — Cross-Platform System Inventory (Optional Phase 3)
| Component | Language | Role |
|---|---|---|
| osquery | **C++** | SQL queries against OS state |

> GitHub: https://github.com/osquery/osquery

---

## Infrastructure & Data

| Technology | Purpose |
|---|---|
| **PostgreSQL 16** | Primary database (tenants, findings, ratings, reports) |
| **Redis 7** | Celery broker + result backend, API caching |
| **Docker + Compose** | All services containerized |
| **Nginx** | Reverse proxy, SSL termination, white-label domain routing |
| **Let's Encrypt / Certbot** | Automated SSL certificates |

---

## External APIs

| API | Purpose | Pricing |
|---|---|---|
| **FIRST.org EPSS** | Exploit Probability Score per CVE | Free |
| **HaveIBeenPwned v3** | Email + password breach detection | Free (rate-limited) / ~$4/mo |
| **NVD (NIST)** | CVE metadata, CVSS scores | Free |
| **NinjaOne API** | Push findings as tickets to RMM | Per MSP contract |
| **Autotask PSA API** | Ticket creation (optional Phase 3) | Per contract |

---

## CI/CD

| Technology | Purpose |
|---|---|
| **GitHub Actions** | Build, test, lint, deploy pipelines |
| **Docker Hub / GHCR** | Container registry |
| **pytest** | Python unit + integration tests |
| **Playwright** | E2E frontend tests |
| **Ruff** | Python linter (replaces flake8/black) |
| **ESLint + Prettier** | TypeScript/Next.js linting |

---

## Language Summary

```
What YOU write:
  Python      → FastAPI platform, rating engine, integrations (~60% of custom code)
  TypeScript  → Next.js frontend, shared Zod schemas (~40% of custom code)

What you DEPLOY (OSS, no custom code needed):
  C/C++       → Wazuh Agent + Manager (battle-tested, Windows/Linux/macOS)
  C           → Greenbone/OpenVAS scanner engine
  Java        → OWASP ZAP (JVM required on scanner host)
  Go          → Nuclei (single binary, zero runtime deps)
  Python      → DefectDojo aggregator

What you DO NOT need:
  Assembly    → Never. Not applicable.
  Rust        → Not needed at this layer.
```
