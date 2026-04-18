# SecureSync — Sources & Implementation References
> NEXO AI | All links needed to implement each component correctly

---

## 1. Wazuh (Endpoint Agent + SIEM)

### Documentation
- **Main Docs**: https://documentation.wazuh.com/current/
- **Agent Installation (all platforms)**: https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html
- **Vulnerability Detection — How it works**: https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/how-it-works.html
- **REST API Reference**: https://documentation.wazuh.com/current/user-manual/api/reference.html
- **Security Configuration Assessment (CIS)**: https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/index.html
- **File Integrity Monitoring**: https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
- **Docker Deployment (Wazuh Manager + Indexer + Dashboard)**: https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html
- **Multi-tenant / Multiple groups**: https://documentation.wazuh.com/current/user-manual/agent/agent-management/grouping-agents.html

### GitHub
- **Wazuh Core**: https://github.com/wazuh/wazuh
- **Wazuh Docker**: https://github.com/wazuh/wazuh-docker
- **Wazuh API Python client**: https://github.com/wazuh/wazuh-api-client

### Integration Notes
- Wazuh REST API runs on port `55000` (manager)
- Authentication: JWT token via `POST /security/user/authenticate`
- Agents are grouped per customer tenant using Wazuh Agent Groups
- Vulnerability data: `GET /vulnerability/{agent_id}` returns CVE list per agent

---

## 2. Greenbone / OpenVAS (Network CVE Scanner)

### Documentation
- **Greenbone Community Edition**: https://greenbone.github.io/docs/latest/
- **GVM Python Library (python-gvm)**: https://python-gvm.readthedocs.io/en/latest/
- **Docker Setup (Community Edition)**: https://greenbone.github.io/docs/latest/22.4/container/index.html
- **GMP Protocol Reference**: https://docs.greenbone.net/API/GMP/gmp-22.4.html
- **Scan Configs explained**: https://greenbone.github.io/docs/latest/22.4/scanning/

### GitHub
- **openvas-scanner**: https://github.com/greenbone/openvas-scanner
- **gvmd (manager)**: https://github.com/greenbone/gvmd
- **python-gvm**: https://github.com/greenbone/python-gvm
- **Community Feed**: https://github.com/greenbone/vulnerability-tests

### Integration Notes
- Connect via Unix socket or TLS: `UnixSocketConnection('/run/gvmd/gvmd.sock')`
- Auth: `gmp.authenticate(username, password)`
- Create scan: `gmp.create_task(name, config_id, target_id, scanner_id)`
- Poll results: `gmp.get_reports(task_id=task_id)`
- Parse XML results into normalized finding schema

---

## 3. OWASP ZAP (Web Application DAST Scanner)

### Documentation
- **ZAP API Docs**: https://www.zaproxy.org/docs/api/
- **ZAP Docker**: https://www.zaproxy.org/docs/docker/about/
- **ZAP Python Client (zapv2)**: https://github.com/zaproxy/zap-api-python
- **Headless/Daemon Mode**: https://www.zaproxy.org/docs/docker/api-scan/
- **Authentication Handling**: https://www.zaproxy.org/docs/authentication/
- **OpenAPI Scanning**: https://www.zaproxy.org/docs/desktop/addons/openapi-support/

### GitHub
- **ZAP Core**: https://github.com/zaproxy/zaproxy
- **ZAP API Python**: https://github.com/zaproxy/zap-api-python
- **ZAP Docker Images**: https://github.com/zaproxy/zaproxy/tree/main/docker

### Integration Notes
- Run ZAP headless: `docker run -d -p 8080:8080 ghcr.io/zaproxy/zaproxy zap.sh -daemon -host 0.0.0.0 -port 8080`
- Python: `from zapv2 import ZAPv2; zap = ZAPv2(apikey='yourkey', proxies={'http': 'http://zap:8080'})`
- Spider: `zap.spider.scan(target)` → poll `zap.spider.status(scan_id)`
- Active scan: `zap.ascan.scan(target)` → poll `zap.ascan.status(scan_id)`
- Alerts: `zap.alert.alerts(baseurl=target)` returns list of findings

---

## 4. Nuclei (Fast Template Scanner)

### Documentation
- **Official Docs**: https://docs.projectdiscovery.io/tools/nuclei/overview
- **Template Guide**: https://docs.projectdiscovery.io/templates/introduction
- **CLI Reference**: https://docs.projectdiscovery.io/tools/nuclei/running
- **JSON Output Format**: https://docs.projectdiscovery.io/tools/nuclei/output

### GitHub
- **Nuclei**: https://github.com/projectdiscovery/nuclei
- **Nuclei Templates**: https://github.com/projectdiscovery/nuclei-templates
- **Template Syntax**: https://github.com/projectdiscovery/nuclei/blob/main/SYNTAX-REFERENCE.md

### Integration Notes
- Run via subprocess: `nuclei -u https://target.com -json-export results.json -severity critical,high`
- Parse JSON output line by line (JSONL format)
- Filter by tags: `-tags cve,exposure,misconfig`
- Custom templates: place in `/home/nuclei-templates/custom/`
- Rate limiting: `-rate-limit 50 -bulk-size 25`

---

## 5. DefectDojo (Vulnerability Aggregator)

### Documentation
- **Official Docs**: https://defectdojo.com/documentation/
- **API Reference**: https://demo.defectdojo.org/api/v2/doc/
- **Import Scanner Results**: https://docs.defectdojo.com/integrations/parsers/
- **Docker Quickstart**: https://github.com/DefectDojo/django-DefectDojo#quick-start
- **Multi-tenant (Products)**: https://docs.defectdojo.com/usage/features/

### GitHub
- **DefectDojo**: https://github.com/DefectDojo/django-DefectDojo
- **Supported Parsers (200+)**: https://github.com/DefectDojo/django-DefectDojo/tree/master/dojo/tools

### Integration Notes
- Products = Customers, Engagements = Scan Sessions
- Import findings: `POST /api/v2/import-scan/` with `scan_type` and file
- Supported scan types: `OpenVAS XML`, `ZAP Scan`, `Nuclei Scan`, `Wazuh`
- Deduplication: enabled per Product, hash-based on title+cve+asset
- API key: `Authorization: Token <api_key>` header

---

## 6. EPSS API (Exploit Probability Scoring)

### Documentation
- **EPSS Homepage**: https://www.first.org/epss/
- **EPSS API**: https://www.first.org/epss/api
- **EPSS Data Downloads**: https://epss.cyentia.com/

### Integration Notes
- `GET https://api.first.org/data/v1/epss?cve=CVE-2023-44487`
- Returns: `epss` (probability 0–1) and `percentile`
- Bulk query: `?cve=CVE-2023-1,CVE-2023-2` (comma separated, up to 100)
- Update daily: EPSS scores change as threat landscape evolves

---

## 7. HaveIBeenPwned API

### Documentation
- **API Docs**: https://haveibeenpwned.com/API/v3
- **Breach search by domain**: `GET /breachesaccount/{account}`
- **Pricing**: https://haveibeenpwned.com/API/Key

### Integration Notes
- Header: `hibp-api-key: YOUR_KEY`
- Domain breach check: `GET /breachedaccount/{email}?truncateResponse=false`
- Rate limit: 1 req/1500ms (free tier) — implement queue + retry logic
- Pastes check: `GET /pasteaccount/{email}`

---

## 8. NVD / NIST CVE Database

### Documentation
- **NVD API 2.0**: https://nvd.nist.gov/developers/vulnerabilities
- **CVE detail**: `GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-44487`
- **Rate limit**: 5 requests/30s without API key, 50/30s with key (free)

### Integration Notes
- Register for free API key: https://nvd.nist.gov/developers/request-an-api-key
- Cache responses aggressively — CVE data rarely changes after publication
- Use for enriching findings with: description, references, CWE IDs, CVSS vectors

---

## 9. NinjaOne API

### Documentation
- **API Reference**: https://app.ninjarmm.com/apidocs/
- **OAuth Setup**: https://ninjarmm.zendesk.com/hc/en-us/articles/12973871685517
- **Ticket Creation**: `POST /v2/ticketing/ticket`
- **Device Management**: `GET /v2/devices`

### Integration Notes
- OAuth 2.0 client credentials flow
- Match SecureSync asset hostname → NinjaOne device by `systemName`
- Priority mapping: Critical→Urgent, High→High, Medium→Medium, Low→Low
- Custom field on ticket: `CVE ID`, `CVSS Score`, `EPSS Score`, `Affected Asset`

---

## 10. Python Libraries Reference

```
# Core
fastapi==0.111.0
uvicorn[standard]==0.30.0
pydantic==2.7.0
pydantic-settings==2.3.0
sqlalchemy==2.0.30
alembic==1.13.1
asyncpg==0.29.0           # Async PostgreSQL driver
celery==5.4.0
redis==5.0.4
apscheduler==3.10.4

# Security
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
python-multipart==0.0.9

# HTTP
httpx==0.27.0
aiohttp==3.9.5

# Scanner integrations
python-gvm==24.1.0        # OpenVAS/Greenbone
python-nmap==0.7.1        # Nmap
zapv2==0.0.21             # OWASP ZAP

# Reporting
weasyprint==62.1
jinja2==3.1.4

# Utils
structlog==24.2.0         # Structured logging
tenacity==8.3.0           # Retry logic
```

---

## 11. Key Articles & Guides

| Topic | Link |
|---|---|
| Wazuh Multi-Tenant MSP Setup | https://wazuh.com/blog/multi-tenant-wazuh-deployment/ |
| OpenVAS via Python | https://greenbone.github.io/python-gvm/gettingstarted.html |
| DefectDojo + Wazuh Integration | https://defectdojo.github.io/django-DefectDojo/integrations/parsers/file/wazuh/ |
| Nuclei in CI/CD | https://docs.projectdiscovery.io/tools/nuclei/running#cicd-integration |
| CVSS v3.1 Specification | https://www.first.org/cvss/specification-document |
| EPSS White Paper | https://www.first.org/epss/model |
| FastAPI Multi-Tenant Patterns | https://fastapi.tiangolo.com/advanced/middleware/ |
| Next.js App Router + Auth.js | https://authjs.dev/getting-started/installation?framework=next.js |
| WeasyPrint PDF Templates | https://doc.courtbouillon.org/weasyprint/stable/ |
| NinjaOne API Docs | https://app.ninjarmm.com/apidocs/ |
