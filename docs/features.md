# SecureSync — Feature Specification
> NEXO AI | Automated Security Audit Platform for Swiss MSPs/MSSPs

---

## Feature Categories

1. [Multi-Tenant Management](#1-multi-tenant-management)
2. [External Scanning](#2-external-scanning)
3. [Internal Scanning (Endpoint Agent)](#3-internal-scanning-endpoint-agent)
4. [Vulnerability Management](#4-vulnerability-management)
5. [Security Rating Engine](#5-security-rating-engine)
6. [Reporting & Communication](#6-reporting--communication)
7. [White-Label & Branding](#7-white-label--branding)
8. [Integrations](#8-integrations)
9. [Customer Portal](#9-customer-portal)
10. [Platform Administration](#10-platform-administration)

---

## 1. Multi-Tenant Management

### 1.1 Tenant Hierarchy
- MSP account (NEXO AI partner) → Customer tenants → Assets/Targets
- Unlimited customer tenants per MSP account
- Role-based access: `platform_admin`, `msp_admin`, `msp_technician`, `customer_readonly`

### 1.2 Asset Management
- Register external targets: domains, subdomains, IP ranges, CIDR blocks
- Register internal targets: agent-enrolled endpoints
- Asset tagging (e.g. `managed`, `critical`, `dmz`)
- Asset discovery via Nmap network sweep
- Auto-discovery of subdomains via DNS enumeration

### 1.3 Cross-Customer Analytics
- Dashboard view across all managed customers
- Aggregate vulnerability count by severity across all tenants
- Identify common vulnerabilities affecting multiple customers
- Trend comparison between customers (rating history)
- Export cross-customer summary as PDF

---

## 2. External Scanning

### 2.1 Network Scan (via Greenbone/OpenVAS)
- Full CVE scan against external IPs and hostnames
- Port enumeration (TCP/UDP, top 1000 ports or full range)
- Service fingerprinting and version detection
- OS detection
- 120,000+ CVE checks with daily feed updates
- Scan profiles: `Fast`, `Full`, `Stealth`

### 2.2 Web Application Scan (via OWASP ZAP)
- OWASP Top 10 coverage
- Active + passive scanning modes
- Auth-aware scanning (form login, Bearer token)
- Spider/crawler to map all endpoints
- API scanning (OpenAPI/Swagger spec upload)
- Checks: XSS, SQLi, SSRF, CSRF, open redirects, insecure headers, exposed admin panels

### 2.3 Fast Template Scan (via Nuclei)
- 9,000+ community templates
- Tech stack detection (CMS, frameworks, server versions)
- Exposed admin panels (Grafana, Kibana, phpMyAdmin, etc.)
- Subdomain takeover detection
- SSL/TLS misconfiguration (expired certs, weak ciphers)
- DNS misconfiguration (SPF, DMARC, DKIM)
- CVE-specific checks for known exploitable software

### 2.4 Email & Credential Breach Check (via HaveIBeenPwned)
- Bulk email address check for breach exposure
- Password hash lookup
- Domain-level breach history
- Returns breach name, date, exposed data types

### 2.5 Mail Server Security
- SPF record validation
- DMARC policy check
- DKIM verification
- Mail relay open relay test
- STARTTLS enforcement check

---

## 3. Internal Scanning (Endpoint Agent)

### 3.1 Wazuh Agent Deployment
- Agent installer generation per customer (pre-configured)
- Supported platforms: Windows 10/11/Server 2016+, Ubuntu/Debian/RHEL, macOS
- Silent/GPO deployment support for Windows
- Agent auto-registration with manager via enrollment key

### 3.2 Software Inventory
- Full installed software list with versions
- Application last-used timestamps
- Browser extensions inventory
- Windows services enumeration

### 3.3 Vulnerability Detection
- Continuous CVE correlation against software inventory
- Wazuh CTI feed: updated CVE definitions daily
- Severity classification (Critical/High/Medium/Low/Info)
- Affected software version range matching
- Alerts on newly published CVEs matching installed software

### 3.4 Patch Status
- Missing Windows Updates (KB IDs)
- Missing Linux package updates (apt/yum/dnf)
- Third-party software patch gaps (Chrome, Firefox, Java, Adobe, etc.)

### 3.5 Security Configuration Assessment (CIS Benchmarks)
- CIS Benchmark checks for Windows, Ubuntu, macOS
- Hardening gap identification
- Pass/Fail per control with remediation guidance
- Compliance mapping (CIS Level 1 / Level 2)

### 3.6 Firewall & AV Status
- Windows Defender / third-party AV active status
- Windows Firewall state (Domain/Private/Public profiles)
- Firewall rule enumeration (excessive open rules flagged)
- Real-time protection enabled/disabled

### 3.7 File Integrity Monitoring (FIM)
- Monitor critical system paths for changes
- Alert on unexpected modifications to system files
- User and process attribution for file changes

---

## 4. Vulnerability Management

### 4.1 Finding Normalization
- All findings from all scanners normalized into unified schema
- Fields: title, CVE ID, CVSS score, EPSS score, severity, asset, description, evidence, remediation
- Deduplication across scanners (same CVE on same host = single finding)
- DefectDojo as deduplication engine

### 4.2 CVSS Scoring
- CVSS v3.1 base score display
- Score breakdown: AV, AC, PR, UI, S, C, I, A vectors
- Environmental score adjustment (optional)

### 4.3 EPSS Enrichment
- Exploit Prediction Scoring System score per CVE (FIRST.org API)
- Percentile ranking (e.g. "Top 5% most likely to be exploited")
- Combined risk priority: CVSS severity × EPSS likelihood

### 4.4 Remediation Tracking
- Status per finding: `Open`, `In Progress`, `Resolved`, `Accepted Risk`, `False Positive`
- Assignee per finding
- Due date with SLA breach alerting
- Resolution notes
- Verification re-scan after remediation

### 4.5 False Positive Management
- Mark findings as false positive with justification
- Suppress finding across future scans
- Audit log of suppression decisions

---

## 5. Security Rating Engine

### 5.1 A–F Rating Calculation
Rating computed from weighted categories:

| Category | Weight | Source |
|---|---|---|
| Patch Management | 25% | Wazuh patch status |
| Network Exposure | 20% | OpenVAS findings |
| Web Security | 15% | ZAP + Nuclei |
| Endpoint Security | 15% | Wazuh SCA, AV, FIM |
| Email Security | 10% | SPF/DMARC/DKIM checks |
| Credential Exposure | 10% | HIBP breach data |
| Ransomware Readiness | 5% | Backup check (questionnaire) |

### 5.2 Rating History
- Rating tracked per scan over time
- Trend graph: improvement or deterioration
- Compare rating before/after remediation sprint

### 5.3 House Analogy Visualisation
- Customer-friendly visual metaphor
- Each security category = part of house
- Open front door = weak/missing password policy
- Cracked walls = unpatched critical CVEs
- Broken roof = email security failures
- Non-technical customers can immediately understand their situation

### 5.4 Ransomware Readiness Score
- Sub-score specifically for ransomware susceptibility
- Checks: AV status, macro security, patch level, backup questionnaire, web traffic filtering
- A–F sub-rating displayed separately

---

## 6. Reporting & Communication

### 6.1 Executive Report (PDF)
- White-labeled PDF per customer
- Security rating + trend
- Top 10 critical findings
- House analogy page for non-technical readers
- Remediation summary (what was fixed since last report)
- Recommended next actions

### 6.2 Technical Report (PDF)
- Full finding list with CVE IDs, CVSS scores, EPSS
- Evidence and proof-of-concept details
- Detailed remediation steps per finding
- Asset inventory

### 6.3 Scheduled Report Delivery
- Automated monthly/quarterly report emails
- Configurable per customer
- Branded email templates
- Report archive per customer

### 6.4 Real-Time Alerts
- Email alert on new Critical/High severity finding
- Webhook support (Teams, Slack, custom)
- Alert thresholds configurable per customer

---

## 7. White-Label & Branding

### 7.1 Per-Customer Branding
- Custom logo (uploaded PNG/SVG)
- Primary colour scheme (hex input)
- Custom subdomain: `customer.securesync.nexo-ai.ch` (or custom domain)
- Branded login page
- Branded email templates (sender name, footer, logo)

### 7.2 MSP Branding
- NEXO AI partner can white-label entire platform under own brand
- Custom domain support with automatic SSL (Let's Encrypt)
- Nginx virtual host per white-label domain

---

## 8. Integrations

### 8.1 NinjaOne RMM
- Push findings as tickets directly into NinjaOne
- Severity → NinjaOne priority mapping
- Bidirectional status sync (resolved in NinjaOne → resolved in SecureSync)
- Asset matching by hostname

### 8.2 Autotask PSA (Phase 3)
- Auto-create service tickets per Critical/High finding
- Customer mapping by Autotask account ID
- SLA tracking via Autotask ticket priority

### 8.3 Open REST API
- Full OpenAPI 3.0 spec (auto-generated by FastAPI)
- API key authentication per tenant
- Endpoints: tenants, targets, scans, findings, ratings, reports
- Webhook delivery for scan completion events (HMAC-signed)

### 8.4 Microsoft 365 (Phase 3)
- Azure AD app registration check (OAuth apps with excessive permissions)
- M365 Secure Score API integration
- MFA enforcement status check

---

## 9. Customer Portal

### 9.1 Read-Only Customer Access
- Customers get login to their own white-labeled portal
- View: current rating, findings list, report history
- Cannot modify any settings or trigger scans
- Download their own reports

### 9.2 Customer Questionnaire
- MSP sends digital questionnaire to customer
- Collects non-technical data: backup routine, security awareness training, BCP
- Questionnaire responses feed into rating calculation

---

## 10. Platform Administration

### 10.1 User Management
- Invite team members via email
- Role assignment
- MFA enforcement (TOTP)
- Session management (active sessions, revoke)

### 10.2 Scan Scheduling
- Configurable intervals per customer: daily, weekly, monthly, custom cron
- Maintenance window exclusions (no scans during business hours if desired)
- Scan queue management with priority

### 10.3 Audit Log
- Full audit trail: who triggered what scan, who changed findings, who accessed reports
- Immutable log (append-only)
- Export for compliance evidence

### 10.4 Platform Health Dashboard
- Scanner cluster status (OpenVAS, ZAP, Nuclei, Wazuh Manager)
- Scan queue depth and processing times
- API rate limit usage (HIBP, EPSS, NVD)
- Error rate monitoring
