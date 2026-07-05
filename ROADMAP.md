# MSTE v2 — Product Improvement Roadmap
## Helping Security Teams Work More Efficiently

> This document proposes feature improvements that address real-world pain points in security operations — moving beyond "scan and report" toward a continuous security operations platform.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Category A: Remediation Workflow & Accountability](#2-category-a-remediation-workflow--accountability)
3. [Category B: Continuous Monitoring & Automation](#3-category-b-continuous-monitoring--automation)
4. [Category C: Intelligent Prioritization & Risk](#4-category-c-intelligent-prioritization--risk)
5. [Category D: Compliance & Executive Reporting](#5-category-d-compliance--executive-reporting)
6. [Category E: Developer Experience & Self-Service](#6-category-e-developer-experience--self-service)
7. [Category F: Operational Efficiency](#7-category-f-operational-efficiency)
8. [Category G: Platform Extensibility](#8-category-g-platform-extensibility)
9. [Prioritization Matrix](#9-prioritization-matrix)
10. [Recommended Next Quarter Roadmap](#10-recommended-next-quarter-roadmap)

---

## 1. Executive Summary

MSTE v2 is a capable scan orchestrator. The highest-leverage improvements now lie in **what happens after the scan** — the lifecycle of a finding from discovery through remediation, verification, and closure. Security teams don't struggle to find vulnerabilities; they struggle to **get them fixed**, **prove they were fixed**, and **report progress to leadership and auditors**.

This roadmap is organized around 7 themes that address those post-scan workflows.

---

## 2. Category A: Remediation Workflow & Accountability

### A.1 Jira / ServiceNow / Azure DevOps Integration
**The Problem:** A pentest produces 200 findings. The analyst exports a PDF. Developers never see the PDF. Three months later, the same 200 findings appear in the re-test.

**The Solution:** One-click "Create Ticket" from any finding. The integration should:
- Create a ticket in the configured tracker (Jira, ServiceNow, Azure DevOps, GitHub Issues) with finding details, evidence, and remediation guidance
- Link the ticket back to the MSTE finding (stored as `external_ticket_id`)
- Sync status bidirectionally: when Jira moves to "Done", MSTE can auto-verify via re-scan
- Support per-engagement tracker configuration (different clients use different tools)

**Backend Changes:**
- New model: `IntegrationConfig` (engagement_id, provider, url, auth_token_encrypted, project_key)
- New router: `routers/integrations.py` — CRUD for integration configs
- New Celery task: `sync_ticket_status` — periodic background sync
- New field on Finding: `external_ticket_id`, `external_ticket_url`

**Frontend Changes:**
- "Create Ticket" button on Finding detail page
- Ticket status badge (icon + status) on finding list
- Integration settings panel on Engagement settings tab

---

### A.2 Finding Assignment & Ownership
**The Problem:** A scan produces 50 findings for an engagement owned by Analyst Alice, but the actual developers who need to fix them are Bob (API), Carol (frontend), and Dave (infra). Alice becomes a bottleneck because every question routes through her.

**The Solution:** Assign individual findings to specific users (analysts or external contacts) with clear ownership.

**Implementation:**
- New field: `Finding.assigned_to` (FK to User, nullable)
- New field: `Finding.due_date` (datetime, nullable — for SLA tracking)
- Dashboard widget: "My Open Findings" for the logged-in user
- Email/notification when a finding is assigned to you
- Bulk assignment: "Assign all Critical findings in this scan to User X"

---

### A.3 Verification Scan Workflow
**The Problem:** A developer marks a finding "Fixed" in MSTE. The analyst trusts them. The re-test 3 months later shows it's still exploitable. Trust is broken.

**The Solution:** A formal verification workflow:
1. Developer marks finding "Fixed"
2. Analyst (or automated scheduler) triggers a **verification scan** — a lightweight re-scan of just that finding's target + vulnerability type
3. If the finding is absent → status moves to "Verified Fixed"
4. If the finding is still present → status moves to "Reopened" with a note

**Implementation:**
- New scan subtype: `verification` — runs only the specific tool + target that originally found the vulnerability
- New status: `Verified Fixed` (terminal)
- New status transition: `Fixed` → `Verified Fixed` or `Reopened`
- New endpoint: `POST /api/findings/{id}/verify` — triggers verification scan

---

### A.4 SLA & Due Date Tracking
**The Problem:** Security teams have SLAs (e.g., Critical = 7 days, High = 30 days) but no way to track compliance. Auditors ask "How many findings were remediated within SLA?" and the answer requires manual spreadsheet archaeology.

**The Solution:** Configurable SLA rules per engagement with automated tracking.

**Implementation:**
- New model: `SLARule` (engagement_id, severity, days, is_default)
- Auto-compute `due_date = first_seen + sla_days` when a finding is created
- New field: `Finding.due_date`, `Finding.sla_met` (bool, nullable)
- Dashboard widget: "SLA Compliance" — % of findings fixed before due date
- Alert: Email/notification when a finding is approaching due date (e.g., 2 days before)
- Report: "SLA Compliance Report" — per-engagement, per-analyst, per-quarter

---

## 3. Category B: Continuous Monitoring & Automation

### B.1 Scheduled / Recurring Scans
**The Problem:** Teams want continuous security monitoring but manually creating scans is tedious. As a result, scans happen once per quarter at best.

**The Solution:** Cron-like recurring scan schedules per engagement.

**Implementation:**
- New model: `ScanSchedule` (engagement_id, scan_type, target, cron_expr, options_json, is_active, last_run_at, next_run_at)
- Use the existing `celery-beat` service (already in docker-compose but unused)
- New Celery beat task: `check_scheduled_scans` — runs every minute, triggers scans whose `next_run_at` has passed
- Frontend: "Schedule" tab on Engagement page with a simple UI ("Daily", "Weekly", "Monthly", "Custom cron")
- Email notification on scan completion (configurable per schedule)

**Value:** Turns MSTE from a "project-based" tool into a "continuous monitoring" platform.

---

### B.2 Automated Re-test on Finding Closure
**The Problem:** A developer says "I fixed the SQL injection." The analyst has to manually schedule a re-scan to verify. This friction means verification rarely happens.

**The Solution:** When a finding is marked "Fixed", automatically queue a verification scan for that specific vulnerability within 24 hours.

**Implementation:**
- Hook into `_update_finding_status` or the finding status update endpoint
- If new status == 'Fixed', schedule a `run_verification_scan` Celery task with `countdown=86400`
- Configurable per engagement: "auto_verify_on_fix: true/false"

---

### B.3 Alerting & Notifications
**The Problem:** Users have to keep the web UI open to know when scans finish or critical findings appear.

**The Solution:** Multi-channel notification system.

**Implementation:**
- New model: `NotificationPreference` (user_id, event_type, channel, is_enabled)
- Events: `scan_completed`, `critical_finding_found`, `finding_assigned`, `sla_breach`, `verification_failed`
- Channels: In-app (badge + toast), email, Slack webhook, MS Teams webhook
- In-app notification center: bell icon in header with unread count

---

## 4. Category C: Intelligent Prioritization & Risk

### C.1 Risk Score Beyond CVSS
**The Problem:** 50 findings are marked "High." Which one do you fix first? CVSS doesn't consider whether the asset is internet-facing, contains PII, or has a public exploit.

**The Solution:** A composite risk score that factors in:
- **Base severity** (CVSS or tool severity)
- **Asset exposure** (internal vs internet-facing)
- **Asset sensitivity** (does it process PII, financial data, health data?)
- **Exploitability** (is there a public exploit? Metasploit module?)
- **Business context** (is this a revenue-critical system?)

**Implementation:**
- New field: `Finding.risk_score` (float, 0.0–10.0, computed)
- New field: `Engagement.asset_classification` (enum: `public_facing`, `internal`, `sensitive_pii`, `critical_infrastructure`)
- New service: `risk_engine.py` — computes risk score on finding creation/update
- Risk score formula (configurable): `risk = base_severity * exposure_factor * sensitivity_factor * exploitability_factor`
- Frontend: Sort findings by risk score, not just severity
- Dashboard: "Top 10 Riskiest Findings" widget

---

### C.2 Exploitability Intelligence
**The Problem:** An analyst sees CVE-2023-XXXXX but has to manually check Exploit-DB, Metasploit, and CISA KEV to know if it's actually exploitable.

**The Solution:** Automatic enrichment of findings with exploitability data.

**Implementation:**
- Background Celery task: `enrich_finding` — triggered after finding creation if `cve_id` is present
- Queries public APIs: NVD (CVSS v3), CISA KEV (known exploited vulnerabilities), Exploit-DB (public exploits)
- Stores: `Finding.exploit_available` (bool), `Finding.exploit_db_id` (str), `Finding.cisa_kev` (bool)
- Frontend: Exploit-DB link badge, "Known Exploited" warning banner on finding detail

---

### C.3 Duplicate / Noise Reduction
**The Problem:** The same vulnerability (e.g., missing HSTS header) is found by both ZAP and Nuclei. It's stored once (thanks to dedup), but the analyst still has to triage it once per tool if they review by tool.

**The Solution:** Already partially solved with `tool_count` (added in this session). Extend with:
- Auto-confirm findings found by ≥2 tools: if `tool_count >= 2`, auto-set status to "Confirmed" (bypass "Open")
- Noise suppression: Allow analysts to mark a finding pattern as "Expected / Accepted Risk" with justification. On re-scan, if the same dedup_hash appears and there's an active waiver, auto-set status to "Waived" with a reference to the waiver.

**Implementation:**
- New model: `FindingWaiver` (engagement_id, dedup_hash_pattern, justification, created_by, expires_at)
- New status: `Waived` (terminal, like False Positive)
- In `_upsert_finding`: check for matching waiver before creating/updating

---

## 5. Category D: Compliance & Executive Reporting

### D.1 Compliance Framework Mapping
**The Problem:** An auditor asks: "Show me how you address OWASP Top 10 A01:2021 – Broken Access Control." The analyst manually correlates findings to frameworks. It takes hours.

**The Solution:** Automatic mapping of findings to compliance frameworks.

**Implementation:**
- New model: `ComplianceFramework` (name: OWASP Top 10 2021, NIST CSF, ISO 27001, PCI-DSS 4.0)
- New model: `ComplianceControl` (framework_id, control_id, control_name, description)
- New model: `FindingComplianceMapping` (finding_id, control_id, confidence: auto/manual)
- Mapping logic: Use CWE + tool + vulnerability_name to infer control mapping (e.g., CWE-22 → OWASP A01:2021)
- Frontend: Filter findings by framework/control, compliance gap report
- PDF report section: "Compliance Summary" — findings grouped by framework control

---

### D.2 Executive Dashboard
**The Problem:** CISOs don't care about individual findings. They care about: "Are we getting better or worse? What's our MTTR? How many critical vulns are open?"

**The Solution:** A high-level executive dashboard with trend metrics.

**Metrics to show:**
- **Mean Time To Remediation (MTTR)** by severity — trend line over last 90 days
- **Open Critical/High findings** — count + trend
- **SLA compliance rate** — % of findings fixed within SLA
- **Scan coverage** — % of assets scanned in the last 30 days
- **Re-test success rate** — % of "Fixed" findings that passed verification
- **Top riskiest engagements** — ranked by open critical count × risk score

**Implementation:**
- New router: `routers/metrics.py` — time-series aggregation queries
- New page: `/executive` (Admin-only, or role-based)
- Use materialized views or pre-computed summary tables for performance
- Charts: Line charts for trends, bar charts for current state, pie charts for severity distribution

---

### D.3 Canned Compliance Reports
**The Problem:** Every audit requires slightly different report formats. SOC2 wants one thing, PCI-DSS wants another.

**The Solution:** Report templates tied to compliance frameworks.

**Implementation:**
- Extend `ReportTemplate` with `compliance_framework_id` (nullable)
- New report types: `executive_summary`, `full_technical`, `compliance_gap`, `remediation_tracker`
- Each type uses a different Jinja2 template
- PDF export supports all types per engagement

---

## 6. Category E: Developer Experience & Self-Service

### E.1 Scoped Developer Access
**The Problem:** Developers need to see findings for their app, but giving them "Viewer" role lets them see all engagements across all clients. In an MSSP context, this is a non-starter.

**The Solution:** Fine-grained access control where developers can be invited to specific engagements (or even specific findings) without seeing anything else.

**Implementation:**
- New model: `EngagementMember` (engagement_id, user_id, role: `analyst` | `developer` | `viewer`)
- Developers can: view findings, update status to "Fixed", add comments, view scan logs
- Developers cannot: start new scans, delete findings, export reports, view admin pages
- Invite flow: Analyst sends invite link → developer creates account → auto-assigned to engagement

---

### E.2 Finding Comments (Threaded Discussion)
**The Problem:** `analyst_notes` is a single text field. When a developer, security engineer, and product manager all need to discuss a finding, the notes become a mess.

**The Solution:** Threaded comments on findings, like GitHub issues.

**Implementation:**
- New model: `FindingComment` (finding_id, user_id, content, created_at, parent_id for threads)
- @mentions support: parse `@username` → notify user
- Frontend: Comment thread UI on Finding detail page
- Email notification on new comment if you're mentioned or if you commented previously

---

### E.3 API-First Design for CI/CD Integration
**The Problem:** Security teams want developers to run scans in CI/CD (e.g., on every PR), but MSTE is web-UI-centric.

**The Solution:** A first-class API for CI/CD integration.

**Implementation:**
- New endpoint: `POST /api/scans/trigger` — accepts API key auth (not JWT), triggers a scan, returns scan_id
- New endpoint: `GET /api/scans/{id}/summary` — lightweight JSON with finding counts by severity (for CI gating)
- New endpoint: `GET /api/scans/{id}/sarif` — export findings in SARIF format (GitHub/CodeQL compatible)
- API key management: per-engagement API keys with scopes (`scan:trigger`, `findings:read`)
- CLI tool: `mste-cli` — lightweight Python/Go CLI for CI/CD pipelines

**CI/CD Use Case:**
```yaml
# GitHub Actions example
- name: Run MSTE SAST scan
  run: mste-cli scan --engagement 42 --type sast --target .
- name: Check for Critical findings
  run: mste-cli gate --scan ${{ steps.scan.outputs.scan_id }} --max-critical 0
```

---

## 7. Category F: Operational Efficiency

### F.1 Scan Configuration Templates
**The Problem:** Every web scan requires clicking the same checkboxes: enable Katana, enable SQLmap, stealth mode. It's repetitive and error-prone.

**The Solution:** Saveable scan templates per engagement or globally.

**Implementation:**
- New model: `ScanTemplate` (name, scan_type, options_json, is_global, created_by)
- Frontend: "Use Template" dropdown when starting a scan
- Default template per engagement: "Standard Web Scan", "Deep Assessment", "Quick Smoke Test"

---

### F.2 Bulk Operations on Findings
**The Problem:** A scan produces 100 Info-level findings that are all expected (e.g., Katana discovered URLs on a public documentation site). Marking each as "False Positive" one by one takes 20 minutes.

**The Solution:** Powerful bulk operations with filtering.

**Already partially implemented:** `POST /api/findings/bulk-status`

**Extensions:**
- Bulk assign: "Assign all findings from tool=Nuclei, severity=Medium to User X"
- Bulk create tickets: "Create Jira tickets for all Open, severity≥High findings"
- Bulk export: "Export all findings with status=Open as CSV"
- Bulk waive: "Waive all findings matching pattern `Missing HSTS` with justification `Internal app, WAF handles it`"

---

### F.3 Asset Inventory
**The Problem:** The "target" field is just a string. There's no persistent record of "these are Client X's assets." When a new engagement starts, the analyst has to re-enter all targets.

**The Solution:** An asset registry per engagement.

**Implementation:**
- New model: `Asset` (engagement_id, name, type: `web_app` | `api` | `mobile_app` | `cloud_account` | `infra_host`, url/host, description, is_active)
- When starting a scan, select from asset list instead of typing a target string
- Asset-level finding aggregation: "Show me all findings for the API gateway asset"
- Asset health score: average risk score of all findings on this asset

---

### F.4 Data Retention & Archival
**The Problem:** After 2 years of continuous scanning, the database is 500GB. Old scan artifacts (JSON files, container logs) fill the disk.

**The Solution:** Configurable retention policies.

**Implementation:**
- New model: `RetentionPolicy` (engagement_id, scan_days: 90, artifact_days: 30, finding_days: 365)
- Celery beat task: `apply_retention` — daily job that:
  - Soft-deletes scans older than `scan_days`
  - Deletes artifact files older than `artifact_days`
  - Archives findings older than `finding_days` to cold storage (S3-compatible)
- Archival format: ZIP per engagement per month with findings JSON + evidence

---

## 8. Category G: Platform Extensibility

### G.1 Custom Tool Plugins
**The Problem:** A team wants to run a proprietary scanner or a new open-source tool that MSTE doesn't support. They have to fork the codebase.

**The Solution:** A plugin architecture where new tools can be added via configuration, not code.

**Implementation:**
- New model: `CustomTool` (name, docker_image, docker_args_template, output_parser: `json` | `xml` | `sarif` | `custom_script`, severity_mapping_json)
- `scan.sh` reads active custom tools from the DB and runs them alongside built-in tools
- Parser registry: map file extensions/Glob patterns to parser classes
- Admin UI: "Add Custom Tool" form

---

### G.2 SARIF Import & Export
**The Problem:** Teams use multiple scanners (Snyk, SonarQube, Checkmarx) alongside MSTE. Findings live in silos.

**The Solution:** Import findings from external scanners via SARIF, and export MSTE findings to SARIF for ingestion into other tools.

**Implementation:**
- New parser: `parse_sarif()` — reads SARIF JSON and creates Finding records
- New endpoint: `POST /api/engagements/{id}/import` — accepts SARIF file upload
- New export format: `/api/engagements/{id}/report?sarif=1` — returns SARIF JSON

---

### G.3 Webhook Marketplace
**The Problem:** Currently webhooks are simple JSON POSTs. Teams want to integrate with Slack, MS Teams, PagerDuty, email — each with different payload formats.

**The Solution:** Pluggable webhook destinations with templated payloads.

**Implementation:**
- New model: `WebhookTemplate` (name, provider: `slack` | `teams` | `pagerduty` | `generic`, payload_template, headers_json)
- Pre-built templates for Slack (block kit), MS Teams (adaptive cards), PagerDuty (events API v2)
- Jinja2 templating in payloads: `{{ finding.severity }}`, `{{ engagement.name }}`, etc.

---

## 9. Prioritization Matrix

| Feature | Team Impact | Implementation Effort | Recommended Priority |
|---|---|---|---|
| **Jira/ServiceNow Integration** | 🔴 Critical — fixes the #1 handoff problem | Medium (new model + Celery task + OAuth) | **P0 — Next Sprint** |
| **Scheduled / Recurring Scans** | 🔴 Critical — enables continuous monitoring | Low (leverage existing Celery beat) | **P0 — Next Sprint** |
| **Risk Score Beyond CVSS** | 🟡 High — solves prioritization paralysis | Medium (new service + formula tuning) | **P1 — Next Quarter** |
| **Executive Dashboard** | 🟡 High — unlocks leadership buy-in | Medium (aggregation queries + charts) | **P1 — Next Quarter** |
| **Finding Assignment & SLA** | 🟡 High — drives accountability | Low (new fields + UI) | **P1 — Next Quarter** |
| **Verification Scan Workflow** | 🟡 High — closes the trust gap | Medium (new scan subtype + status flow) | **P1 — Next Quarter** |
| **Scoped Developer Access** | 🟡 High — enables self-service | Low (new model + permission check) | **P1 — Next Quarter** |
| **Compliance Framework Mapping** | 🟡 High — massive audit time savings | Medium (seed data + mapping logic) | **P2 — Q2** |
| **Notification Center** | 🟢 Medium — quality of life | Low (in-app only; email is harder) | **P2 — Q2** |
| **SARIF Import/Export** | 🟢 Medium — ecosystem interoperability | Low (SARIF is well-documented) | **P2 — Q2** |
| **Exploitability Intelligence** | 🟢 Medium — analyst productivity | Medium (external API integrations) | **P2 — Q2** |
| **Scan Configuration Templates** | 🟢 Medium — analyst convenience | Low (new model + dropdown) | **P2 — Q2** |
| **Asset Inventory** | 🟢 Medium — better organization | Medium (new model + CRUD UI) | **P3 — Q3** |
| **Data Retention & Archival** | 🟢 Medium — operational necessity | Medium (Celery task + S3 integration) | **P3 — Q3** |
| **Custom Tool Plugins** | 🟢 Medium — platform extensibility | High (plugin architecture design) | **P3 — Q3** |
| **Webhook Marketplace** | 🟢 Low — nice to have | Low (template system) | **P3 — Q3** |
| **Finding Comments** | 🟢 Low — collaboration | Low (new model + thread UI) | **P3 — Q3** |
| **CI/CD API & CLI** | 🟢 Low — advanced use case | Medium (API key auth + CLI tool) | **P3 — Q3** |

---

## 10. Recommended Next Quarter Roadmap

### Sprint 1–2: Foundation for Accountability
1. **Jira/ServiceNow Integration** — The #1 blocker for operationalizing findings
2. **Finding Assignment** — `assigned_to` + `due_date` + "My Findings" dashboard
3. **Notification Center** — In-app notifications for scan completion, assignment, SLA breach

### Sprint 3–4: Continuous Monitoring
4. **Scheduled Scans** — Cron schedules per engagement using existing Celery beat
5. **Verification Scan Workflow** — Auto-verify when finding is marked Fixed
6. **Risk Score Engine** — Composite score with exposure × sensitivity × exploitability

### Sprint 5–6: Executive & Compliance
7. **Executive Dashboard** — MTTR trends, SLA compliance, open critical counts
8. **Compliance Framework Mapping** — OWASP Top 10 + NIST CSF auto-mapping
9. **Scoped Developer Access** — Invite developers to specific engagements

### Sprint 7–8: Polish & Extensibility
10. **SARIF Import/Export** — Interoperability with Snyk, SonarQube, GitHub
11. **Scan Configuration Templates** — Saveable templates for common scan types
12. **Asset Inventory** — Persistent asset registry per engagement

---

## Closing Thought

> The best security platform isn't the one that finds the most vulnerabilities. It's the one that ensures the most vulnerabilities get fixed.

MSTE v2 already finds vulnerabilities exceptionally well. The next phase of maturity is about **closing the loop** — from discovery → assignment → remediation → verification → reporting. The features in this roadmap are designed to make that loop as tight and frictionless as possible.
