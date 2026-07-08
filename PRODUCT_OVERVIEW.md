# MSTE v2 — Complete Product Overview

> **Modular Security Testing Engine v2.0**  
> A full-stack, multi-tenant penetration-testing platform for automated vulnerability assessment, continuous security monitoring, and professional report generation.

---

## Table of Contents

1. [What Is MSTE v2?](#1-what-is-mste-v2)
2. [System Architecture](#2-system-architecture)
3. [Data Flow: How a Scan Works](#3-data-flow-how-a-scan-works)
4. [Security Model](#4-security-model)
5. [Key Features](#5-key-features)
6. [The Scan Orchestrator](#6-the-scan-orchestrator)
7. [The Parser Layer](#7-the-parser-layer)
8. [The Frontend](#8-the-frontend)
9. [Deployment Options](#9-deployment-options)
10. [Improvements Made in This Session](#10-improvements-made-in-this-session)
11. [File Inventory](#11-file-inventory)

---

## 1. What Is MSTE v2?

MSTE v2 is a **web-based penetration testing orchestration platform** designed for security teams, red teams, and MSSPs. It allows analysts to:

- **Create engagements** — scoped security assessments per client
- **Launch multi-tool scans** — Web, SAST, Infrastructure, Cloud, and Mobile
- **Track findings** — normalized, deduplicated, with evidence and analyst notes
- **Generate PDF reports** — professional pentest reports with custom branding
- **Compare re-tests** — delta views showing new, recurring, and resolved findings
- **Monitor in real-time** — live scan logs via Server-Sent Events
- **Export data** — CSV exports, webhook notifications, full audit trails

It is **not** a vulnerability scanner itself — it is an **orchestrator** that runs best-in-class open-source tools (Nuclei, ZAP, Semgrep, Trivy, Nmap, ScoutSuite, MobSF, etc.) in Docker containers, normalizes their outputs, and presents them in a unified interface.

---

## 2. System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER (Browser)                                  │
│  React 18 SPA → TanStack Query → React Router → JWT in sessionStorage       │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              FastAPI Backend                                 │
│  Async REST API → Pydantic v2 → SQLAlchemy 2.0 → asyncpg → PostgreSQL       │
│  Health probes: /health/live (process) /health/ready (DB + Redis)           │
│  Rate limiting: slowapi on auth + scan endpoints                             │
│  Security headers: CSP, X-Frame-Options, X-Content-Type-Options             │
│  CORS: Explicit allowlist via env var                                       │
└─────────────────────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
  ┌────────────┐     ┌────────────┐       ┌─────────────────┐
  │ PostgreSQL │     │   Redis    │       │  Celery Workers │
  │  (asyncpg) │     │  (broker + │       │   (sync, via    │
  │  GIN idx   │     │   cache)   │       │   psycopg2)     │
  └────────────┘     └────────────┘       └─────────────────┘
                                                 │
                    ┌────────────────────────────┼────────────────────────────┐
                    │                            │                            │
                    ▼                            ▼                            ▼
            ┌──────────────┐            ┌──────────────┐            ┌──────────────┐
            │ worker-web   │            │ worker-sast  │            │ worker-infra │
            │ Nuclei, ZAP  │            │ Semgrep,     │            │ Nmap, Cloud, │
            │ ffuf, Katana │            │ Trivy,       │            │ Mobile       │
            │ SQLmap, SSL  │            │ Gitleaks     │            │              │
            └──────────────┘            └──────────────┘            └──────────────┘
                    │                            │                            │
                    └────────────────────────────┼────────────────────────────┘
                                                 │
                                                 ▼
                                        ┌──────────────┐
                                        │ Docker daemon│
                                        │ (containers) │
                                        └──────────────┘
```

### Technology Stack

| Layer | Technology | Version |
|---|---|---|
| **Frontend** | React + Vite + TypeScript + TanStack Query | React 18, Vite 5 |
| **Backend** | FastAPI + uvicorn (uvloop) | Python 3.12 |
| **ORM** | SQLAlchemy 2.0 (async) | 2.0+ |
| **Validation** | Pydantic v2 | 2.0+ |
| **Workers** | Celery + Redis | Celery 5.4 |
| **Database** | PostgreSQL 16 | 16 |
| **Cache/Broker** | Redis 7 | 7 |
| **PDF Engine** | WeasyPrint + Jinja2 | latest |
| **Infra** | Docker Compose / K8s + Helm + KEDA | Helm 3 |

---

## 3. Data Flow: How a Scan Works

### Step-by-Step: Web Scan Example

```
1. USER clicks "New Scan" in React SPA
   → POST /api/engagements/{id}/scans
   → Body: { scan_type: "web", target: "https://app.example.com",
             auth_header: "Bearer eyJ...", enable_katana: true }

2. FASTAPI validates → creates Scan row (status: "Queued")
   → Returns ScanOut with scan_id and celery_task_id
   → Frontend opens SSE stream: GET /api/scans/{scan_id}/stream

3. CELERY WORKER (web queue) picks up the task
   → run_web_scan.delay(scan_id, target, folder, options)
   → Status updates to "Running" via _update_scan_status()
   → Publishes progress lines to Redis: scan:{id}:progress

4. WORKER spawns scan.sh as subprocess (with 4h timeout)
   → scan.sh launches background Docker containers:
      • mste_nuclei_{hash}    (detached, --memory 1g --cpus 1.0)
      • mste_ffuf_{hash}      (detached, --memory 512m --cpus 0.5)
      • mste_katana_{hash}    (detached, --memory 1g --cpus 1.0)
      • mste_sqlmap_{hash}    (detached, --memory 512m --cpus 0.5)
      • mste_testssl_{hash}   (detached, --memory 512m --cpus 0.5)
   → Foreground: ZAP active scan with curl API calls
      (all curls have --connect-timeout 5 --max-time 30)

5. scan.sh WAITS for all containers (timeout 7200 = 2h)
   → Captures container logs to output dir before removal
   → Returns exit code to worker

6. WORKER parses all output files
   → _parse_web_findings() → parse_nuclei, parse_zap, parse_ffuf, etc.
   → Each finding goes through _upsert_finding()
   → Dedup hash prevents duplicates across re-scans
   → tool_count increments if same finding confirmed by multiple tools

7. WORKER marks scan "Completed"
   → _update_scan_status() publishes to Redis status channel
   → SSE stream receives "event: end" → closes connection
   → If webhook_url configured: HMAC-signed POST dispatched

8. USER sees findings in the Findings page
   → Filterable by severity, status, tool, scan, engagement
   → Analyst can update status, add notes, create manual findings
```

---

## 4. Security Model

### Authentication
- **JWT tokens** with 8-hour expiry, refresh endpoint
- Tokens stored in **sessionStorage** (survives F5, dies with tab close)
- Frontend API client stores token in **module-level memory** (never localStorage)
- Passwords hashed with **bcrypt** (work factor 12)
- Rate limiting on login, refresh, and change-password endpoints

### Authorization (RBAC)

| Role | Permissions |
|---|---|
| **Admin** | Full access: all engagements, user management, audit logs, report templates, delete |
| **Analyst** | CRUD on own engagements, start/cancel scans, update findings, create manual findings |
| **Viewer** | Read-only: view own engagements, findings, reports; cannot start scans or edit |

- Every engagement-scoped route checks `_get_engagement_or_403()`
- Every finding-scoped route verifies engagement ownership
- SSE stream endpoint now verifies scan ownership before streaming

### Input Security
- **SSRF Prevention**: Pydantic validators block RFC1918, link-local, and internal hostnames
- **Command Injection Prevention**: Array-based args in subprocess, `shlex.quote()`, dash-led targets rejected
- **ZAP API Key**: Passed exclusively via `X-ZAP-API-Key` header (never in URL query params)
- **PDF Injection Mitigation**: Jinja2 `autoescape=True` prevents HTML/JS in WeasyPrint output
- **Webhook Validation**: URL must be http(s) with public hostname; SSRF blocklist enforced

### Audit & Monitoring
- **Every mutating action** logged: user, IP, target, timestamp, detail
- Audit log stored in DB, paginated, filterable by action/user
- **Structured JSON logging** in production with scan_id, engagement_id, user_id
- **User cache** in Redis (5-min TTL) with immediate invalidation on role/password changes

---

## 5. Key Features

### Engagements
- Scoped assessments per client with CIDR, hostname glob, and URL prefix validation
- Status lifecycle: Draft → Active → Archived
- Per-engagement webhook with HMAC-SHA256 signed deliveries
- Report template override (per-engagement or global default)
- Scope warnings when scan targets fall outside declared scope

### Scan Types

| Type | Tools | What It Finds |
|---|---|---|
| **Web** | Nuclei, ZAP, ffuf, Katana, SQLmap, testssl | OWASP Top 10, misconfigurations, XSS, SQLi, TLS issues, hidden endpoints |
| **SAST** | Semgrep, Trivy, Gitleaks, Hadolint | Code vulnerabilities, dependency CVEs, leaked secrets, Dockerfile issues |
| **Infra** | Nmap | Open ports, services, OS detection, NSE vulnerability scripts |
| **Cloud** | ScoutSuite, Prowler | AWS/GCP/Azure misconfigurations, CIS benchmark violations |
| **Mobile** | MobSF | Android/iOS app security: permissions, hardcoded secrets, SSL pinning |

### Findings
- **Deduplication**: SHA-256 hash of `tool:name:location` prevents duplicates across re-scans
- **tool_count**: Tracks how many tools confirmed the same finding
- **Status**: Open → Confirmed → False Positive → Fixed → Reopened
- **Evidence**: Request/response pairs, code snippets, log excerpts, MobSF reports
- **Analyst Notes**: Markdown-supported, for exploitability confirmation or false-positive rationale
- **CVSS Scoring**: Automatic mapping from severity; manual override supported
- **Bulk Operations**: Update status on multiple findings at once

### Delta / Re-test
- Compare any two completed scans within an engagement
- Buckets: **New** (present now, absent before), **Recurring** (still there), **Resolved** (fixed)
- Sorted by severity then CVSS score

### Reports
- **PDF Export**: WeasyPrint-rendered professional pentest reports
- Custom templates with logo upload, cover page, executive summary
- Default template includes: severity grid, findings table, detailed findings with evidence, scan coverage
- Safety cap: 5,000 findings max per report (with logged warning)

### Search
- Global search across findings, engagements, and scans
- `ILIKE` pattern matching with `pg_trgm` GIN indexes for performance
- Scoped search by engagement or finding status

---

## 6. The Scan Orchestrator (`scan.sh`)

`scan.sh` is the heart of the execution layer. It is a bash script called by Celery workers that:

1. **Validates the target** — pre-flight HTTP check with timeout
2. **Resolves networking** — remaps `localhost` → `host.docker.internal`
3. **Launches background containers** — all tools run concurrently in detached mode
4. **Runs ZAP active scan** — spider → active scan → XML export (foreground, blocking)
5. **Waits for completion** — `timeout 7200 docker wait` on each container
6. **Captures logs** — `docker logs` saved to output directory before removal
7. **Cleans up** — trap-based container removal on exit

### Resource Limits (New)
Every container now has `--memory` and `--cpus` limits:

| Tool | Memory | CPUs | Env Override |
|---|---|---|---|
| Nuclei | 1g | 1.0 | `NUCLEI_MEMORY_LIMIT`, `NUCLEI_CPUS_LIMIT` |
| ffuf | 512m | 0.5 | — |
| Katana | 1g | 1.0 | — |
| SQLmap | 512m | 0.5 | `SQLMAP_MEMORY_LIMIT`, `SQLMAP_CPUS_LIMIT` |
| testssl | 512m | 0.5 | — |

### Timeouts (New)
- `curl` to ZAP API: `--connect-timeout 5 --max-time 30`
- `docker wait`: `timeout 7200` (2 hours)
- Worker subprocess: `threading.Timer(14400, proc.kill)` (4 hours)

---

## 7. The Parser Layer (`parsers.py`)

The parser layer normalizes 12 different tool output formats into a unified finding schema:

| Parser | Input Format | Output |
|---|---|---|
| `parse_nuclei` | JSONL | Web vulnerabilities with request/response evidence |
| `parse_zap` | XML | Active scan findings with instances as evidence |
| `parse_ffuf` | JSON | Discovered endpoints with status code descriptions |
| `parse_katana` | JSONL | Crawled URLs |
| `parse_testssl` | JSON | TLS/SSL issues with remediation hints |
| `parse_sqlmap` | XML + log | SQL injection confirmations with payloads |
| `parse_semgrep` | JSON | Code vulnerabilities with code snippet evidence |
| `parse_trivy` | JSON | CVEs, secrets, misconfigurations |
| `parse_gitleaks` | JSON | Leaked secrets in git history |
| `parse_hadolint` | JSON | Dockerfile issues |
| `parse_nmap` | XML | Open ports, services, NSE script results |
| `parse_scoutsuite` | JSON | Cloud misconfigurations |
| `parse_prowler` | JSON | AWS compliance failures |
| `parse_mobsf` | JSON | Mobile app security findings |

Each parser is a **generator** that yields dicts compatible with `_upsert_finding()`.

---

## 8. The Frontend

### Pages

| Route | Page | What It Does |
|---|---|---|
| `/` | Dashboard | Active engagements, critical open findings, quick stats |
| `/engagements` | Engagements list | All engagements with status, client, dates |
| `/engagements/new` | New Engagement | Create engagement with scope and webhook |
| `/engagements/:id` | Engagement Detail | Scans, delta, scope editor, settings, report export |
| `/findings` | Findings list | Paginated, filterable findings across all engagements |
| `/findings/:id` | Finding Detail | Full finding with evidence, status update, notes |
| `/search` | Global Search | Search findings, engagements, scans |
| `/profile` | Profile | Change password |
| `/admin/users` | Admin Users | User CRUD, role assignment (Admin only) |
| `/admin/audit` | Audit Log | Paginated audit trail (Admin only) |
| `/admin/report-templates` | Report Templates | Template management, logo upload (Admin only) |

### State Management
- **TanStack Query** (React Query) for server state — caching, invalidation, polling
- **Auth Context** for JWT lifecycle — login, logout, session restore
- **Custom hooks** (`hooks.ts`) wrap every API call with automatic cache invalidation

### Real-Time Scan Logs
- **EventSource** connects to `/api/scans/{id}/stream`
- Parses JSON progress events, color-codes by level (error=red, success=green, warning=yellow)
- Falls back to polling `scanStatus` if SSE fails

---

## 9. Deployment Options

### Docker Compose (Development / Small Teams)
```yaml
# 7 services: api, frontend, postgres, redis, worker-web, worker-sast, worker-infra
# Scan artifacts volume shared between api and workers
# Docker socket mounted into workers for container orchestration
```

### Kubernetes + Helm (Production)
- **Helm chart** with Bitnami sub-charts for PostgreSQL and Redis
- **KEDA autoscaling** — scales workers by queue depth (3 jobs/replica)
- **Separate worker Deployments** — web, sast, infra scale independently
- **Ingress** — nginx with TLS via cert-manager
- **RBAC** — least-privilege Role/RoleBinding for scan Jobs
- **PodSecurity** — `restricted` standard on scan namespace
- **Health probes** — liveness (`/health/live`) vs readiness (`/health/ready`)

### Phase 3: Kubernetes Jobs Executor (Future)
- Eliminates Docker socket mounting in workers
- Each scan becomes a Kubernetes Job with rootless container
- Security context: non-root, drop ALL capabilities, read-only root FS

---

## 10. Improvements Made in This Session

### 🔴 High Priority (Security & Robustness)

| # | Fix | File | Impact |
|---|---|---|---|
| 1 | SSE stream ownership check — 403 for non-owners | `findings.py` | Prevents scan data leakage via progress streams |
| 2 | Curl timeouts on all ZAP API calls | `scan.sh` | Prevents hung ZAP daemon from stalling scans |
| 3 | `timeout 7200` on `docker wait` | `scan.sh` | Prevents hung containers from blocking indefinitely |
| 4 | `threading.Timer(14400)` on subprocess | `tasks.py` | Kills hung scan.sh / Docker runs after 4h |
| 5 | Secure GCP creds via `tempfile.mkstemp` | `tasks.py` | `0o600` permissions, random suffix, dynamic cleanup |
| 6 | Remove `docker.io` from API image | `Dockerfile` | Reduces attack surface on API container |

### 🟡 Medium Priority (Performance & Operations)

| # | Fix | File | Impact |
|---|---|---|---|
| 7 | Container resource limits (`--memory`, `--cpus`) | `scan.sh` | Prevents runaway tools from consuming all host resources |
| 8 | Unified `result_expires=300` on all scan types | `tasks.py` | Limits sensitive data (auth headers, tokens) in Redis |
| 9 | Container log capture before removal | `scan.sh` | Tool stdout/stderr saved to output dir for debugging |
| 10 | GIN trigram indexes for search | `0007_gin_search_indexes.py` | Accelerates `ILIKE` search at scale |
| 11 | Security scanning CI (bandit, semgrep, pip-audit) | `ci.yml` | Catches vulnerabilities in the codebase itself |
| 12 | Frontend build + lint CI | `ci.yml` | Catches TypeScript and build errors before merge |

### 🟢 Low Priority (Code Quality)

| # | Fix | File | Impact |
|---|---|---|---|
| 13 | `func.now()` replaces `lambda` datetime defaults | `models.py` | Database-side timestamps, no Python clock skew |
| 14 | `tool_count` column for multi-tool confirmation | `models.py` + `0008_tool_count.py` | Track findings confirmed by multiple tools |
| 15 | Fixed `finding_count` comment in schemas | `schemas.py` | Correct documentation |
| 16 | `SQLMAP_LEVEL` / `SQLMAP_RISK` env vars | `scan.sh` | Tunable SQLmap detection depth |
| 17 | `MAX_REPORT_FINDINGS=5000` safeguard | `report.py` | Prevents memory exhaustion on huge engagements |

---

## 11. File Inventory

### Backend (`api/`)

| File | Lines | Purpose |
|---|---|---|
| `main.py` | 80 | FastAPI app factory, lifespan (DB engine, Redis), middleware, health probes |
| `config.py` | 50 | Pydantic Settings, env var validation, sync DB URL conversion |
| `models.py` | 270 | SQLAlchemy 2.0 ORM: User, Engagement, Scan, Finding, Evidence, AuditLog, ReportTemplate |
| `schemas.py` | 390 | Pydantic v2 request/response models, validators, scope/webhook validation |
| `auth.py` | 100 | JWT encode/decode, password hashing, role-based FastAPI dependencies |
| `database.py` | 40 | AsyncSessionLocal, get_db dependency, engine factory |
| `tasks.py` | 1050 | Celery app, 5 scan tasks, _docker_run, _upsert_finding, webhook dispatch |
| `parsers.py` | 1100 | 14 tool parsers (generators) normalizing to unified finding dicts |
| `report.py` | 400 | WeasyPrint PDF generation with Jinja2 template, engagement data fetching |
| `utils.py` | 60 | Audit log helper, client IP extraction, structured logging config |
| `routers/auth.py` | 120 | Login, refresh, me, change-password, rate limiting |
| `routers/engagements.py` | 700 | Engagement CRUD, scan start/cancel, scope check, delta, report export, webhook secrets |
| `routers/findings.py` | 460 | Finding list/filter, detail, status update, notes, manual creation, bulk update, SSE stream |
| `routers/search.py` | 110 | Global search across findings, engagements, scans |
| `routers/admin.py` | 220 | User management, audit log, report template management |

### Frontend (`frontend/src/`)

| File | Lines | Purpose |
|---|---|---|
| `App.tsx` | 80 | React Router with lazy-loaded routes, auth-guarded admin pages |
| `main.tsx` | 20 | React 18 root with StrictMode |
| `lib/api.ts` | 400 | Typed API client, JWT in memory, all endpoint wrappers |
| `lib/auth-context.tsx` | 80 | Auth state, sessionStorage persistence, logout invalidation |
| `lib/hooks.ts` | 300 | TanStack Query hooks for every API call with cache invalidation |
| `pages/Dashboard.tsx` | 130 | Quick stats, active engagements, critical findings |
| `pages/Engagements.tsx` | 70 | Engagement list table |
| `pages/Engagement.tsx` | 1190 | Full engagement detail: scans, delta, scope, settings, webhooks, report templates |
| `pages/Findings.tsx` | ~200 | Paginated findings with filters |
| `pages/FindingPage.tsx` | ~250 | Finding detail with evidence, status editor, notes |
| `pages/Search.tsx` | ~100 | Global search results |
| `pages/Login.tsx` | ~100 | Login form |
| `pages/Profile.tsx` | ~80 | Password change |
| `pages/Admin*.tsx` | ~400 | Admin pages (users, audit, templates) |
| `components/Layout.tsx` | ~150 | Sidebar navigation, role-based menu items |
| `components/Badges.tsx` | ~50 | Severity and status badge components |

### Infrastructure

| File | Purpose |
|---|---|
| `docker-compose.yml` | 7-service stack with resource limits and healthchecks |
| `api/Dockerfile` | Python 3.12 slim with WeasyPrint deps |
| `frontend/Dockerfile` | Multi-stage Vite build → nginx static serve |
| `scan.sh` | 500-line bash orchestrator for tool containers |
| `k8s/helm/mste/` | Helm chart with KEDA, ingress, sub-charts |
| `k8s/rbac-scan-jobs.yaml` | Least-privilege RBAC for K8s scan Jobs |
| `workers/k8s_executor.py` | Rootless K8s Job executor for Phase 3 |

### Migrations (`api/alembic/versions/`)

| Migration | Purpose |
|---|---|
| `0001_initial.py` | Base schema: all tables, indexes, pg_trgm extension |
| `0002_perf_and_integrity.py` | Performance indexes, integrity constraints |
| `0003_engagement_template_fk.py` | Report template foreign key |
| `0004_engagement_scope.py` | Scope text field |
| `0005_engagement_webhook.py` | Webhook URL field |
| `0006_engagement_webhook_secret.py` | Webhook signing secret |
| `0007_gin_search_indexes.py` | **NEW** GIN trigram indexes for search |
| `0008_tool_count.py` | **NEW** `tool_count` column on findings |

### Tests (`tests/`)

| File | Coverage |
|---|---|
| `test_auth.py` | Login, refresh, password change, role checks |
| `test_engagements.py` | CRUD, RBAC, scope warnings, delta, webhook secrets |
| `test_findings.py` | List, filter, status update, bulk update, manual creation |
| `test_parsers.py` | All 12 parsers with valid, empty, and malformed fixtures |
| `conftest.py` | Async test DB, mocked Celery, test client |

---

## Summary

MSTE v2 is a **mature, production-oriented penetration testing platform** with:

- ✅ **Strong security foundations** — JWT RBAC, SSRF blocking, HMAC webhooks, audit logging
- ✅ **Modern async architecture** — FastAPI + SQLAlchemy 2.0 + asyncpg
- ✅ **Comprehensive tool coverage** — 14 parsers across 5 scan types
- ✅ **Professional reporting** — Custom-branded PDFs with evidence
- ✅ **Real-time monitoring** — SSE progress streams with Redis pub/sub
- ✅ **Operational readiness** — Docker Compose, K8s/Helm/KEDA, health probes, resource limits
- ✅ **Continuous improvement** — Security scanning in CI, frontend build checks, Alembic migrations

The codebase is now **significantly more robust** after the session's fixes, with bounded execution times, proper ownership checks, secure credential handling, and comprehensive observability.
