# MSTE v2 — Codebase Review

## Executive Summary

MSTE v2 (Modular Security Testing Engine) is a full-stack penetration-testing platform with a **FastAPI** async backend, **React SPA** frontend, **Celery** workers, **PostgreSQL**, and **Redis**. It supports docker-compose and Kubernetes (Helm + KEDA) deployments, and includes a mature security model with JWT auth, RBAC, audit logging, and SSRF protection.

**Overall verdict:** Solid, production-oriented architecture with strong security foundations and clean separation of concerns. There are a few areas where robustness, edge-case handling, and operational safety could be tightened.

---

## 1. Architecture Overview

| Layer | Technology | Notes |
|---|---|---|
| **Frontend** | React 18 + Vite + TanStack Query + React Router v6 | Lazy-loaded routes, dark-themed SPA |
| **Backend** | FastAPI + uvicorn (uvloop) + SQLAlchemy 2.0 (async) | Fully async, Pydantic v2 validation |
| **Workers** | Celery + Redis (3 queues: web, sast, infra) | Docker-based tool execution |
| **Database** | PostgreSQL 16 (asyncpg runtime, psycopg2 Alembic) | Alembic migrations, GIN/pg_trgm extensions |
| **Cache / Broker** | Redis 7 | Celery broker, SSE pub/sub, user cache |
| **Infra** | docker-compose + Helm/K8s + KEDA autoscaling | Phase 3 includes K8s Jobs executor (rootless) |
| **Reports** | WeasyPrint + Jinja2 | PDF generation with autoescape |

### Key Design Decisions (Good)
- **Async throughout**: Routes, DB queries, and SSE streaming are all non-blocking.
- **Stateless JWT**: Scales horizontally; no session affinity needed.
- **Redis-backed SSE**: Progress streaming uses pub/sub rather than DB polling.
- **Phase 3 security roadmap**: Docker socket elimination via Sysbox or K8s Jobs.

---

## 2. Strengths

### 2.1 Security Model
- **JWT with role-based access control**: `Admin`, `Analyst`, `Viewer` roles enforced via FastAPI dependencies.
- **SSRF prevention**: Pydantic validators block RFC1918/link-local targets and internal hostnames (`localhost`, `metadata.google.internal`).
- **Webhook HMAC signing**: Uses `secrets.token_hex(32)` + HMAC-SHA256 with timestamped payloads.
- **Command injection prevention**: Array-based args in `subprocess`, `shlex.quote()` for dynamic variables, dash-led targets rejected.
- **PDF injection mitigation**: Jinja2 `autoescape=True` prevents HTML/JS injection into WeasyPrint output.
- **Audit logging**: Every mutating action recorded with user, IP, target, and detail.
- **Rate limiting**: `slowapi` on login, refresh, change-password, and scan endpoints.
- **CORS**: Explicit allowlist via environment variable.
- **Security headers**: X-Frame-Options, X-Content-Type-Options, Referrer-Policy, CSP.

### 2.2 Code Quality
- **Pydantic v2 schemas**: Request/response validation on every route; automatic OpenAPI docs.
- **SQLAlchemy 2.0**: Modern declarative style with `Mapped[]`, `mapped_column()`.
- **Database indexes**: Well-chosen composite indexes (`ix_findings_scan_severity`, `ix_findings_scan_status`, etc.) for common query patterns.
- **Health probes**: Proper K8s liveness/readiness split (`/health/live` vs `/health/ready`).
- **Structured JSON logging**: Production logs are JSON with `scan_id`, `engagement_id`, `user_id` promotion.
- **User caching**: Redis cache for user records (5-min TTL) with immediate invalidation on role/password changes.
- **Admin bypasses cache**: `require_admin` always hits the DB to prevent stale privilege escalation.

### 2.3 Testing
- **Comprehensive test suite**: ~2,500+ lines across auth, engagements, findings, and parser tests.
- **Mocked Celery**: Tests never connect to Redis broker; tasks are mocked.
- **In-memory SQLite**: Fast, isolated tests via `aiosqlite`.
- **Parser fixtures**: Every parser tested with valid, empty, and malformed inputs.
- **CI pipeline**: Shellcheck, pytest (Python 3.11 + 3.12), Docker build, Alembic migration smoke test.

### 2.4 Operations
- **Alembic migrations**: Versioned schema migrations; no `db.create_all()` in production.
- **Resource limits**: Docker Compose includes CPU/memory limits for all services.
- **K8s RBAC**: Least-privilege `Role`/`RoleBinding` for scan Jobs (`k8s/rbac-scan-jobs.yaml`).
- **PodSecurity**: `restricted` PodSecurity standard enforced on `mste-scans` namespace.
- **K8s executor**: `k8s_executor.py` implements rootless scan jobs with security context (non-root, drop ALL capabilities, read-only root FS option).

---

## 3. Areas for Improvement & Concerns

### 3.1 🔴 Security — Medium Risk

#### 3.1.1 ZAP API Key in URL Query Parameters (scan.sh)
- **Issue**: Lines 344–346 and 362–363 pass the ZAP API key as a URL query parameter (`api.key=${ZAP_API_KEY}`) for some endpoints, while other endpoints use the `X-ZAP-API-Key` header. Query parameters appear in proxy logs, access logs, and `ps aux` output.
- **Impact**: API key exposure in logs/process listings.
- **Recommendation**: Ensure the ZAP API key is **only** passed via the `X-ZAP-API-Key` header for all endpoints. The ZAP daemon supports this consistently.

#### 3.1.2 `scan.sh` runs `docker run` with `-d` but no resource limits
- **Issue**: Background tool containers (Nuclei, ffuf, Katana, SQLmap, testssl) are launched without `--memory` or `--cpus` limits.
- **Impact**: A runaway tool (e.g., Katana on an infinite SPA, SQLmap on a huge DB) can consume all host resources.
- **Recommendation**: Add `--memory` and `--cpus` flags to all `docker run` commands in `scan.sh`, configurable via environment variables.

#### 3.1.3 SQLmap `--level=1 --risk=1` is mild
- **Issue**: SQLmap runs with default level/risk, which may miss time-based or stacked-query injections.
- **Impact**: False negatives on subtle SQL injection vulnerabilities.
- **Recommendation**: Consider exposing `--level` and `--risk` as scan options, or default to `--level=2 --risk=1` for a better balance.

#### 3.1.4 GCP credentials written to disk (tasks.py)
- **Issue**: Cloud scan for GCP writes `gcp-credentials.json` to the output directory (line 752–753), then deletes it after (line 830–832). If the worker crashes between write and delete, the credential file persists.
- **Impact**: Long-lived service account key on disk.
- **Recommendation**: Write to a `tempfile` with restrictive permissions (`0o600`) in `/tmp`, or use a Kubernetes Secret/CSI driver mount instead.

#### 3.1.5 `testssl.sh` runs with `--severity LOW` but no timeout
- **Issue**: testssl.sh can hang on unresponsive hosts or unusual TLS stacks.
- **Impact**: Scan jobs may hang indefinitely.
- **Recommendation**: Wrap testssl in a `timeout` command (e.g., `timeout 600`) or set Docker `--stop-timeout`.

### 3.2 🟡 Robustness — Error Handling & Edge Cases

#### 3.2.1 `subprocess.Popen` in `tasks.py` (web scan) has no timeout
- **Issue**: `run_web_scan` spawns `scan.sh` via `subprocess.Popen` (line 409) and waits forever via `proc.wait()` (line 417).
- **Impact**: A hung `scan.sh` (e.g., ZAP spider stuck) blocks the worker indefinitely.
- **Recommendation**: Add a `timeout` parameter (e.g., 4 hours) and terminate the process if exceeded. Emit a `Failed` status update.

#### 3.2.2 `_docker_run` stderr is merged into stdout
- **Issue**: `stderr=subprocess.STDOUT` (line 364) means error output is interleaved with stdout. This makes it hard to distinguish errors from normal output.
- **Recommendation**: Capture stdout and stderr separately, or at least log stderr distinctly.

#### 3.2.3 `scan.sh` ZAP active scan: no timeout on curl calls
- **Issue**: `curl` calls to ZAP API (lines 344, 362, 375, etc.) use `-sf` but no `--max-time` or `--connect-timeout`.
- **Impact**: If ZAP daemon is unresponsive, `curl` hangs indefinitely, blocking the scan.
- **Recommendation**: Add `--max-time 30` and `--connect-timeout 5` to all ZAP API `curl` commands.

#### 3.2.4 `scan_stream` SSE: no scan ownership check
- **Issue**: The SSE endpoint (`/api/scans/{scan_id}/stream`) verifies the scan exists but does **not** verify that the current user owns the engagement (line 376–380).
- **Impact**: Any authenticated user can subscribe to any scan's progress stream, leaking scan targets and findings.
- **Recommendation**: Add an ownership check before opening the SSE stream, similar to `_get_engagement_or_403`.

#### 3.2.5 `scan.sh` cleanup trap may fail if Docker daemon is unavailable
- **Issue**: `cleanup()` calls `docker rm -f` but does not handle the case where Docker is not running.
- **Impact**: Script exits with error; trap failure may suppress the original exit code.
- **Recommendation**: `|| true` is already present — good. But ensure `set -e` doesn't cause the trap itself to abort prematurely. Use `set +e` inside `cleanup`.

### 3.3 🟡 Data Integrity & Concurrency

#### 3.3.1 `_update_scan_status` uses a separate DB session from parsing
- **Issue**: `_update_scan_status` opens its own `_db_session()` context manager, while `_parse_*_findings` opens another. If the worker process crashes between `_update_scan_status('Completed')` and the findings parser finishing, the scan shows `Completed` with zero findings.
- **Impact**: Inconsistent state: scan completed but no findings stored.
- **Recommendation**: Ensure the scan status update and findings insert happen in the same DB transaction, or use a two-phase commit pattern where the scan is marked `Completed` only after parsing succeeds.

#### 3.3.2 `dedup_hash` collision possible across tools
- **Issue**: `_make_dedup_hash` uses `sha256(f'{tool}:{name}:{location}')`. If two different tools find the same vulnerability at the same location with the same name, they deduplicate to one finding. This is intentional but may mask multi-tool confirmation.
- **Impact**: A finding confirmed by both Nuclei and ZAP appears as one finding, losing the "confirmed by multiple tools" signal.
- **Recommendation**: Document this behavior clearly. Consider adding a `confirmed_by` array or `tool_count` field if multi-tool confirmation is valuable.

### 3.4 🟡 Performance & Scalability

#### 3.4.1 `search.py` uses `ILIKE` without full-text indexes
- **Issue**: The global search uses `ILIKE '%pattern%'` on multiple columns. For large datasets (100k+ findings), this will be slow.
- **Recommendation**: The `pg_trgm` extension is installed in `db-init.sh`, but no GIN indexes on `findings` text columns are created. Add `CREATE INDEX ... USING gin (vulnerability_name gin_trgm_ops)` for search acceleration.

#### 3.4.2 `list_findings` loads all evidence eagerly
- **Issue**: Evidence is not eagerly loaded in `list_findings`, but it is in `get_finding`. This is fine. However, `list_findings` returns `FindingOut` which does not include evidence, so the N+1 risk is low. Good.

#### 3.4.3 `report.py` loads all findings into memory
- **Issue**: `render_engagement_report_async` loads all findings for an engagement into a Python list, then passes to WeasyPrint. For engagements with 10,000+ findings, this will exhaust memory.
- **Recommendation**: Paginate findings during report generation, or stream the PDF. For now, document a recommended max engagement size.

### 3.5 🟡 Observability & Operational Safety

#### 3.5.1 `scan.sh` container logs are lost
- **Issue**: Background containers are launched with `docker run -d ... >/dev/null`, so their logs are never captured by the worker.
- **Impact**: If a tool fails silently, debugging requires SSHing into the host and running `docker logs`.
- **Recommendation**: Add `--log-driver json-file` and ensure worker logs include `docker logs <cname>` output on failure, or redirect stdout/stderr to files in the output directory.

#### 3.5.2 `celery.control.revoke` in `cancel_scan` uses `terminate=True, signal='SIGTERM'`
- **Issue**: Celery sends SIGTERM to the worker process. The worker may be in the middle of a DB write, leaving data inconsistent.
- **Impact**: Partial findings or orphaned evidence records.
- **Recommendation**: Document that cancellation is best-effort. Consider using `signal='SIGUSR1'` with a custom handler that gracefully exits after the current tool finishes, or rely on the Docker container kill (which is already done) and let the task complete its DB transaction.

#### 3.5.3 `api/Dockerfile` installs `docker.io`
- **Issue**: The API image installs Docker client (`docker.io`), but the API container does **not** mount the Docker socket. This is unnecessary weight.
- **Impact**: Larger API image, potential attack surface if the API were compromised and someone mounted the socket later.
- **Recommendation**: Remove `docker.io` and `curl` from the API Dockerfile; keep them only in the worker image. `curl` is needed for healthchecks though — use a minimal `curl` image or `wget` from `busybox`.

### 3.6 🟡 Frontend & API Consistency

#### 3.6.1 `ScanOut.finding_count` is not a real column
- **Issue**: The schema comment (line 366–368) says `finding_count` is populated from a `column_property`, but `models.py` explicitly states (line 213–218) that `column_property` is **not** used. The bulk COUNT query in `list_scans` populates it manually.
- **Impact**: Comment in `schemas.py` is misleading.
- **Recommendation**: Update the comment to reflect the actual implementation.

#### 3.6.2 `tasks.py` result_expires inconsistency
- **Issue**: `run_sast_scan`, `run_cloud_scan`, and `run_mobile_scan` set `result_expires=300` to limit token exposure, but `run_web_scan` and `run_infra_scan` use the global `86400`.
- **Impact**: SAST/cloud/mobile results expire quickly, but web/infra results linger in Redis for 24h. If web scans include sensitive headers (auth_header) in their result metadata, this is a longer exposure window.
- **Recommendation**: Apply `result_expires=300` to all scan types, or ensure no sensitive data is stored in the result backend.

### 3.7 🟡 Minor Code Issues

#### 3.7.1 `models.py` uses `lambda` in `default=` for mutable objects
- **Issue**: `default=lambda: datetime.now(timezone.utc)` is used everywhere. SQLAlchemy handles this correctly, but it's slightly less efficient than `default=func.now()` (database-side).
- **Recommendation**: Not critical. `func.now()` is database-portable and avoids Python-side clock skew.

#### 3.7.2 `config.py` sync_database_url replacement is brittle
- **Issue**: `self.database_url.replace('postgresql+asyncpg://', 'postgresql://')` assumes the URL starts exactly with that prefix. If someone uses `postgres+asyncpg://` or adds query parameters, it may break.
- **Recommendation**: Use `urllib.parse` or `sqlalchemy.engine.make_url` to parse and reconstruct the URL with the sync driver.

#### 3.7.3 `tasks.py` imports `os` twice (lines 24 and 72)
- **Issue**: `import os` at line 24, then `import os as _os` at line 72. The second is redundant.
- **Recommendation**: Remove the second import.

#### 3.7.4 `parsers.py` line 92: `cve` indexing is fragile
- **Issue**: `(info.get('classification', {}).get('cve-id') or [None])[0]` assumes `cve-id` is always a list. If Nuclei changes its output format, this crashes.
- **Recommendation**: Use a safer helper:
  ```python
  cve_list = info.get('classification', {}).get('cve-id', [])
  cve = cve_list[0] if isinstance(cve_list, list) and cve_list else None
  ```

---

## 4. Testing Coverage Gaps

| Area | Coverage | Gap |
|---|---|---|
| **Auth** | ✅ Strong | Tests for login, refresh, password change, role checks |
| **Engagements** | ✅ Strong | CRUD, RBAC, scope warnings, delta, webhook secrets |
| **Findings** | ✅ Strong | List, filter, status update, bulk update, manual creation |
| **Parsers** | ✅ Strong | All 12 parsers tested with fixtures |
| **SSE stream** | ❌ Missing | No tests for `/api/scans/{id}/stream` endpoint |
| **Report generation** | ❌ Missing | No tests for PDF rendering or report export |
| **Admin routes** | ✅ Moderate | Users, audit log, templates; missing logo upload edge cases |
| **Webhook dispatch** | ❌ Missing | `_dispatch_webhook` is not tested |
| **Cancel scan** | ❌ Partial | Mocked Celery revoke, but no Docker container kill test |
| **K8s executor** | ❌ Missing | `k8s_executor.py` has no unit tests |
| **Cloud scans** | ❌ Partial | Stubs present, but no full integration test |
| **Mobile scans** | ❌ Partial | MobSF interaction mocked, but no parser test for MobSF |

---

## 5. Infrastructure & Deployment

### 5.1 Docker Compose
- **Good**: Resource limits, healthchecks, dependency ordering (`condition: service_healthy`), restart policies.
- **Concern**: Workers mount the **Docker socket** (`/var/run/docker.sock`). This is a known security risk (Phase 3 addresses it). In the interim, consider using [Docker Socket Proxy](https://github.com/Tecnativa/docker-socket-proxy) to limit API exposure.
- **Concern**: `worker-beat` runs Celery beat but no periodic tasks are defined. It consumes resources unnecessarily.

### 5.2 Kubernetes
- **Good**: Helm chart structure, KEDA autoscaling, proper RBAC, PodSecurity `restricted`.
- **Concern**: `sysbox-runtimeclass.yaml` is mentioned but not provided in the file tree. Ensure it's included before Phase 3 deployment.
- **Concern**: K8s executor (`k8s_executor.py`) does not handle Job creation failures gracefully (e.g., API server unreachable). It returns `1, str(e)` but does not retry.

### 5.3 CI/CD
- **Good**: Shellcheck, multi-version Python testing, Docker build, Alembic smoke test.
- **Missing**: Frontend build/test step (no `npm run build` or lint check in CI).
- **Missing**: Security scanning (SAST) of the codebase itself (ironic for a pentest platform). Consider adding `bandit`, `semgrep`, or `safety` to CI.
- **Missing**: Dependency vulnerability scanning (`pip-audit`, `safety check`).

---

## 6. Recommendations (Prioritized)

### 🔴 High Priority (Do Before Production)

1. **Fix SSE ownership check** (`findings.py:scan_stream`): Add engagement ownership validation before streaming progress.
2. **Add timeouts to `scan.sh`**: `curl` calls to ZAP, `docker wait`, and `subprocess.Popen` in `tasks.py` all need bounded execution time.
3. **Remove Docker from API image**: The API Dockerfile should not install `docker.io`.
4. **Fix ZAP API key leakage**: Ensure all ZAP API calls use the `X-ZAP-API-Key` header exclusively; never in query params.
5. **Secure GCP credential handling**: Write to a temp file with `0o600` permissions, or use a Kubernetes Secret mount.

### 🟡 Medium Priority (Next Sprint)

6. **Add GIN trigram indexes** for search columns in `findings` and `engagements`.
7. **Add container resource limits** (`--memory`, `--cpus`) in `scan.sh`.
8. **Unify `result_expires`**: Apply 300s to all scan types to limit sensitive data in Redis.
9. **Improve worker observability**: Capture tool container logs into the output directory or worker logs.
10. **Add frontend CI**: Build and lint the React app in GitHub Actions.
11. **Add security scanning to CI**: Run `bandit`, `semgrep`, and `pip-audit` on the API code.
12. **Test the K8s executor**: Add unit tests for `k8s_executor.py` using the `kubernetes` client mock library.

### 🟢 Low Priority (Nice to Have)

13. **Add `func.now()`** as default for `DateTime` columns instead of Python `lambda`.
14. **Fix `schemas.py` misleading comment** about `column_property`.
15. **Add `confirmed_by` or `tool_count`** to findings to track multi-tool confirmation.
16. **Stream large PDFs** or paginate findings during report generation.
17. **Add SQLmap `--level`/`--risk` options** to scan options.
18. **Clean up duplicate `import os`** in `tasks.py`.

---

## 7. Final Assessment

| Category | Score | Notes |
|---|---|---|
| **Architecture** | A | Clean async stack, proper separation of concerns, modern tools. |
| **Security** | B+ | Strong foundations; a few medium-risk issues (SSE auth, ZAP key in URL, timeouts). |
| **Code Quality** | A- | Excellent Pydantic/SQLAlchemy usage, good comments, minor cleanup needed. |
| **Testing** | B+ | Good API coverage, missing SSE/webhook/report/K8s tests. |
| **Operations** | A- | Great Helm/K8s support, resource limits, healthchecks. Docker socket is the main gap. |
| **Documentation** | A | README, API docs, inline comments, and architecture diagram are all excellent. |

**Overall: This is a well-architected, security-conscious codebase that is close to production-ready.** The most important fixes are the SSE ownership check, ZAP API key handling, and adding execution timeouts. After those, the platform is solid for a v2.0 release.
