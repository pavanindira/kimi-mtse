# MSTE v2 — Modular Security Testing Engine

A self-hosted penetration testing platform rebuilt on a modern async stack
with full Kubernetes support and a decoupled React SPA frontend.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Phase 1 — FastAPI + React SPA                                  │
│                                                                 │
│  nginx / Ingress                                                │
│    ├── /          → React SPA (Vite + TypeScript + TanStack Q)  │
│    └── /api/*     → FastAPI (uvicorn + uvloop, async SQLAlchemy)│
│                                                                 │
│  Celery workers (3 queues, isolated Deployments)                │
│    worker-web   ← Q:web   (Nuclei, ZAP, ffuf, Katana)          │
│    worker-sast  ← Q:sast  (Semgrep, Trivy, Gitleaks, Hadolint) │
│    worker-infra ← Q:infra (Nmap + NSE)                         │
│                                                                 │
│  PostgreSQL 16 (asyncpg at runtime, psycopg2 for Alembic)      │
│  Redis 7       (Celery broker + SSE pub/sub + result backend)  │
│  scan-artifacts PVC (shared: api ↔ workers ↔ ZAP)             │
├─────────────────────────────────────────────────────────────────┤
│  Phase 2 — Kubernetes + Helm + KEDA                             │
│                                                                 │
│  Helm chart: k8s/helm/mste/                                     │
│    api-deployment.yaml        FastAPI pods (replicas: 2)        │
│    worker-deployment.yaml     One Deployment per queue          │
│    keda-scaledobjects.yaml    Scale workers 0→N on queue depth  │
│    services-ingress-pvc.yaml  Services, TLS Ingress, PVC        │
│    sysbox-runtimeclass.yaml   Phase 3 runtime hook              │
├─────────────────────────────────────────────────────────────────┤
│  Phase 3 — Rootless workers                                     │
│                                                                 │
│  Option A: Sysbox runtime — nested Docker without host socket   │
│  Option B: workers/k8s_executor.py — create K8s Jobs instead   │
│            of calling Docker daemon at all                      │
└─────────────────────────────────────────────────────────────────┘
```

### Key changes from v1

| Concern | v1 (Flask) | v2 (FastAPI) |
|---|---|---|
| Framework | Flask + Jinja2 | FastAPI + React SPA |
| Auth | Flask-Login sessions + CSRF | Stateless JWT (python-jose) |
| DB driver | psycopg2 (sync) | asyncpg (async) + psycopg2 for Alembic |
| Validation | Manual `if not x` checks | Pydantic v2 schemas on every route |
| API docs | None | Auto-generated OpenAPI at `/docs` and `/redoc` |
| SSE streaming | Blocking `pubsub.listen()` in a thread | `asyncio.wait_for()` + non-blocking pub/sub |
| Frontend | 10 Jinja2 templates | React SPA, TanStack Query, React Router v6 |
| Migrations | `db.create_all()` (silently ignores changes) | Alembic with versioned migrations |
| Orchestration | docker-compose only | docker-compose + Helm + KEDA |
| Worker isolation | Docker socket in web-ui + workers | Socket removed from API; Phase 3 removes from workers |

---

## Quick start (Kubernetes via Helm)

### 1. Prerequisites
```bash
# Install KEDA
helm repo add kedacore https://kedacore.github.io/charts
helm install keda kedacore/keda -n keda --create-namespace

# Install cert-manager for TLS
helm repo add jetstack https://charts.jetstack.io
helm install cert-manager jetstack/cert-manager -n cert-manager \
  --create-namespace --set crds.enabled=true
```

### 2. Create secrets
```bash
kubectl create secret generic mste-secrets \
  --from-literal=JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))") \
  --from-literal=ADMIN_PASSWORD='<strong-password>' \
  --from-literal=DATABASE_URL='postgresql+asyncpg://mste_user:<pass>@<host>:5432/mste' \
  --from-literal=REDIS_URL='redis://:<pass>@<host>:6379/0' \
  --from-literal=ZAP_API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))") \
  --from-literal=POSTGRES_PASSWORD='<strong-password>' \
  --from-literal=WEB_DB_PASSWORD='<strong-password>' \
  --from-literal=REDIS_PASSWORD='<strong-password>'
```

### 3. Deploy
```bash
# Build and push images first
docker build -t mste/api:2.0.0      ./api
docker build -t mste/frontend:2.0.0 ./frontend
docker push mste/api:2.0.0
docker push mste/frontend:2.0.0

# Install / upgrade
helm install mste ./k8s/helm/mste \
  --set ingress.hosts[0].host=your-domain.com \
  --set api.env.CORS_ORIGINS=https://your-domain.com

# Apply RBAC for K8s Jobs executor (Phase 3 Option B)
kubectl apply -f k8s/rbac-scan-jobs.yaml
```

### 4. KEDA autoscaling
KEDA watches each Celery queue's Redis list length and adjusts worker replicas:
- **0 jobs** → 0 replicas (scale to zero — no idle cost)
- **3 jobs** → 1 replica
- **9 jobs** → 3 replicas
- **30 jobs** → 10 replicas (maxReplicas for web queue)

Tune in `values.yaml`:
```yaml
keda:
  queueLengthPerReplica: 3   # jobs per worker before scaling up
  maxReplicas:
    web:  10
    sast: 5
    infra: 3
  cooldownPeriod: 300        # seconds idle before scaling to zero
```

---

## Alternative: Local development (docker-compose)

### 1. Prerequisites
- Docker + Docker Compose v2
- Node 22+ (for frontend dev only — production uses the Docker build)

### 2. Configure
```bash
cp .env.example .env
# Fill in every <CHANGE_ME_...> value
export HOST_PROJECT_PATH=$PWD
```

### 3. TLS certificate
```bash
mkdir -p nginx/certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/certs/server.key \
  -out    nginx/certs/server.crt \
  -subj   "/CN=localhost"
```

### 4. Start
```bash
docker compose up -d

# With DVWA scan target (dev):
docker compose --profile dev up -d
```

### 5. Access
| Service | URL | Notes |
|---|---|---|
| Web UI | https://localhost/ | Login: admin / ADMIN_PASSWORD |
| API docs | https://localhost/docs | OpenAPI / Swagger UI |
| API redoc | https://localhost/redoc | ReDoc alternative |
| Caido proxy | localhost:8081 | SSH tunnel to access |

---

## Phase 3: Eliminating the Docker socket

### Option A — Sysbox (docker-compose + bare-metal K8s)
```bash
# Install Sysbox on worker nodes
curl -fsSL https://downloads.nestybox.com/sysbox/releases/v0.6.4/sysbox-ce_0.6.4-0.linux_amd64.deb \
  -o /tmp/sysbox.deb && dpkg -i /tmp/sysbox.deb

# Label nodes
kubectl label node <worker-node> sysbox-install=yes

# Enable in values.yaml
workers:
  runtimeClassName: sysbox-runc
```

With Sysbox, worker containers can run `docker run` internally without
mounting the host socket. Each worker gets its own isolated Docker daemon.

### Option B — K8s Jobs executor (managed K8s / EKS / GKE / AKS)
Replace `docker run` calls in tasks with `k8s_executor.run_tool_job()`:

```python
# In tasks.py, replace:
docker run -v ... projectdiscovery/nuclei:latest ...

# With:
from k8s_executor import run_tool_job
exit_code, logs = run_tool_job(
    scan_id=scan_id,
    tool_name='nuclei',
    image='projectdiscovery/nuclei:latest',
    command=['-target', target, '-je', '/output/findings.json'],
    output_subfolder=folder_name,
)
```

Workers need no Docker socket — they call the K8s API via ServiceAccount
permissions scoped to `Jobs` in the `mste-scans` namespace only.

---

## Database migrations (Alembic)

```bash
# First-time setup
docker compose run --rm api alembic init alembic   # already done
docker compose run --rm api alembic revision --autogenerate -m "initial schema"
docker compose run --rm api alembic upgrade head

# After changing models.py
docker compose run --rm api alembic revision --autogenerate -m "describe change"
git add api/alembic/versions/ && git commit -m "migration: describe change"
docker compose up -d --build   # upgrade head runs automatically on container start
```

---

## Frontend development

```bash
cd frontend
npm install
npm run dev       # Vite dev server on :5173, proxies /api → localhost:8000
```

The API runs separately:
```bash
cd api
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

---

## Running Tests

The comprehensive test suite covers API endpoints, authentication workflows, and database operations. It runs securely via a mocked Celery broker and an in-memory SQLite database (`aiosqlite`).

```bash
# 1. Activate your virtual environment
venv\Scripts\activate      # Windows
# source venv/bin/activate # Linux/macOS

# 2. Install app and testing dependencies
pip install -r api/requirements.txt
pip install pytest pytest-asyncio httpx aiosqlite

# 3. Run the complete test suite
pytest
```

---

## API documentation

With the API running, visit:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

All 20 endpoints are fully documented with request/response schemas,
example values, and authentication requirements.

---

## Security inventory

| Control | Implementation |
|---|---|
| Authentication | Stateless JWT (HS256, 8h expiry, in-memory on client) |
| Authorisation | `require_analyst` / `require_admin` FastAPI dependencies |
| SSRF prevention | Pydantic validator rejects RFC1918 + link-local targets |
| Input validation | Pydantic v2 on every request body — automatic 422 on invalid |
| PDF injection | Jinja2 `autoescape=True` prevents LFI/SSRF via WeasyPrint |
| Argument injection | Pydantic rejects dash-led targets; `--` separator enforced in CLI calls |
| Command injection | Array args used throughout, `shlex.quote()` for dynamic shell variables |
| Secret storage | All secrets via K8s Secret / `.env` — no hardcoded defaults |
| Audit logging | Every mutating action recorded in `audit_logs` table |
| Docker socket | Removed from API container; Phase 3 removes from workers |
| CORS | Explicit origin allowlist via `CORS_ORIGINS` env var |
| Security headers | X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| Rate limiting | slowapi on `/api/auth/login` and `/api/engagements/*/scans` |
| TLS | nginx terminates TLS; HSTS header enforced |
