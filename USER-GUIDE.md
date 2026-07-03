# Using MSTE v2 — A Walkthrough

This guide walks through the platform end to end: getting it running, logging
in, setting up your first engagement, launching a scan, triaging findings,
and producing a client-ready report. It's written in the order you'll
actually do things, not as a reference manual — see `API-README.md` for the
full API reference and `README.md` for architecture.

---

## 1. Before you start

You need Docker and Docker Compose installed on the host. MSTE launches
scanning tools (Nuclei, ZAP, SQLmap, etc.) as sibling Docker containers, so
the worker containers need access to the host's Docker socket — this is
already wired up in `docker-compose.yml`.

### 1.1 — Configure environment

```bash
cp .env.example .env
export HOST_PROJECT_PATH=$PWD
```

Open `.env` and replace every `<CHANGE_ME_...>` placeholder. Generate strong
secrets with:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

At minimum you need: `WEB_DB_PASSWORD`, `REDIS_PASSWORD`, `JWT_SECRET`,
`ADMIN_PASSWORD`, `ZAP_API_KEY`. The other variables (Hoppscotch, MobSF) have
working defaults but should be changed before any real client engagement.

### 1.2 — Start everything

```bash
docker compose up -d
```

This builds and starts 13 services: the API, three Celery workers (web,
sast, infra), Postgres, Redis, the nginx-served React frontend, and the
scanning tool containers (ZAP, plus on-demand Nuclei/ffuf/Katana/SQLmap/
testssl/Semgrep/Trivy/Gitleaks/Hadolint/Nmap/ScoutSuite/Prowler/MobSF, which
launch only when a scan needs them).

Watch the API come up:

```bash
docker compose logs -f api
```

You should see Alembic apply all four migrations, then `MSTE API ready.`

**What to expect**: on first boot, the API automatically creates the default
admin account (`admin` / the password you set as `ADMIN_PASSWORD`) and seeds
a default PDF report template. You don't need to run any setup scripts.

### 1.3 — Confirm it's healthy

```bash
curl http://localhost/api/health/live   # always 200 if the process is up
curl http://localhost/api/health/ready  # 200 once DB + Redis are reachable
```

Once `/health/ready` returns 200, open `http://localhost` in a browser.

---

## 2. Logging in

You'll land on the login page. Sign in with:

```
Username: admin
Password: <the ADMIN_PASSWORD you set in .env>
```

**What to expect**: your session is held in memory and in `sessionStorage`
(survives a page refresh, cleared when you close the tab). There's no
"remember me" — this is deliberate for a security tool. If you leave the tab
open, the JWT token is valid for 8 hours by default; the app silently
refreshes it as you work, so you generally won't be logged out mid-session.

The first thing you should do as admin is create real user accounts —
**don't share the admin login** with your team. Go to **Admin → Users**.

---

## 3. Setting up users

Admin → Users → fill in a username, password, and role:

- **Admin** — full access, can manage users, delete engagements, view the
  audit log, manage report templates
- **Analyst** — can create engagements, start/cancel scans, triage findings,
  add manual findings, export reports — cannot delete engagements or manage
  users
- **Viewer** — read-only on engagements they created or were given access to

**What to expect**: each user only sees engagements *they* created (admins
see everything). There's no sharing/team-assignment feature yet — if two
analysts need to collaborate on one engagement, have one of them create it
and loop the other in by sharing screen, or have an admin do the
administrative pieces. This is a known limitation, not a bug.

Create at least one Analyst account now and log in as them for the rest of
this walkthrough — that's the role you'll use day to day.

---

## 4. Creating your first engagement

Click **+ New Engagement** from the dashboard or the Engagements page.

Fill in:
- **Name** — something descriptive, e.g. "Q3 2026 Web App Pentest"
- **Client Name** — used in the PDF report header
- **Description** — optional, shows on the engagement detail page
- **In-Scope Targets** — optional but recommended. One entry per line:
  - CIDR ranges: `10.10.0.0/16`
  - Hostname globs: `*.example.com`
  - URL prefixes: `https://app.example.com`

**What to expect**: scope is *advisory*, not enforced. If you later start a
scan against a target that doesn't match any scope line, you'll see a yellow
warning banner — but the scan still runs. This is intentional: pentesters
sometimes legitimately need to scan supporting infrastructure for the same
client that wasn't explicitly listed. The warning exists to catch
copy-paste mistakes, not to gatekeep.

Click **Create Engagement**. You land on the engagement detail page with
three tabs: **Scans**, **Delta / Re-test**, and **Scope**.

---

## 5. Starting a scan

Click **+ New Scan**. Pick a scan type:

| Type | Target format | Tools run |
|---|---|---|
| **Web / API** | Full URL — `https://app.example.com` | Nuclei, ffuf, Katana, SQLmap, testssl, ZAP |
| **SAST / SCA** | Git repo URL — `https://github.com/org/repo` | Semgrep, Trivy, Gitleaks, Hadolint |
| **Infrastructure** | IP or CIDR — `192.168.1.0/24` | Nmap |
| **Cloud** | `provider:resource` — `aws:default`, `gcp:my-project` | ScoutSuite, Prowler (AWS only) |
| **Mobile** | URL to an APK/IPA — `https://cdn.example.com/app.apk` | MobSF |

For web scans you can also set an auth header (for authenticated scanning),
a proxy, and toggle Katana (SPA crawling), SQLmap, and stealth/rate-limiting
mode. For SAST scans against private repos, paste a Git token — it's used
once for the clone and is never written to the database.

For cloud scans, you'll need to supply credentials — these aren't in the UI
form yet; pass them via the API directly (`aws_access_key_id`,
`aws_secret_access_key`, etc. in the scan options) until the credentials
form ships.

Click **Start Scan**.

**What to expect immediately**: the scan is created with status `Queued` and
handed to a Celery worker. The modal switches to a live log view connected
via Server-Sent Events — you'll see real tool output streaming in as it
happens (container launches, crawl progress, findings being recorded). This
is not a polling refresh; it's a genuine live connection. If you close the
modal and come back later, reopening the log replays everything that
happened while you were away, then resumes live streaming.

**What to expect timing-wise**: a web scan against a small target typically
takes 3–10 minutes depending on which tools are enabled (SQLmap and ZAP's
active scan are the slowest). SAST scans depend on repo size. Infra scans
against a /24 can take a while if Nmap's NSE scripts are thorough. Cloud
scans against a real AWS account can take 5–15 minutes since ScoutSuite
enumerates many services.

You can navigate away — the scan keeps running in the background. Come back
to the **Scans** tab and you'll see its status update live (Queued → Running
→ Completed), polling every 5 seconds while active.

**If you need to stop a scan**: click **Cancel** next to a Running or Queued
scan. This sends a termination signal to the Celery task and forcibly
removes any Docker containers that scan launched. Cancellation is not
instant — tools that don't check for interruption frequently (some Nmap
NSE scripts) may take a few seconds to actually stop.

---

## 6. Reviewing findings

Once a scan completes, click **Findings** on its row, or navigate to the
**Findings** page and filter by `Status: Open`.

**What to expect on the findings list**: results are paginated (50 per
page), sorted by CVSS score descending, then recency. You can filter by
severity, status, tool, or scope to a specific scan/engagement via the URL
— the filters are shareable links.

Click into any finding to see:
- Full description and remediation guidance (pulled directly from the tool)
- Evidence — request/response pairs, code snippets, log excerpts, depending
  on the tool
- Metadata — CVSS score/vector, CVE/CWE references, file path or URL,
  first-seen/last-seen timestamps

**Triage workflow**: change the status dropdown (Open → Confirmed / False
Positive / Fixed / Accepted Risk) and/or add analyst notes — markdown
supported. These save independently: changing notes alone doesn't require
also re-submitting the status, and vice versa. Use notes for things like
"Confirmed exploitable — PoC: curl ... " or "False positive, WAF blocks this
pattern in production."

**Bulk triage**: on the findings list, select multiple findings with the
checkboxes and apply a status change with one optional note to all of them
at once — useful for clearing out a batch of low-severity informational
findings after a quick review.

**Adding findings manually**: not everything is caught by automated tools.
On a completed scan's row, click **+ Manual Finding** to record something
you found through manual testing — business logic flaws, chained exploits,
anything outside the automated tools' reach. Manual findings start at
**Confirmed** status (since you're asserting they're real) and are tagged
`tool: Manual` so they're visually distinguishable from automated results,
but they appear in every list, filter, and the final report exactly like
any other finding.

---

## 7. Re-testing (the Delta view)

Once an engagement has run the **same kind of scan twice** (e.g. you fixed
some issues and re-ran the web scan), go to the **Delta / Re-test** tab.

**What to expect**: by default it compares the most recent completed scan
against the one before it. You can change the baseline via the dropdown if
you want to compare against an earlier scan instead. Results are split into
three buckets:

- **New** — findings that weren't there before (regressions, or just newly
  discovered)
- **Recurring** — findings present in both runs (not yet fixed)
- **Resolved** — findings from the baseline that are gone now (fixed, or no
  longer detected)

This is matched by content (tool + finding name + location), not database
ID, so it correctly tracks a finding across scans even though each scan
creates fresh rows under the hood.

If you've only run one scan so far, this tab will tell you it needs at
least two completed scans and won't show an error — just an explanation.

---

## 8. Exporting the report

From the engagement page, click **↓ Export PDF**. This generates a complete
client-facing report covering the executive summary, severity breakdown,
and full finding details with remediation guidance, using the engagement's
assigned report template (or the system default if none is set).

**What to expect**: generation can take a few seconds for engagements with
many findings since WeasyPrint renders the full HTML-to-PDF pipeline
server-side. The file downloads directly — there's no intermediate preview
step currently.

### Customizing the report logo

As an admin, go to **Admin → Report Templates**. Each template shows whether
it has a logo attached. Click **Upload Logo** to add your firm's branding
(PNG, JPEG, SVG, or WebP, max 512 KB) — it'll be embedded in every report
generated from that template. Click **Set Default** to make a template the
system-wide default for engagements that don't have a specific template
assigned.

---

## 9. Searching across everything

The **Search** page does a single query across findings, engagements, and
scans simultaneously — useful when you remember a CVE or a target hostname
but not which engagement it was under. Results are scoped to engagements you
have access to (admins search everything).

---

## 10. Keeping your account secure

Go to your **Profile** (the ⚙ icon next to your username in the sidebar) to
change your password. You'll need your current password to set a new one —
this prevents a stolen session token from being used to lock you out of your
own account. After a successful change, you stay logged in; no need to
re-authenticate.

---

## 11. What admins can see (the audit trail)

Every meaningful action — logins, password changes, engagement creation,
scan starts/cancellations, finding status changes, user management, report
exports — is logged with a timestamp, the acting user, and the source IP.
Admin → Audit Log lets you filter by action type or username. This exists
for accountability on client engagements where you may need to demonstrate
who did what, and when.

---

## Typical first-day flow, summarized

1. `docker compose up -d`, wait for `/health/ready` to return 200
2. Log in as `admin`, create real user accounts, log out
3. Log in as an Analyst
4. Create an engagement, optionally define scope
5. Start a web scan against the target, watch the live log
6. Once complete, review findings — triage status, add notes, add anything
   you found manually
7. Run a second scan after remediation work; check the Delta tab
8. Export the PDF report for the client
9. As admin, periodically check the audit log for engagement activity

---

## Troubleshooting

**Scan stuck at "Queued" forever** — check that the relevant Celery worker
is running: `docker compose ps worker-web` (or `worker-sast` / `worker-infra`
depending on scan type). If it's not running, `docker compose up -d
worker-web`.

**Live log doesn't connect / shows nothing** — the SSE connection requires
nginx to not buffer the response. If you're running behind a custom reverse
proxy (not the bundled nginx config), make sure `X-Accel-Buffering: no` is
respected and the connection isn't terminated by an aggressive proxy
timeout. The log will still update via a 15-second polling fallback even if
the live stream fails, so you won't lose visibility — it'll just be less
real-time.

**Cloud scan fails immediately with "AWS scan requires aws_access_key_id"**
— cloud scan credentials aren't yet exposed in the UI form; you need to pass
them via the API directly in the scan request body. This is a known gap,
not a misconfiguration on your end.

**"You do not have access to this engagement" (403)** — this means the
engagement was created by a different user. Only admins can see engagements
they didn't personally create. If you need cross-analyst visibility, that
has to be handled administratively for now (have an admin pull the data) —
team-based sharing isn't built yet.
