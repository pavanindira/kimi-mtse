"""
report.py — Generate professional PDF pentest reports from engagement findings.

Uses WeasyPrint to render a Jinja2 HTML template to PDF.
Install: pip install weasyprint

The DEFAULT_TEMPLATE_HTML below is the built-in template.
Custom templates per client are stored in the ReportTemplate model.
"""

import logging
from datetime import datetime

from jinja2 import Environment, BaseLoader
from weasyprint import HTML

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    'Critical': '#7c1d1d',
    'High':     '#c0392b',
    'Medium':   '#e67e22',
    'Low':      '#2980b9',
    'Info':     '#7f8c8d',
}

DEFAULT_TEMPLATE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<style>
  @page {
    size: A4;
    margin: 2cm 2.5cm;
    @bottom-center {
      content: "CONFIDENTIAL — " string(client) " — Page " counter(page) " of " counter(pages);
      font-size: 8pt; color: #888;
    }
  }
  :root { font-family: 'Helvetica Neue', Arial, sans-serif; font-size: 10pt; color: #222; }
  body  { margin: 0; }

  .cover {
    height: 100vh; display: flex; flex-direction: column;
    justify-content: center; background: #1a2744;
    color: white; padding: 3cm; box-sizing: border-box;
  }
  .cover h1  { font-size: 28pt; font-weight: 800; margin: 0 0 0.3cm; }
  .cover h2  { font-size: 16pt; font-weight: 400; margin: 0 0 1.5cm; color: #a8b8d8; }
  .cover .meta { font-size: 10pt; color: #a8b8d8; line-height: 1.8; }
  .cover .confidential {
    margin-top: 2cm; font-size: 8pt; letter-spacing: 2px;
    text-transform: uppercase; color: #c0392b;
    border: 1px solid #c0392b; padding: 3px 8px; display: inline-block;
  }

  .page-break { page-break-before: always; }
  h2.section-title {
    color: #1a2744; font-size: 14pt; font-weight: 700;
    border-bottom: 2px solid #1a2744; padding-bottom: 4px; margin-bottom: 0.5cm;
  }
  h3.finding-title { font-size: 11pt; font-weight: 700; margin: 0 0 4px; }

  .sev-grid { display: flex; gap: 0.4cm; margin: 0.5cm 0; }
  .sev-box  { flex: 1; padding: 0.4cm; border-radius: 4px; text-align: center; border: 1px solid #dde3ec; }
  .sev-box .count { font-size: 24pt; font-weight: 800; }
  .sev-box .label { font-size: 8pt; text-transform: uppercase; letter-spacing: 1px; }
  .sev-Critical { background: #fdecea; color: #7c1d1d; }
  .sev-High     { background: #fdf0ee; color: #c0392b; }
  .sev-Medium   { background: #fef9ee; color: #e67e22; }
  .sev-Low      { background: #eaf4fb; color: #2980b9; }
  .sev-Info     { background: #f4f4f4; color: #7f8c8d; }

  .finding { border: 1px solid #dde3ec; border-radius: 4px; margin-bottom: 0.6cm; page-break-inside: avoid; }
  .finding-header { padding: 0.3cm 0.5cm; display: flex; justify-content: space-between; align-items: center; }
  .finding-body   { padding: 0.4cm 0.5cm; background: white; }

  .badge { display: inline-block; padding: 2px 8px; border-radius: 3px;
           font-size: 8pt; font-weight: 700; text-transform: uppercase;
           letter-spacing: 0.5px; color: white; }
  .badge-Critical { background: #7c1d1d; }
  .badge-High     { background: #c0392b; }
  .badge-Medium   { background: #e67e22; }
  .badge-Low      { background: #2980b9; }
  .badge-Info     { background: #7f8c8d; }

  .meta-row   { display: flex; gap: 1cm; font-size: 8pt; color: #555; margin: 0.3cm 0; }
  .label-block { font-size: 8pt; font-weight: 700; text-transform: uppercase;
                 letter-spacing: 0.5px; color: #888; margin: 0.3cm 0 0.1cm; }
  .desc       { font-size: 9.5pt; line-height: 1.5; }
  .remediation { background: #f0f7ef; border-left: 3px solid #27ae60;
                 padding: 0.3cm 0.4cm; font-size: 9.5pt; line-height: 1.5; }

  pre {
    background: #1e1e2e; color: #cdd6f4;
    font-family: 'Courier New', monospace; font-size: 7.5pt; line-height: 1.4;
    padding: 0.3cm; border-radius: 3px; white-space: pre-wrap;
    word-break: break-all; overflow: hidden; max-height: 8cm;
  }

  table.findings-table { width: 100%; border-collapse: collapse; font-size: 9pt; margin: 0.3cm 0; }
  table.findings-table th { background: #1a2744; color: white; padding: 0.2cm 0.3cm; text-align: left; font-size: 8pt; }
  table.findings-table td { padding: 0.2cm 0.3cm; border-bottom: 1px solid #dde3ec; }
  table.findings-table tr:nth-child(even) td { background: #f7f9fc; }
</style>
<title>Pentest Report</title>
</head>
<body>

<div class="cover">
  {% if logo_b64 %}<img style="max-height:60px;margin-bottom:2cm;" src="data:image/png;base64,{{ logo_b64 }}"/>{% endif %}
  <h1>Penetration Test Report</h1>
  <h2>{{ engagement.name }}</h2>
  <div class="meta">
    <div><strong>Client:</strong> {{ engagement.client_name }}</div>
    <div><strong>Report Date:</strong> {{ now }}</div>
    <div><strong>Assessment Period:</strong>
      {{ engagement.started_at.strftime('%d %b %Y') if engagement.started_at else 'N/A' }} -
      {{ engagement.completed_at.strftime('%d %b %Y') if engagement.completed_at else 'Ongoing' }}
    </div>
    <div><strong>Total Findings:</strong> {{ findings | length }}</div>
  </div>
  <div class="confidential">Confidential</div>
</div>

<div class="page-break">
  <h2 class="section-title">Executive Summary</h2>
  <p>
    This report presents findings from a penetration test of
    <strong>{{ engagement.client_name }}</strong>'s <strong>{{ engagement.name }}</strong>.
    The assessment identified <strong>{{ findings | length }}</strong> findings across
    <strong>{{ scans | length }}</strong> scan(s).
  </p>
  {% if engagement.description %}<p>{{ engagement.description }}</p>{% endif %}
  <div class="sev-grid">
    {% for sev in ['Critical','High','Medium','Low','Info'] %}
    <div class="sev-box sev-{{ sev }}">
      <div class="count">{{ severity_counts[sev] }}</div>
      <div class="label">{{ sev }}</div>
    </div>
    {% endfor %}
  </div>
</div>

<div style="margin-top:1cm;">
  <h2 class="section-title">Findings Summary</h2>
  <table class="findings-table">
    <thead><tr><th>#</th><th>Finding</th><th>Severity</th><th>CVSS</th><th>Tool</th><th>Location</th></tr></thead>
    <tbody>
    {% for f in findings %}
    <tr>
      <td>{{ loop.index }}</td>
      <td>{{ f.vulnerability_name }}</td>
      <td><span class="badge badge-{{ f.severity }}">{{ f.severity }}</span></td>
      <td>{{ '%.1f'|format(f.cvss_score) if f.cvss_score else '-' }}</td>
      <td>{{ f.tool }}</td>
      <td style="font-size:7.5pt;word-break:break-all;">{{ f.target_url or f.file_path or f.host or '-' }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>

<div class="page-break">
  <h2 class="section-title">Detailed Findings</h2>
  {% for f in findings %}
  <div class="finding">
    <div class="finding-header sev-{{ f.severity }}">
      <h3 class="finding-title">{{ loop.index }}. {{ f.vulnerability_name }}</h3>
      <span class="badge badge-{{ f.severity }}">{{ f.severity }}</span>
    </div>
    <div class="finding-body">
      <div class="meta-row">
        <span><strong>Tool:</strong> {{ f.tool }}</span>
        {% if f.cvss_score %}<span><strong>CVSS:</strong> {{ '%.1f'|format(f.cvss_score) }}</span>{% endif %}
        {% if f.cve_id %}<span><strong>CVE:</strong> {{ f.cve_id }}</span>{% endif %}
        {% if f.cwe_id %}<span><strong>CWE:</strong> {{ f.cwe_id }}</span>{% endif %}
        <span><strong>Status:</strong> {{ f.status }}</span>
      </div>
      {% set loc = f.target_url or f.file_path or f.host %}
      {% if loc %}
      <div class="meta-row">
        <span><strong>Location:</strong> {{ loc }}{% if f.line_number %}:{{ f.line_number }}{% endif %}{% if f.port %} port {{ f.port }}{% endif %}</span>
      </div>
      {% endif %}
      {% if f.description %}
      <div class="label-block">Description</div>
      <div class="desc">{{ f.description }}</div>
      {% endif %}
      {% if f.remediation %}
      <div class="label-block">Remediation</div>
      <div class="remediation">{{ f.remediation }}</div>
      {% endif %}
      {% if f.analyst_notes %}
      <div class="label-block">Analyst Notes</div>
      <div class="desc">{{ f.analyst_notes }}</div>
      {% endif %}
      {% for ev in f.evidence %}
      <div class="label-block">Evidence - {{ ev.label or ev.ev_type }}</div>
      <pre>{{ ev.content[:2000] if ev.content else '' }}</pre>
      {% endfor %}
    </div>
  </div>
  {% endfor %}
</div>

<div class="page-break">
  <h2 class="section-title">Scan Coverage</h2>
  <table class="findings-table">
    <thead><tr><th>Type</th><th>Target</th><th>Status</th><th>Completed</th><th>Findings</th></tr></thead>
    <tbody>
    {% for s in scans %}
    <tr>
      <td>{{ s.scan_type | upper }}</td>
      <td style="font-size:8pt;word-break:break-all;">{{ s.target }}</td>
      <td>{{ s.status }}</td>
      <td>{{ s.completed_at.strftime('%d %b %Y %H:%M') if s.completed_at else '-' }}</td>
      <td>{{ s.finding_count }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>

</body>
</html>
"""


def _render_pdf(template_html: str, context: dict) -> bytes:
    """
    Pure CPU-bound PDF render — no ORM access, no async, no session.

    All data is passed in as plain Python dicts/lists so this function is
    safe to call from asyncio.to_thread() after the DB session is closed.

    autoescape=True prevents malicious HTML in finding fields (names,
    descriptions, URLs, evidence) from being injected raw into the PDF.
    Without it, a scanned target returning
      <iframe src="file:///etc/passwd">
    or a JS payload in a vulnerability name would be rendered by WeasyPrint,
    enabling LFI/SSRF. The template HTML itself is admin-controlled and
    trusted; all ORM values rendered into it are untrusted and must be escaped.
    """
    env      = Environment(loader=BaseLoader(), autoescape=True)
    template = env.from_string(template_html)
    html_str = template.render(**context)
    return HTML(string=html_str).write_pdf()


async def render_engagement_report_async(engagement, db) -> bytes:
    """
    Fetch all report data inside the open async DB session, then hand off
    plain dicts to _render_pdf() running in a thread pool.

    WeasyPrint is CPU-bound and synchronous; asyncio.to_thread() keeps it
    off the FastAPI event loop without blocking other requests.
    """
    import asyncio
    from datetime import timezone
    from sqlalchemy import select, func
    from sqlalchemy.orm import selectinload
    from models import Scan, Finding, Evidence, ReportTemplate, SEVERITIES

    # ── Fetch report template ─────────────────────────────────────────────────
    # Priority: engagement-specific template → system default → built-in HTML
    tmpl = None
    if getattr(engagement, 'report_template_id', None):
        tmpl = (await db.execute(
            select(ReportTemplate).where(
                ReportTemplate.id == engagement.report_template_id
            )
        )).scalar_one_or_none()

    if tmpl is None:
        tmpl = (await db.execute(
            select(ReportTemplate).where(ReportTemplate.is_default.is_(True))
        )).scalar_one_or_none()

    template_html = tmpl.html_template if tmpl else DEFAULT_TEMPLATE_HTML
    logo_b64      = tmpl.logo_base64   if tmpl else None

    # ── Fetch scans for this engagement (ordered) ─────────────────────────────
    scan_rows = (await db.execute(
        select(Scan)
        .where(Scan.engagement_id == engagement.id)
        .order_by(Scan.created_at.asc())
    )).scalars().all()

    # Pre-compute per-scan finding counts in a single query
    count_rows = (await db.execute(
        select(Finding.scan_id_fk, func.count(Finding.id))
        .where(
            Finding.scan_id_fk.in_([s.id for s in scan_rows]),
            Finding.status.in_(['Open', 'Confirmed']),
        )
        .group_by(Finding.scan_id_fk)
    )).all()
    finding_count_by_scan = {row[0]: row[1] for row in count_rows}

    scans_ctx = [
        {
            'scan_type':   s.scan_type,
            'target':      s.target,
            'status':      s.status,
            'completed_at': s.completed_at,
            'finding_count': finding_count_by_scan.get(s.id, 0),
        }
        for s in scan_rows
    ]

    # ── Fetch open/confirmed findings with evidence eager-loaded ──────────────
    # Safety limit: engagements with 10,000+ findings would exhaust memory
    # during PDF generation.  Cap at 5,000 and log a warning so the operator
    # knows the report is partial.
    MAX_REPORT_FINDINGS = 5000
    scan_ids = [s.id for s in scan_rows]
    total_finding_count = (await db.execute(
        select(func.count(Finding.id))
        .where(
            Finding.scan_id_fk.in_(scan_ids),
            Finding.status.in_(['Open', 'Confirmed']),
        )
    )).scalar_one()

    if total_finding_count > MAX_REPORT_FINDINGS:
        logger.warning(
            'Engagement %s has %d findings; capping report at %d',
            engagement.id, total_finding_count, MAX_REPORT_FINDINGS
        )

    finding_rows = (await db.execute(
        select(Finding)
        .where(
            Finding.scan_id_fk.in_(scan_ids),
            Finding.status.in_(['Open', 'Confirmed']),
        )
        .options(selectinload(Finding.evidence))
        .order_by(
            Finding.severity,
            Finding.cvss_score.desc().nulls_last(),
        )
        .limit(MAX_REPORT_FINDINGS)
    )).scalars().all()

    severity_counts = {s: 0 for s in SEVERITIES}
    findings_ctx = []
    for f in finding_rows:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        findings_ctx.append({
            'vulnerability_name': f.vulnerability_name,
            'severity':           f.severity,
            'cvss_score':         f.cvss_score,
            'cvss_vector':        f.cvss_vector,
            'cve_id':             f.cve_id,
            'cwe_id':             f.cwe_id,
            'tool':               f.tool,
            'target_url':         f.target_url,
            'file_path':          f.file_path,
            'host':               f.host,
            'port':               f.port,
            'line_number':        f.line_number,
            'description':        f.description,
            'remediation':        f.remediation,
            'analyst_notes':      f.analyst_notes,
            'status':             f.status,
            'evidence': [
                {
                    'ev_type': ev.ev_type,
                    'label':   ev.label,
                    'content': ev.content,
                }
                for ev in (f.evidence or [])
            ],
        })

    # ── Engagement context (plain values only — no ORM object in thread) ──────
    engagement_ctx = {
        'name':         engagement.name,
        'client_name':  engagement.client_name,
        'description':  engagement.description,
        'started_at':   engagement.started_at,
        'completed_at': engagement.completed_at,
    }

    context = {
        'engagement':      engagement_ctx,
        'scans':           scans_ctx,
        'findings':        findings_ctx,
        'severity_counts': severity_counts,
        'logo_b64':        logo_b64,
        'now':             datetime.now(timezone.utc).strftime('%d %B %Y'),
    }

    return await asyncio.to_thread(_render_pdf, template_html, context)
