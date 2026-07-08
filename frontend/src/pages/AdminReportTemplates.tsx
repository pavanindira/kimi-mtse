import { useState, useRef } from 'react';
import {
  useReportTemplates, useUploadLogo, useReportTemplateDetail,
  useCreateReportTemplate, useUpdateReportTemplate, useDeleteReportTemplate,
} from '../lib/hooks';
import { admin } from '../lib/api';
import { useQueryClient } from '@tanstack/react-query';
import { QK } from '../lib/hooks';

const BLANK_TEMPLATE_HTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/></head>
<body>
  <h1>{{ engagement.name }}</h1>
  <h2>{{ engagement.client_name }}</h2>

  {% for finding in findings %}
    <h3>{{ finding.vulnerability_name }} ({{ finding.severity }})</h3>
    <p>{{ finding.description }}</p>
  {% endfor %}
</body>
</html>`;

export default function AdminReportTemplates() {
  const { data: templates = [], isLoading } = useReportTemplates();
  const upload   = useUploadLogo();
  const del      = useDeleteReportTemplate();
  const qc       = useQueryClient();
  const fileRefs = useRef<Record<number, HTMLInputElement | null>>({});
  const [editing, setEditing] = useState<number | 'new' | null>(null);

  async function handleLogoUpload(templateId: number, file: File) {
    try {
      await upload.mutateAsync({ templateId, file });
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : 'Upload failed');
    }
  }

  async function handleDeleteLogo(templateId: number) {
    if (!confirm('Remove logo from this template?')) return;
    try {
      await admin.reportTemplates.deleteLogo(templateId);
      qc.invalidateQueries({ queryKey: QK.templates });
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : 'Delete failed');
    }
  }

  async function handleSetDefault(templateId: number) {
    try {
      await admin.reportTemplates.setDefault(templateId);
      qc.invalidateQueries({ queryKey: QK.templates });
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : 'Failed');
    }
  }

  async function handleDelete(templateId: number, name: string) {
    if (!confirm(`Delete template "${name}"? Any engagement using it will fall back ` +
                'to the system default. This cannot be undone.')) return;
    try {
      await del.mutateAsync(templateId);
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : 'Delete failed');
    }
  }

  if (editing !== null) {
    return <TemplateEditor templateId={editing} onClose={() => setEditing(null)} />;
  }

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Report Templates</h1>
          <div className="sub">
            Manage PDF report branding and content. Upload a logo, edit the
            HTML/Jinja2 body, and set one template as the system default.
          </div>
        </div>
        <button className="btn btn-primary" onClick={() => setEditing('new')}>
          + New Template
        </button>
      </div>

      {isLoading ? (
        <div className="card"><div className="empty">Loading…</div></div>
      ) : templates.length === 0 ? (
        <div className="card">
          <div className="empty" style={{ padding: '48px 20px' }}>
            No report templates yet. Click "New Template" to create one.
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {templates.map(t => (
            <div key={t.id} className="card" style={{ padding: 24 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>

                {/* Logo preview / placeholder */}
                <div style={{
                  width: 80, height: 48, borderRadius: 6,
                  background: 'var(--surface2)', border: '1px solid var(--border)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  flexShrink: 0, fontSize: 11, color: 'var(--muted)',
                }}>
                  {t.has_logo ? '✓ Logo' : 'No logo'}
                </div>

                {/* Template info */}
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 600, fontSize: 14 }}>
                    {t.name}
                    {t.is_default && (
                      <span style={{
                        marginLeft: 8, fontSize: 11, fontWeight: 500,
                        background: 'color-mix(in srgb, var(--accent) 15%, transparent)',
                        color: 'var(--accent)', padding: '2px 8px', borderRadius: 10,
                      }}>
                        Default
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 3 }}>
                    Created {t.created_at ? new Date(t.created_at).toLocaleDateString() : '—'}
                  </div>
                </div>

                {/* Actions */}
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                  <button className="btn btn-ghost btn-sm" onClick={() => setEditing(t.id)}>
                    Edit HTML
                  </button>

                  {!t.is_default && (
                    <button className="btn btn-ghost btn-sm"
                            onClick={() => handleSetDefault(t.id)}>
                      Set Default
                    </button>
                  )}

                  <input
                    type="file"
                    accept="image/png,image/jpeg,image/svg+xml,image/webp"
                    style={{ display: 'none' }}
                    ref={el => { fileRefs.current[t.id] = el; }}
                    onChange={e => {
                      const file = e.target.files?.[0];
                      if (file) handleLogoUpload(t.id, file);
                      e.target.value = '';
                    }}
                  />
                  <button className="btn btn-ghost btn-sm"
                          disabled={upload.isPending}
                          onClick={() => fileRefs.current[t.id]?.click()}>
                    {upload.isPending ? 'Uploading…' : t.has_logo ? 'Replace Logo' : 'Upload Logo'}
                  </button>

                  {t.has_logo && (
                    <button className="btn btn-ghost btn-sm"
                            style={{ color: '#ef4444' }}
                            onClick={() => handleDeleteLogo(t.id)}>
                      Remove Logo
                    </button>
                  )}

                  <button
                    className="btn btn-ghost btn-sm"
                    style={{ color: t.is_default ? undefined : '#ef4444' }}
                    disabled={t.is_default || del.isPending}
                    title={t.is_default
                      ? 'Set a different template as default before deleting this one'
                      : undefined}
                    onClick={() => handleDelete(t.id, t.name)}
                  >
                    Delete
                  </button>
                </div>

              </div>

              {/* Upload hint */}
              <div style={{
                fontSize: 11, color: 'var(--muted)', marginTop: 12,
                paddingTop: 12, borderTop: '1px solid var(--border)',
              }}>
                Accepted: PNG, JPEG, SVG, WebP · Max 512 KB ·
                Logo is embedded as a data URI in the PDF header.
              </div>
            </div>
          ))}
        </div>
      )}
    </>
  );
}

/* ── Create/edit HTML editor ─────────────────────────────────────────────── */
function TemplateEditor({ templateId, onClose }: {
  templateId: number | 'new'; onClose: () => void;
}) {
  const isNew  = templateId === 'new';
  const { data: detail, isLoading } = useReportTemplateDetail(isNew ? null : templateId);
  const create = useCreateReportTemplate();
  const update = useUpdateReportTemplate(isNew ? -1 : templateId);

  const [name, setName]         = useState('');
  const [html, setHtml]         = useState(BLANK_TEMPLATE_HTML);
  const [initialized, setInitialized] = useState(isNew);
  const [error, setError]       = useState('');

  // Populate the form once the existing template's detail has loaded —
  // guarded by `initialized` so it doesn't stomp on in-progress edits if
  // this component re-renders after a background refetch.
  if (!isNew && detail && !initialized) {
    setName(detail.name);
    setHtml(detail.html_template);
    setInitialized(true);
  }

  const saving = create.isPending || update.isPending;

  async function save() {
    setError('');
    if (!name.trim()) { setError('Template name is required'); return; }
    if (!html.trim()) { setError('Template HTML is required'); return; }
    try {
      if (isNew) {
        await create.mutateAsync({ name: name.trim(), html_template: html });
      } else {
        await update.mutateAsync({ name: name.trim(), html_template: html });
      }
      onClose();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Save failed');
    }
  }

  return (
    <>
      <div className="topbar">
        <div>
          <h1>{isNew ? 'New Report Template' : 'Edit Report Template'}</h1>
          <div className="sub">
            Raw HTML rendered through Jinja2, then to PDF via WeasyPrint. Syntax
            is validated on save.
          </div>
        </div>
        <div style={{ display:'flex', gap:8 }}>
          <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" onClick={save} disabled={saving || isLoading}>
            {saving ? 'Saving…' : 'Save Template'}
          </button>
        </div>
      </div>

      {error && (
        <div className="card" style={{ padding:'12px 16px', marginBottom:12,
                                        color:'#ef4444', fontSize:13 }}>
          {error}
        </div>
      )}

      {!isNew && isLoading ? (
        <div className="card"><div className="empty">Loading…</div></div>
      ) : (
        <div className="card" style={{ padding:24 }}>
          <div style={{ marginBottom:16 }}>
            <label style={{ display:'block', fontSize:12, fontWeight:600, marginBottom:6 }}>
              Template Name
            </label>
            <input value={name} onChange={e => setName(e.target.value)}
                  placeholder="e.g. Acme Corp Branded Report" />
          </div>

          <div style={{
            fontSize:12, color:'var(--muted)', marginBottom:8, lineHeight:1.6,
            background:'var(--surface2)', borderRadius:8, padding:'10px 14px',
          }}>
            Available in the template: <code>engagement</code> (name, client_name,
            description, started_at, completed_at), <code>scans</code>,{' '}
            <code>findings</code> (each with vulnerability_name, severity,
            cvss_score, description, target_url, status, etc.),{' '}
            <code>severity_counts</code>, <code>logo_b64</code>, <code>now</code>.
            All values are auto-escaped.
          </div>

          <label style={{ display:'block', fontSize:12, fontWeight:600, marginBottom:6 }}>
            HTML / Jinja2
          </label>
          <textarea
            value={html}
            onChange={e => setHtml(e.target.value)}
            rows={24}
            style={{
              width:'100%', fontFamily:'monospace', fontSize:12.5,
              resize:'vertical', boxSizing:'border-box', lineHeight:1.5,
            }}
            spellCheck={false}
          />
        </div>
      )}
    </>
  );
}
