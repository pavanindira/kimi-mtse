import { useRef } from 'react';
import { useReportTemplates, useUploadLogo } from '../lib/hooks';
import { admin } from '../lib/api';
import { useQueryClient } from '@tanstack/react-query';
import { QK } from '../lib/hooks';

export default function AdminReportTemplates() {
  const { data: templates = [], isLoading } = useReportTemplates();
  const upload   = useUploadLogo();
  const qc       = useQueryClient();
  const fileRefs = useRef<Record<number, HTMLInputElement | null>>({});

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

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Report Templates</h1>
          <div className="sub">
            Manage PDF report branding. Upload a logo to any template and set one as the system default.
          </div>
        </div>
      </div>

      {isLoading ? (
        <div className="card"><div className="empty">Loading…</div></div>
      ) : templates.length === 0 ? (
        <div className="card">
          <div className="empty" style={{ padding: '48px 20px' }}>
            No report templates found. Templates are created automatically on first startup.
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
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
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
