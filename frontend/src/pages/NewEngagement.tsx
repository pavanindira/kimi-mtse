import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useCreateEngagement } from '../lib/hooks';

export default function NewEngagement() {
  const navigate = useNavigate();
  const create   = useCreateEngagement();

  const [name,   setName  ] = useState('');
  const [client, setClient] = useState('');
  const [desc,   setDesc  ] = useState('');
  const [scope,  setScope ] = useState('');
  const [webhook, setWebhook] = useState('');
  const [error,  setError ] = useState('');

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    if (!name.trim())   { setError('Engagement name is required'); return; }
    if (!client.trim()) { setError('Client name is required');     return; }
    if (webhook.trim() && !/^https?:\/\/.+/i.test(webhook.trim())) {
      setError('Webhook URL must start with http:// or https://');
      return;
    }
    try {
      const eng = await create.mutateAsync({
        name: name.trim(), client_name: client.trim(),
        description: desc.trim() || undefined,
        scope: scope.trim() || undefined,
        webhook_url: webhook.trim() || undefined,
      });
      navigate(`/engagements/${eng.id}`);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to create engagement');
    }
  }

  return (
    <>
      <div style={{ maxWidth: 580, margin: '0 auto' }}>
        <div className="topbar">
          <div>
            <div style={{ fontSize:12, color:'var(--muted)', marginBottom:4 }}>
              <a href="/engagements" style={{ color:'var(--muted)', textDecoration:'none' }}
                 onClick={e => { e.preventDefault(); navigate('/engagements'); }}>
                Engagements
              </a> / New
            </div>
            <h1>New Engagement</h1>
          </div>
        </div>

        <div className="card" style={{ padding: 28 }}>
          <form onSubmit={submit}>
            {error && (
              <div style={{
                background:'#2d1414', color:'#ef4444',
                border:'1px solid #5a2020', borderRadius:8,
                padding:'10px 12px', marginBottom:20, fontSize:13,
              }}>
                {error}
              </div>
            )}

            <Field label="Engagement Name *">
              <input value={name} onChange={e => setName(e.target.value)}
                     placeholder="Web Application Penetration Test" autoFocus />
            </Field>

            <Field label="Client Name *">
              <input value={client} onChange={e => setClient(e.target.value)}
                     placeholder="Acme Corp" />
            </Field>

            <Field label="Description">
              <textarea value={desc} onChange={e => setDesc(e.target.value)}
                        placeholder="Briefly describe the scope and objectives…"
                        rows={3} style={{ resize:'vertical' }} />
            </Field>

            <Field label="In-Scope Targets"
                   hint="One entry per line: CIDR (10.0.0.0/8), hostname (*.example.com), or URL prefix (https://app.example.com)">
              <textarea value={scope} onChange={e => setScope(e.target.value)}
                        placeholder={'*.example.com\nhttps://app.example.com\n10.10.0.0/16'}
                        rows={4} style={{ resize:'vertical', fontFamily:'monospace', fontSize:12 }} />
            </Field>

            <Field label="Webhook URL"
                   hint="Optional — notified with a JSON POST when a scan on this engagement finishes. Must be a public http(s) endpoint.">
              <input value={webhook} onChange={e => setWebhook(e.target.value)}
                     placeholder="https://hooks.example.com/mste" />
            </Field>

            <div style={{ display:'flex', gap:10, justifyContent:'flex-end', marginTop:8 }}>
              <button type="button" className="btn btn-ghost"
                      onClick={() => navigate('/engagements')}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary"
                      disabled={create.isPending}>
                {create.isPending ? 'Creating…' : 'Create Engagement'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </>
  );
}

function Field({ label, hint, children }: {
  label: string; hint?: string; children: React.ReactNode;
}) {
  return (
    <div style={{ marginBottom: 20 }}>
      <label style={{
        display:'block', fontSize:11, fontWeight:600, color:'var(--muted)',
        textTransform:'uppercase', letterSpacing:'.4px', marginBottom:6,
      }}>
        {label}
      </label>
      {children}
      {hint && (
        <div style={{ fontSize:11, color:'var(--muted)', marginTop:5, lineHeight:1.5 }}>
          {hint}
        </div>
      )}
    </div>
  );
}
