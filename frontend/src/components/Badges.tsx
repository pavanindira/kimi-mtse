// Shared badge components used across multiple pages

const SEV_STYLES: Record<string, { bg: string; color: string }> = {
  Critical: { bg: '#2d1414', color: '#ef4444' },
  High:     { bg: '#2d1a0a', color: '#f97316' },
  Medium:   { bg: '#2a2200', color: '#eab308' },
  Low:      { bg: '#0d1f3c', color: '#3b82f6' },
  Info:     { bg: '#1a1d26', color: '#6b7280' },
};

const STATUS_STYLES: Record<string, { bg: string; color: string }> = {
  Queued:            { bg: '#1a1d26', color: '#6b7280' },
  Running:           { bg: '#0d2040', color: '#60a5fa' },
  Completed:         { bg: '#0d2a1a', color: '#4ade80' },
  Failed:            { bg: '#2d1414', color: '#ef4444' },
  Cancelled:         { bg: '#1a1d26', color: '#6b7280' },
  Open:              { bg: '#0d2040', color: '#60a5fa' },
  Confirmed:         { bg: '#2d1414', color: '#ef4444' },
  Fixed:             { bg: '#0d2a1a', color: '#4ade80' },
  'False Positive':  { bg: '#1a1d26', color: '#6b7280' },
  'Accepted Risk':   { bg: '#2a2200', color: '#eab308' },
};

const badgeStyle = (styles: Record<string, { bg: string; color: string }>, key: string) => ({
  display: 'inline-block' as const,
  padding: '2px 8px',
  borderRadius: 4,
  fontSize: 11,
  fontWeight: 600,
  textTransform: 'uppercase' as const,
  letterSpacing: '.4px',
  whiteSpace: 'nowrap' as const,
  ...(styles[key] ?? { bg: '#1a1d26', color: '#6b7280' }),
  background: (styles[key] ?? { bg: '#1a1d26' }).bg,
});

export function SevBadge({ severity }: { severity: string }) {
  return (
    <span style={badgeStyle(SEV_STYLES, severity)}>
      {severity}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const isRunning = status === 'Running';
  return (
    <span style={{
      ...badgeStyle(STATUS_STYLES, status),
      ...(isRunning ? { animation: 'pulse 1.6s ease-in-out infinite' } : {}),
    }}>
      {status}
    </span>
  );
}

export function CvssBadge({ score }: { score: number | null }) {
  if (!score) return <span style={{ color: 'var(--muted)', fontSize: 12 }}>—</span>;
  const color = score >= 9 ? '#ef4444' : score >= 7 ? '#f97316' :
                score >= 4 ? '#eab308' : '#3b82f6';
  return (
    <span style={{ fontFamily: 'monospace', fontSize: 12, color }}>
      {score.toFixed(1)}
    </span>
  );
}
