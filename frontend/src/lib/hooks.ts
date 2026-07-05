/**
 * hooks.ts — TanStack Query hooks wrapping every API call.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, admin, auth, engagements, findings, search } from './api';
import type { FindingOut, PaginatedFindings } from './api';

// ── Query keys ────────────────────────────────────────────────────────────────
export const QK = {
  me:          ['me']                                as const,
  engagements: (status?: string) => ['engagements', status] as const,
  engagement:  (id: number)      => ['engagement',  id]     as const,
  scans:       (engId: number)   => ['scans',       engId]  as const,
  scanStatus:  (scanId: string)  => ['scan-status', scanId] as const,
  delta:       (engId: number)   => ['delta',       engId]  as const,
  findings:    (p: object)       => ['findings',    p]      as const,
  finding:     (id: number)      => ['finding',     id]     as const,
  search:      (q: string)       => ['search',      q]      as const,
  users:       ['users']                             as const,
  audit:       (p: object)       => ['audit',       p]      as const,
  templates:   ['report-templates']                  as const,
  notifications: ['notifications']                    as const,
  myFindings:  (p: object)       => ['my-findings', p]      as const,
};


// ── Auth ──────────────────────────────────────────────────────────────────────

export function useMe() {
  return useQuery({ queryKey: QK.me, queryFn: auth.me, retry: false });
}

export function useChangePassword() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ current_password, new_password }: {
      current_password: string; new_password: string;
    }) => auth.changePassword(current_password, new_password),
    onSuccess: () => qc.invalidateQueries({ queryKey: QK.me }),
  });
}


// ── Engagements ───────────────────────────────────────────────────────────────

export function useEngagements(status?: string) {
  return useQuery({
    queryKey: QK.engagements(status),
    queryFn:  () => engagements.list(status),
  });
}

export function useEngagement(id: number) {
  return useQuery({
    queryKey: QK.engagement(id),
    queryFn:  () => engagements.get(id),
    enabled:  !!id,
  });
}

export function useCreateEngagement() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: engagements.create,
    onSuccess:  () => qc.invalidateQueries({ queryKey: ['engagements'] }),
  });
}

export function useUpdateEngagement(id: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Parameters<typeof engagements.update>[1]) =>
      engagements.update(id, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: QK.engagement(id) });
      qc.invalidateQueries({ queryKey: ['engagements'] });
    },
  });
}

export function useDeleteEngagement() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => engagements.delete(id),
    onSuccess:  () => qc.invalidateQueries({ queryKey: ['engagements'] }),
  });
}

// Modeled as mutations (not queries) even though these are GET/reveal —
// a secret shouldn't be fetched automatically on mount / kept warm in the
// background cache; it should only ever be retrieved in direct response to
// the user clicking "Reveal".
export function useRevealWebhookSecret(engId: number) {
  return useMutation({
    mutationFn: () => engagements.webhookSecret.get(engId),
  });
}

export function useRotateWebhookSecret(engId: number) {
  return useMutation({
    mutationFn: () => engagements.webhookSecret.rotate(engId),
  });
}

export function useScans(engId: number) {
  return useQuery({
    queryKey: QK.scans(engId),
    queryFn:  () => engagements.scans(engId),
    enabled:  !!engId,
    refetchInterval: (query) => {
      const data = query.state.data;
      return data?.some(s => s.status === 'Running' || s.status === 'Queued')
        ? 5000 : false;
    },
  });
}

export function useStartScan(engId: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      engagements.startScan(engId, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: QK.scans(engId) });
      qc.invalidateQueries({ queryKey: QK.engagement(engId) });
    },
  });
}

export function useCancelScan(engId: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (scanId: string) => engagements.cancelScan(engId, scanId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: QK.scans(engId) });
      qc.invalidateQueries({ queryKey: QK.engagement(engId) });
    },
  });
}

export function useDelta(engId: number, sinceScanId?: string) {
  return useQuery({
    queryKey: [...QK.delta(engId), sinceScanId],
    queryFn:  () => engagements.delta(engId, sinceScanId),
    enabled:  !!engId,
    retry:    false,
  });
}

export function useScanStatus(scanId: string, enabled = true) {
  return useQuery({
    queryKey: QK.scanStatus(scanId),
    queryFn:  () => findings.scanStatus(scanId),
    enabled:  enabled && !!scanId,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status && !['Completed','Failed','Cancelled'].includes(status)
        ? 5000 : false;
    },
  });
}


// ── Findings ──────────────────────────────────────────────────────────────────

export function useFindings(params: {
  severity?: string; status?: string; tool?: string;
  scan_id?: string; engagement_id?: number; limit?: number; offset?: number;
} = {}) {
  return useQuery({
    queryKey: QK.findings(params),
    queryFn:  () => findings.list(params),
    placeholderData: (prev: PaginatedFindings | undefined) => prev,
  });
}

export function useMyFindings(params: {
  severity?: string; status?: string; limit?: number; offset?: number;
} = {}) {
  return useQuery({
    queryKey: QK.myFindings(params),
    queryFn:  () => api.get('/api/findings/my', { params }).then(r => r.data),
  });
}

export function useFinding(id: number) {
  return useQuery({
    queryKey: QK.finding(id),
    queryFn:  () => findings.get(id),
    enabled:  !!id,
  });
}

export function useUpdateFindingStatus() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, status, notes }: {
      id: number; status: string; notes?: string
    }) => findings.updateStatus(id, status, notes),
    onSuccess: (updated: FindingOut) => {
      qc.invalidateQueries({ queryKey: QK.finding(updated.id) });
      qc.invalidateQueries({ queryKey: ['findings'] });
    },
  });
}

export function useUpdateFindingNotes() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, notes }: { id: number; notes: string }) =>
      findings.updateNotes(id, notes),
    onSuccess: (updated: FindingOut) => {
      qc.invalidateQueries({ queryKey: QK.finding(updated.id) });
    },
  });
}

export function useCreateManualFinding(scanId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Parameters<typeof findings.createManual>[1]) =>
      findings.createManual(scanId, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['findings'] }),
  });
}

export function useBulkStatus() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ ids, status, notes }: {
      ids: number[]; status: string; notes?: string
    }) => findings.bulkStatus(ids, status, notes),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['findings'] }),
  });
}

export function useAssignFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, assigned_to, due_date }: {
      id: number; assigned_to?: number | null; due_date?: string | null;
    }) => api.patch(`/api/findings/${id}/assign`, { assigned_to, due_date }).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['findings'] });
      qc.invalidateQueries({ queryKey: ['my-findings'] });
    },
  });
}


// ── Notifications ───────────────────────────────────────────────────────────────

export function useNotifications() {
  const { data, refetch } = useQuery({
    queryKey: QK.notifications,
    queryFn: () => api.get('/api/notifications').then(r => r.data),
    refetchInterval: 30000,
  });

  const markRead = useMutation({
    mutationFn: (id: number) => api.post(`/api/notifications/${id}/read`).then(r => r.data),
    onSuccess: () => refetch(),
  });

  const markAllRead = useMutation({
    mutationFn: () => api.post('/api/notifications/read-all').then(r => r.data),
    onSuccess: () => refetch(),
  });

  return { notifications: data, markRead, markAllRead, refetch };
}


// ── Search ────────────────────────────────────────────────────────────────────

export function useSearch(q: string, scope = 'all') {
  return useQuery({
    queryKey: QK.search(q),
    queryFn:  () => search.query(q, scope),
    enabled:  q.length >= 2,
  });
}


// ── Admin ─────────────────────────────────────────────────────────────────────

export function useUsers() {
  return useQuery({ queryKey: QK.users, queryFn: admin.users.list });
}

export function useCreateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: admin.users.create,
    onSuccess:  () => qc.invalidateQueries({ queryKey: QK.users }),
  });
}

export function useSetUserRole() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ userId, role }: { userId: number; role: string }) =>
      admin.users.setRole(userId, role),
    onSuccess: () => qc.invalidateQueries({ queryKey: QK.users }),
  });
}

export function useDeleteUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (userId: number) => admin.users.delete(userId),
    onSuccess:  () => qc.invalidateQueries({ queryKey: QK.users }),
  });
}

export function useAuditLog(params: {
  page?: number; action_filter?: string; user_filter?: string;
} = {}) {
  return useQuery({
    queryKey: QK.audit(params),
    queryFn:  () => admin.audit(params),
  });
}

export function useReportTemplates() {
  return useQuery({
    queryKey: QK.templates,
    queryFn:  admin.reportTemplates.list,
  });
}

// Analyst-accessible equivalent of useReportTemplates, used by the
// per-engagement template picker — admin.reportTemplates.list() 403s for
// non-admins. Shares the same query key/cache since both return the same
// ReportTemplateOut[] shape.
export function useEngagementReportTemplates() {
  return useQuery({
    queryKey: QK.templates,
    queryFn:  engagements.reportTemplates,
  });
}

export function useUploadLogo() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ templateId, file }: { templateId: number; file: File }) =>
      admin.reportTemplates.uploadLogo(templateId, file),
    onSuccess: () => qc.invalidateQueries({ queryKey: QK.templates }),
  });
}


// ── Integrations ────────────────────────────────────────────────────────────────

export function useIntegrations(engId: number) {
  return useQuery({
    queryKey: ['integrations', engId],
    queryFn: () => api.get(`/api/integrations/engagement/${engId}`).then(r => r.data),
    enabled: !!engId,
  });
}

export function useCreateIntegration() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { engagement_id: number; provider: string; base_url: string; auth_token: string; project_key?: string }) =>
      api.post('/api/integrations', body).then(r => r.data),
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ['integrations', vars.engagement_id] });
    },
  });
}

export function useDeleteIntegration() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.delete(`/api/integrations/${id}`).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['integrations'] }),
  });
}

export function useCreateTicket() {
  return useMutation({
    mutationFn: ({ cfgId, findingId }: { cfgId: number; findingId: number }) =>
      api.post(`/api/integrations/${cfgId}/ticket/${findingId}`).then(r => r.data),
  });
}
