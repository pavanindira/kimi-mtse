/**
 * hooks.ts — TanStack Query hooks wrapping every API call.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { admin, auth, engagements, findings, search } from './api';
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
