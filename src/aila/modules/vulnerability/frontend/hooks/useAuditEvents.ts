import { useQuery } from "@tanstack/react-query";

import { authorizedRequestJson } from "@platform/api/http";

/**
 * Local mirror of aila.api.schemas.audit.AuditEventResponse -- shape only,
 * intentionally duplicated per FRONTEND_MODULE_STANDARD (no cross-module
 * imports from other @aila/*-frontend packages). Kept minimal to the fields
 * the activity timeline actually renders.
 */
export interface AuditEvent {
  id: number | null;
  run_id: string;
  stage: string;
  action: string;
  status: string;
  target: string;
  user_id: string;
  details: Record<string, unknown>;
  created_at: string | null;
}

export interface AuditListResponse {
  total: number;
  page: number;
  page_size: number;
  pages: number;
  items: AuditEvent[];
}

interface Envelope<T> {
  data: T;
  error: string | null;
  meta: Record<string, unknown>;
}

/**
 * Fetch the first page of audit events for a given run id. The audit router
 * (src/aila/api/routers/audit.py) exposes `/audit/events?run_id=...` and
 * returns rows ordered by created_at DESC. Disabled when `runId` is falsy so
 * the empty-state path does not fire a stray request.
 */
export function useAuditEvents(
  runId: string | null | undefined,
  opts: { pageSize?: number } = {},
) {
  const pageSize = opts.pageSize ?? 50;
  return useQuery({
    queryKey: ["audit", "events", runId ?? null, pageSize],
    queryFn: async () =>
      (
        await authorizedRequestJson<Envelope<AuditListResponse>>(
          `/audit/events?run_id=${encodeURIComponent(runId ?? "")}&page=1&page_size=${pageSize}`,
        )
      ).data,
    enabled: !!runId,
  });
}
