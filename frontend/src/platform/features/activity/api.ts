/**
 * Activity (per-run audit trail) types.
 *
 * Backend contract (aila.api.schemas.audit):
 *   AuditListResponse = PaginatedResponse[AuditEventResponse] ->
 *     { total, page, page_size, pages, items: AuditEvent[] }
 *
 * The `/audit/events` endpoint is shared with the admin AuditLogsPage; this
 * module keeps the run-scoped subset (a small set of filters + a page) so
 * shell entity surfaces can render a scoped Activity view without pulling
 * the full admin log.
 */

export interface ActivityEvent {
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

export interface ActivityListResponse {
  total: number;
  page: number;
  page_size: number;
  pages: number;
  items: ActivityEvent[];
}

export interface ActivityFilters {
  /** Comma-OR list of actions (backend filter). */
  action?: string;
  /** Comma-OR list of statuses (backend filter). */
  status?: string;
  /** ISO 8601 lower bound (inclusive). */
  since?: string;
  /** ISO 8601 upper bound (inclusive). */
  until?: string;
  /** 1-indexed page. Defaults to 1. */
  page?: number;
  /** 1..250. Defaults to 50 on the shell surfaces. */
  pageSize?: number;
}
