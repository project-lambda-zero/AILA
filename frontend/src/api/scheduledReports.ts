/**
 * React Query hooks + narrowed TS interfaces for the scheduled-reports
 * surface -- recurring server-side report generation delivered to a fixed
 * recipient list on a cron, exposed under `/scheduled-reports/*`.
 *
 * Endpoints wrapped here (from src/aila/api/routers/scheduled_reports.py):
 *   GET  /scheduled-reports/kinds              -> list[ScheduledReportKind]
 *   POST /scheduled-reports                    -> ScheduledReportRow
 *
 * The list/detail/edit/delete surfaces stay on the generic DataPage paths;
 * only the CREATE flow needs a dedicated mutation (its onSuccess invalidates
 * the datapage list) and only the detail panel needs the kinds catalog plus
 * the /tasks/{id} poller after a manual trigger.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { ApiError, apiFetch, apiFetchEnvelope } from "./client";

/** One declared config option for a report kind's config_json (mirrors
 * ScheduledReportKindOption). `type` is "string" | "boolean" | "select". */
export interface ScheduledReportKindOption {
  key: string;
  type: string;
  label: string;
  default: string | boolean | null;
  required: boolean;
  options: string[] | null;
}

/** One row of GET /scheduled-reports/kinds (mirrors
 * ScheduledReportKindResponse). `config_schema` drives the wizard's typed
 * options step; an empty array means the kind takes free-form options. */
export interface ScheduledReportKind {
  report_type: string;
  name: string;
  description: string;
  config_schema: ScheduledReportKindOption[];
}

/** One row of GET /scheduled-reports (mirrors ScheduledReportResponse). */
export interface ScheduledReportRow {
  id: string;
  name: string;
  report_type: string;
  cron_expression: string;
  recipient_emails_json: string;
  config_json: string;
  is_active: boolean;
  last_run_at: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
}

/** POST /scheduled-reports body. The two _json fields carry SERIALIZED
 * strings exactly as the backend stores them (recipient array / config
 * object) -- the wizard JSON.stringify's its collected values. */
export interface ScheduledReportCreate {
  name: string;
  report_type: string;
  cron_expression: string;
  recipient_emails_json: string;
  config_json: string;
  is_active: boolean;
}

/** POST /scheduled-reports/{id}/trigger response (mirrors
 * ScheduledReportTriggerResponse). task_id is "manual" when arq/Redis is
 * unavailable -- the run happens on the next worker cycle, nothing to poll. */
export interface ScheduledReportTriggerResponse {
  report_id: string;
  task_id: string;
  status: string;
}

/** Minimal /tasks/{id} projection the poller reads (GET /tasks/{task_id}
 * returns the TaskResponse row flat, not nested under `data`). */
export interface TaskStatusView {
  status: string;
  error: string | null;
}

/** The four terminal TaskRecord states; polling stops on one of these. */
export const TASK_TERMINAL: Record<string, true> = {
  done: true,
  failed: true,
  cancelled: true,
  dead_letter: true,
};

export function useScheduledReportKinds() {
  return useQuery({
    queryKey: ["scheduled-reports", "kinds"],
    queryFn: () => apiFetch<ScheduledReportKind[]>("/scheduled-reports/kinds"),
    staleTime: 60_000,
  });
}

export function useCreateScheduledReport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: ScheduledReportCreate) =>
      apiFetch<ScheduledReportRow>("/scheduled-reports", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      // The wizard's own key plus the console list window, which fetches via
      // DataPage under ["datapage", endpoint] -- invalidate both so the row
      // appears immediately after the wizard's step-5 submit.
      void qc.invalidateQueries({ queryKey: ["scheduled-reports"] });
      void qc.invalidateQueries({ queryKey: ["datapage", "/scheduled-reports"] });
    },
  });
}

/** Poll one task to a terminal state. The task row can lag the enqueue by a
 * beat, so a few 404s are tolerated; the interval stops on TASK_TERMINAL. */
export function useScheduledReportTask(taskId: string | null) {
  return useQuery({
    queryKey: ["task", taskId],
    queryFn: () => apiFetchEnvelope<TaskStatusView>(`/tasks/${taskId ?? ""}`),
    enabled: taskId !== null,
    retry: (count, err) => err instanceof ApiError && err.status === 404 && count < 5,
    refetchInterval: (query) => {
      const s = query.state.data?.status;
      return s && TASK_TERMINAL[s] ? false : 2000;
    },
  });
}
