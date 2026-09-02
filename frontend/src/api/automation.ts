/**
 * React Query hooks + narrowed TS interfaces for the automation surface --
 * the platform's cron-driven action runner exposed under `/automation/*`.
 *
 * Endpoints wrapped here (from src/aila/api/routers/automation.py):
 *   GET  /automation/actions            -> list[AutomationActionInfo]
 *   GET  /automation/schedules          -> list[AutomationScheduleResponse]
 *   POST /automation/schedules          -> AutomationScheduleResponse
 *
 * DELETE / PATCH stay in the generic DataPage delete + edit form paths; only
 * the CREATE flow needs a dedicated mutation so its onSuccess can invalidate
 * the schedules list the moment the wizard's step-5 submit lands.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "./client";

/** One row of GET /automation/actions. `param_schema` is a small
 * JSON-Schema-ish descriptor of the action's kwargs; today the registry
 * returns null for every action but the wizard is contract-ready for the
 * moment an action starts declaring typed args. */
export interface AutomationActionInfo {
  action_id: string;
  description: string;
  module_id: string;
  param_schema?: Record<string, unknown> | null;
}

/** One row of GET /automation/schedules (mirrors AutomationScheduleResponse). */
export interface AutomationSchedule {
  id: number;
  action_id: string;
  target_name: string;
  cron_expression: string;
  enabled: boolean;
  action_kwargs: Record<string, unknown> | null;
  last_run_at: string | null;
  last_run_result: string | null;
  created_at: string | null;
  updated_at: string | null;
}

/** POST /automation/schedules body. `action_kwargs` is optional; the wizard
 * omits it when empty so the server stores null. `enabled` defaults true on
 * the backend but we send it explicitly so the review step reads honestly. */
export interface AutomationScheduleCreate {
  action_id: string;
  target_name: string;
  cron_expression: string;
  action_kwargs?: Record<string, unknown> | null;
  enabled: boolean;
}

export function useAutomationActions() {
  return useQuery({
    queryKey: ["automation", "actions"],
    queryFn: () => apiFetch<AutomationActionInfo[]>("/automation/actions"),
    staleTime: 60_000,
  });
}

export function useAutomationSchedules() {
  return useQuery({
    queryKey: ["automation", "schedules"],
    queryFn: () => apiFetch<AutomationSchedule[]>("/automation/schedules"),
    staleTime: 15_000,
  });
}

export function useCreateAutomationSchedule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: AutomationScheduleCreate) =>
      apiFetch<AutomationSchedule>("/automation/schedules", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["automation", "schedules"] });
      // The console list window fetches via DataPage, which keys its query
      // under ["datapage", endpoint]; invalidate that so the row appears
      // immediately after the wizard's step-5 submit.
      void qc.invalidateQueries({ queryKey: ["datapage", "/automation/schedules"] });
    },
  });
}
