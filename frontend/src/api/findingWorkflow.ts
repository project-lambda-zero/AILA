/**
 * Shared React Query hooks + narrowed TS interfaces for the platform-owned
 * finding workflow surface. Mirrors backend routes:
 *   GET  /findings/workflow/states[?module_id=<mod>]
 *   POST /findings/{finding_id}/transition
 *
 * The GET endpoint returns the base state machine merged with the module-
 * specific extension when `module_id` is supplied (base + only that module's
 * prefixed states/transitions); without `module_id` it returns the base plus
 * every registered module's extensions (a merged read for the admin overview).
 *
 * The POST endpoint enforces the module-scoped transition graph server-side;
 * illegal targets return 422 with a message pointing at the offending edge.
 * Operator+ role.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "./client";

export interface WorkflowStateDefinition {
  states: string[];
  transitions: Record<string, string[]>;
}

export interface FindingTransitionRequest {
  finding_id: number | string;
  module_id: string;
  target_state: string;
  notes?: string;
}

/** Fetch the state machine visible for `moduleId`. Passing null returns the
 * merged (base + all modules) overview used by the admin surface. */
export function useFindingWorkflowStates(moduleId: string | null) {
  const qs = moduleId ? `?module_id=${encodeURIComponent(moduleId)}` : "";
  return useQuery({
    queryKey: ["finding-workflow", "states", moduleId ?? "__all__"],
    queryFn: () =>
      apiFetch<WorkflowStateDefinition>(`/findings/workflow/states${qs}`),
    staleTime: 5 * 60_000,
  });
}

/** Return the legal next-states for a given current state in the fetched
 * machine. Safe against undefined data (returns []) so callers can render
 * without gating on loading. */
export function legalNextStates(
  def: WorkflowStateDefinition | undefined,
  current: string | null | undefined,
): string[] {
  if (!def) return [];
  const key = String(current ?? "").trim();
  const arr = def.transitions[key];
  return Array.isArray(arr) ? arr : [];
}

/** Transition one finding through the module-scoped state machine. On success
 * every list/detail query keyed on the module's findings surface is
 * invalidated so the row's `workflow_state` reflects the new value. */
export function useTransitionFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: FindingTransitionRequest) =>
      apiFetch<unknown>(`/findings/${vars.finding_id}/transition`, {
        method: "POST",
        body: JSON.stringify({
          target_state: vars.target_state,
          notes: vars.notes ?? "",
          module_id: vars.module_id,
        }),
      }),
    onSuccess: (_data, vars) => {
      // Invalidate cross-module list caches used by the three findings views
      // (bespoke VR panel, DataPage-driven malware, forensics project tab) so
      // the badge + facets refresh immediately.
      void qc.invalidateQueries({ queryKey: ["vuln", "findings"] });
      void qc.invalidateQueries({ queryKey: ["vuln", "facets"] });
      void qc.invalidateQueries({ queryKey: ["vuln", "finding"] });
      // Malware findings render via DataPage, whose list cache is keyed on
      // ["datapage", <endpoint>]. Invalidating the prefix refreshes every
      // paged variant regardless of the current page/scope.
      void qc.invalidateQueries({ queryKey: ["datapage"] });
      void qc.invalidateQueries({ queryKey: ["forensics"] });
      void qc.invalidateQueries({
        queryKey: ["finding-workflow", "states", vars.module_id],
      });
    },
  });
}
