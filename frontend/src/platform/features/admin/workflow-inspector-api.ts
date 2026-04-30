/**
 * API layer for the Admin Workflow Inspector (/admin/workflows).
 *
 * Uses authorizedRequestJson<T> exclusively — no raw fetch, no hardcoded /api/ paths.
 * Every call has an explicit type parameter (honesty rule 11).
 *
 * fetchWorkflowRunTransitions hits /admin/workflows/runs/{id}/transitions,
 * which is DISTINCT from the tasks/ endpoint (/tasks/{id}/transitions).
 * Do NOT reuse or merge with fetchTransitions in tasks/transitions.ts.
 */

import { authorizedRequestJson } from "@platform/api/http";
import type { TransitionView } from "@platform/features/tasks/transitions";
import type { DataEnvelope, WorkflowRunView } from "./workflow-inspector-types";

export async function fetchWorkflowRuns(params: {
  definition_id?: string;
  current_state?: string;
}): Promise<WorkflowRunView[]> {
  const qs = new URLSearchParams();
  if (params.definition_id) qs.set("definition_id", params.definition_id);
  if (params.current_state) qs.set("current_state", params.current_state);
  const envelope = await authorizedRequestJson<DataEnvelope<WorkflowRunView[]>>(
    `/admin/workflows/runs?${qs.toString()}`,
    { method: "GET" },
  );
  return envelope.data;
}

/**
 * Fetch transitions for a workflow run.
 *
 * Endpoint: GET /admin/workflows/runs/{run_id}/transitions
 * This is the admin endpoint — distinct from the task-scoped endpoint
 * GET /tasks/{task_id}/transitions used in tasks/transitions.ts.
 */
export async function fetchWorkflowRunTransitions(
  runId: string,
): Promise<TransitionView[]> {
  const envelope = await authorizedRequestJson<DataEnvelope<TransitionView[]>>(
    `/admin/workflows/runs/${encodeURIComponent(runId)}/transitions`,
    { method: "GET" },
  );
  return envelope.data;
}
