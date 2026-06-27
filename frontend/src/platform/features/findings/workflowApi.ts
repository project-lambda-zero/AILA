/**
 * Findings workflow API hooks.
 *
 * Wraps the FastAPI router at src/aila/api/routers/findings_workflow.py:
 *   GET  /findings/workflow/states         -- state machine definition
 *   GET  /findings/{finding_id}/workflow   -- current state + transition history
 *   POST /findings/{finding_id}/transition -- transition to a new state
 *
 * All responses are wrapped in a DataEnvelope; hooks unwrap to plain data so
 * callers receive the domain object directly.
 */
import {
  useMutation,
  useQuery,
  useQueryClient,
  type QueryKey,
} from "@tanstack/react-query";

import { authorizedRequestJson } from "@platform/api/http";

// ---------------------------------------------------------------------------
// Types -- mirror src/aila/api/schemas/endpoints.py exactly.
// ---------------------------------------------------------------------------

export interface WorkflowStateDefinition {
  states: string[];
  /** Map of `from_state -> [allowed next states]`. */
  transitions: Record<string, string[]>;
}

export interface FindingWorkflowHistoryEntry {
  id: string;
  finding_id: string;
  module_id: string;
  current_state: string;
  previous_state: string | null;
  transitioned_by: string;
  notes: string;
  created_at: string;
}

export interface FindingWorkflowState {
  finding_id: string;
  current_state: string;
  history: FindingWorkflowHistoryEntry[];
}

export interface TransitionFindingRequest {
  findingId: number | string;
  /** Target state -- must be in the legal next-state list for current_state. */
  target_state: string;
  /** Operator note, surfaced in the transition history. */
  notes?: string;
  /** Module attributing the transition. Defaults to "platform". */
  module_id?: string;
}

interface DataEnvelope<T> {
  data: T;
  meta?: unknown;
}

// ---------------------------------------------------------------------------
// Query keys -- exported so callers can invalidate from outside this module.
// ---------------------------------------------------------------------------

export const workflowQueryKeys = {
  states: ["findings", "workflow", "states"] as const,
  finding: (id: number | string): QueryKey => ["findings", "workflow", String(id)],
};

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

/**
 * useWorkflowStates -- fetch the canonical state machine definition.
 *
 * Calls GET /findings/workflow/states. The backend merges any module-
 * contributed states/transitions, so the result reflects every state any
 * registered module exposes. Cached for 5m since the definition is static.
 */
export function useWorkflowStates() {
  return useQuery({
    queryKey: workflowQueryKeys.states,
    queryFn: async () => {
      const resp = await authorizedRequestJson<DataEnvelope<WorkflowStateDefinition>>(
        "/findings/workflow/states",
      );
      return resp.data;
    },
    staleTime: 5 * 60_000,
  });
}

/**
 * useFindingWorkflow -- fetch the current workflow state and full transition
 * history for a single finding.
 *
 * Calls GET /findings/{finding_id}/workflow. Disabled when findingId is null.
 */
export function useFindingWorkflow(findingId: number | string | null) {
  const enabled = findingId !== null;
  return useQuery({
    queryKey: enabled
      ? workflowQueryKeys.finding(findingId as number | string)
      : ["findings", "workflow", "__disabled__"],
    enabled,
    queryFn: async () => {
      const id = encodeURIComponent(String(findingId));
      const resp = await authorizedRequestJson<DataEnvelope<FindingWorkflowState>>(
        `/findings/${id}/workflow`,
      );
      return resp.data;
    },
    staleTime: 30_000,
  });
}

/**
 * useTransitionFinding -- POST /findings/{id}/transition.
 *
 * The backend enforces the state machine server-side; an illegal transition
 * comes back as 422. On success we invalidate:
 *   - The single-finding workflow query (drives detail panels & dialogs).
 *   - The vulnerability findings list, kanban roll-up, facets, and detail
 *     queries, so the table badge, kanban column, and facet counts all
 *     reflect the new state without a manual refresh.
 */
export function useTransitionFinding() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({
      findingId,
      target_state,
      notes,
      module_id,
    }: TransitionFindingRequest) => {
      const id = encodeURIComponent(String(findingId));
      const resp = await authorizedRequestJson<DataEnvelope<FindingWorkflowHistoryEntry>>(
        `/findings/${id}/transition`,
        {
          method: "POST",
          body: {
            target_state,
            notes: notes ?? "",
            module_id: module_id ?? "platform",
          },
        },
      );
      return resp.data;
    },
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({
        queryKey: workflowQueryKeys.finding(variables.findingId),
      });
      // Vulnerability module surfaces -- see queries.ts in
      // src/aila/modules/vulnerability/frontend/.
      queryClient.invalidateQueries({ queryKey: ["vulnerability", "findings"] });
      queryClient.invalidateQueries({ queryKey: ["vulnerability", "finding-facets"] });
      queryClient.invalidateQueries({ queryKey: ["vulnerability", "finding-detail"] });
      queryClient.invalidateQueries({
        queryKey: ["vulnerability", "findings-all-filtered"],
      });
    },
  });
}
