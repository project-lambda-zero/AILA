/**
 * Transition API types and fetch function (Phase 181).
 *
 * Mirrors the backend TransitionView Pydantic schema.
 * input_hash / output_hash are intentionally omitted -- backend does not expose them.
 */
import { authorizedRequestJson } from "@platform/api/http";

export interface TransitionView {
  run_id: string;
  seq: number;
  from_state: string | null;
  to_state: string;
  event: string;
  duration_ms: number | null;
  error_class: string | null;
  error_message: string | null;
  happened_at: string;
  task_id: string | null;
}

export interface TransitionsResponse {
  data: TransitionView[];
}

export async function fetchTransitions(taskId: string): Promise<TransitionView[]> {
  const response = await authorizedRequestJson<TransitionsResponse>(
    `/tasks/${encodeURIComponent(taskId)}/transitions`,
  );
  return response.data;
}
