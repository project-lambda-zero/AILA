/**
 * Types for the Admin Workflow Inspector (/admin/workflows).
 *
 * WorkflowRunView mirrors the backend WorkflowRunView Pydantic model.
 * TransitionView is reused from tasks/ -- not redefined.
 * DataEnvelope mirrors the backend DataEnvelope schema.
 */

export interface WorkflowRunView {
  run_id: string;
  current_state: string;
  definition_id: string;
  retries_in_state: number;
  version: number;
  updated_at: string;
}

export interface DataEnvelope<T> {
  data: T;
}
