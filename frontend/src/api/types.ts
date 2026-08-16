/** Shapes returned by the AILA backend, narrowed to the fields the console uses. */

export interface User {
  id?: string;
  username?: string;
  role?: string;
}

export interface LoginResponse {
  access_token: string;
  token_type?: string;
  user?: User;
}

export interface Investigation {
  id: string;
  title: string;
  target_id?: string | null;
  status?: string;
  phase?: string;
  kind?: string;
  is_favorite?: boolean;
  auto_pilot?: boolean;
  pause_reason?: string | null;
  failure_reason?: string | null;
  message_count?: number;
  branch_count?: number;
  outcome_count?: number;
  strategy_family?: string | null;
  cost_budget_usd?: number;
  cost_actual_usd?: number;
  llm_tokens_cost_usd?: number;
  mcp_calls_cost_usd?: number;
  primary_outcome_kind?: string | null;
  primary_outcome_confidence?: string | null;
  primary_outcome_verdict_head?: string | null;
  primary_outcome_polarity?: string | null;
  verifier_verdict?: string | null;
  verifier_confidence?: number | null;
  started_at?: string | null;
  stopped_at?: string | null;
  created_at?: string;
  updated_at?: string;
}

/** One conversational turn. `payload` shape depends on `payload_kind`. */
export interface Message {
  id: string;
  investigation_id: string;
  branch_id?: string | null;
  sender_kind: string; // operator | engine | agent | system
  sender_id?: string | null;
  payload_kind: string; // text | tool_call | hypothesis_update | taint_flow | ...
  payload: Record<string, unknown>;
  operator_intent?: string | null;
  at_turn?: number | null;
  evidence_refs?: string[];
  created_at?: string;
}

export interface Branch {
  id: string;
  investigation_id?: string;
  status: string; // active | closed | merged | paused | ...
  strategy_family?: string | null;
  persona_voice?: string | null;
  turn_count?: number;
  branch_cost_usd?: number;
  promoted?: boolean;
  parent_branch_id?: string | null;
  fork_reason?: string | null;
  fork_at_turn?: number | null;
  closed_reason?: string | null;
}

export interface Hypothesis {
  id: string;
  claim: string;
  state: string; // live | rejected | resolved | ...
  kill_criterion?: string | null;
  why_plausible?: string | null;
  live_in_branches?: string[];
  rejected_in_branches?: string[];
  resolved_in_branches?: string[];
  rejection_reason?: string | null;
  resolution_note?: string | null;
}

/** One phase node in the dispatch hub graph. */
export interface DispatchPhase {
  id: string;
  capability?: string | null;
  trust?: string | null;
}

/** Aggregated dispatch-hub state for an investigation (union across branches). */
export interface DispatchState {
  phases: DispatchPhase[];
  visited: string[];
  current: string[];
  last?: string | null;
  reason?: string | null;
  phase_trust?: string | null;
  replan_relax?: boolean;
  budget_exhausted?: boolean;
}

/** One append-only investigation-ledger entry (shared blackboard). */
export interface LedgerRow {
  id: number;
  kind: string; // discovery | request | decision | note | objective
  intent?: string | null; // activate_phase | request_specialist | write_objective | open_objective | replan
  objective_key?: string | null;
  author_branch_id?: string | null;
  owner_branch_id?: string | null;
  status?: string | null; // open | ratified | applied | ...
  target_capability?: string | null;
  text: string;
  created_at?: string | null;
}

/** One MCP bridge call logged during an investigation. */
export interface McpCall {
  id: string;
  server_id: string;
  action: string;
  status: string; // ready | error | pending
  http_status?: number | null;
  latency_ms?: number | null;
  error_excerpt?: string | null;
  branch_id?: string | null;
  turn_number?: number | null;
  called_at?: string | null;
}
