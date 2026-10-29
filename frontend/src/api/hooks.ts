import { useMutation, useQuery, useQueryClient, type QueryClient } from "@tanstack/react-query";

import { apiFetch } from "./client";
import type {
  Branch,
  DispatchState,
  Hypothesis,
  Investigation,
  LedgerRow,
  McpCall,
  Message,
  OutcomeReview,
  VrFinding,
  VrOutcome,
} from "./types";

export function useInvestigations() {
  return useQuery({
    queryKey: ["vr", "investigations"],
    queryFn: () => apiFetch<Investigation[]>("/vr/investigations?limit=100"),
    staleTime: 15_000,
  });
}

export function useInvestigation(id: string | null) {
  return useQuery({
    queryKey: ["vr", "investigation", id],
    // Live investigation state: a remount must refetch instead of serving cache.
    staleTime: 0,
    queryFn: () => apiFetch<Investigation>(`/vr/investigations/${id}`),
    enabled: Boolean(id),
  });
}

export function useMessages(id: string | null) {
  return useQuery({
    queryKey: ["vr", "messages", id],
    staleTime: 0,
    queryFn: () => apiFetch<Message[]>(`/vr/investigations/${id}/messages?limit=1000`),
    enabled: Boolean(id),
    refetchInterval: 8000,
  });
}

export function useBranches(id: string | null) {
  return useQuery({
    queryKey: ["vr", "branches", id],
    staleTime: 0,
    queryFn: () => apiFetch<Branch[]>(`/vr/investigations/${id}/branches`),
    enabled: Boolean(id),
  });
}

export function useHypotheses(id: string | null) {
  return useQuery({
    queryKey: ["vr", "hypotheses", id],
    staleTime: 0,
    queryFn: () => apiFetch<Hypothesis[]>(`/vr/investigations/${id}/hypotheses`),
    enabled: Boolean(id),
  });
}

export function useDispatch(id: string | null) {
  return useQuery({
    queryKey: ["vr", "dispatch", id],
    staleTime: 0,
    queryFn: () => apiFetch<DispatchState>(`/vr/investigations/${id}/dispatch`),
    enabled: Boolean(id),
    retry: false,
    refetchInterval: 8000,
  });
}

export function useLedger(id: string | null) {
  return useQuery({
    queryKey: ["vr", "ledger", id],
    staleTime: 0,
    queryFn: () => apiFetch<LedgerRow[]>(`/vr/investigations/${id}/ledger`),
    enabled: Boolean(id),
    retry: false,
    refetchInterval: 8000,
  });
}

export function useMcpCalls(id: string | null) {
  return useQuery({
    queryKey: ["vr", "mcp-calls", id],
    staleTime: 0,
    queryFn: () => apiFetch<McpCall[]>(`/vr/investigations/${id}/mcp-calls`),
    enabled: Boolean(id),
    retry: false,
    refetchInterval: 8000,
  });
}

export function usePostMessage(id: string | null) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (arg: string | { text: string; intent?: string }) => {
      const text = typeof arg === "string" ? arg : arg.text;
      const intent = typeof arg === "string" ? undefined : arg.intent;
      const body: Record<string, unknown> = { text };
      if (intent) body.explicit_intent = intent;
      return apiFetch<Message>(`/vr/investigations/${id}/messages`, {
        method: "POST",
        body: JSON.stringify(body),
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["vr", "messages", id] });
    },
  });
}

// Operator controls with real backends: pause | resume | verify | reset.
// Each is a bodiless POST returning the updated investigation summary.
export function useInvestigationControl(id: string | null) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (action: string) =>
      apiFetch<Investigation>(`/vr/investigations/${id}/${action}`, { method: "POST" }),
    onSuccess: () => {
      for (const key of ["investigation", "messages", "branches", "dispatch", "ledger"]) {
        void queryClient.invalidateQueries({ queryKey: ["vr", key, id] });
      }
      void queryClient.invalidateQueries({ queryKey: ["vr", "investigations"] });
    },
  });
}

export function useToggleFavorite(id: string | null) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiFetch<Investigation>(`/vr/investigations/${id}/favorite`, { method: "PATCH" }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["vr", "investigation", id] });
      void queryClient.invalidateQueries({ queryKey: ["vr", "investigations"] });
    },
  });
}

// Enqueue the long-form narrative writeup (async, 202). The backend is
// idempotent without `force`; an operator-driven click passes `force: true`
// so it always (re)generates. Populates payload.investigation_narrative on
// the canonical outcome ~30-90s later.
export function useGenerateNarrative(id: string | null) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiFetch<Record<string, unknown>>(`/vr/investigations/${id}/narrative`, {
        method: "POST",
        body: JSON.stringify({ force: true }),
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["vr", "investigation", id] });
    },
  });
}


// -- X-Ray operator actions. ---------------------------------------------------

/** Branch operation request. `reason` is recorded as the branch's fork or
 *  close reason; fork and merge carry their extra fields. */
export type BranchOpRequest =
  | { op: "promote" | "abandon" | "pause" | "resume"; branchId: string; reason: string }
  | { op: "fork"; branchId: string; reason: string; persona_voice: string | null; at_turn: number | null }
  | { op: "merge"; branchId: string; reason: string; other_branch_id: string };

function invalidateBranchState(queryClient: QueryClient, id: string | null): void {
  for (const key of ["investigation", "branches", "messages", "dispatch"]) {
    void queryClient.invalidateQueries({ queryKey: ["vr", key, id] });
  }
}

export function useBranchOp(id: string | null) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ op, branchId, ...body }: BranchOpRequest) =>
      apiFetch<unknown>(`/vr/investigations/${id}/branches/${branchId}/${op}`, {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: () => invalidateBranchState(queryClient, id),
  });
}

export interface StrategyBranchRequest {
  strategy_family: string;
  persona_voice: string | null;
  rationale: string;
  parent_branch_id: string | null;
}

export interface SpawnedStrategyBranch {
  new_branch_id: string;
  strategy_family: string;
}

export function useSpawnStrategyBranch(id: string | null) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: StrategyBranchRequest) =>
      apiFetch<SpawnedStrategyBranch>(`/vr/investigations/${id}/strategy-branches`, {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: () => invalidateBranchState(queryClient, id),
  });
}

export function useVrOutcomes(id: string | null) {
  return useQuery({
    queryKey: ["vr", "outcomes", id],
    queryFn: () => apiFetch<VrOutcome[]>(`/vr/investigations/${id}/outcomes`),
    enabled: Boolean(id),
    refetchInterval: 10_000,
  });
}

export function useVrOutcomeReviews(id: string | null, outcomeId: string | null) {
  return useQuery({
    queryKey: ["vr", "outcome-reviews", id, outcomeId],
    queryFn: () => apiFetch<OutcomeReview[]>(`/vr/investigations/${id}/outcomes/${outcomeId}/reviews`),
    enabled: Boolean(id && outcomeId),
  });
}

export interface OutcomeReviewRequest {
  outcomeId: string;
  reviewer_branch_id: string;
  vote: string;
  comment: string;
}

export function useCreateVrOutcomeReview(id: string | null) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ outcomeId, ...body }: OutcomeReviewRequest) =>
      apiFetch<OutcomeReview>(`/vr/investigations/${id}/outcomes/${outcomeId}/reviews`, {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: (_review, { outcomeId }) => {
      void queryClient.invalidateQueries({ queryKey: ["vr", "outcomes", id] });
      void queryClient.invalidateQueries({ queryKey: ["vr", "outcome-reviews", id, outcomeId] });
      void queryClient.invalidateQueries({ queryKey: ["vr", "investigation", id] });
    },
  });
}

/** One finding; `poll` re-fetches every 5s while a drafted PoC is pending. */
export function useVrFinding(findingId: string | null, poll: boolean) {
  return useQuery({
    queryKey: ["vr", "finding", findingId],
    queryFn: () => apiFetch<VrFinding>(`/vr/findings/${findingId}`),
    enabled: Boolean(findingId),
    refetchInterval: poll ? 5000 : false,
  });
}

export interface DraftPocQueued {
  finding_id: string;
  task_id: string;
  status: string;
}

/** Queue an LLM PoC draft; the result lands on the finding's `poc` later. */
export function useDraftPoc() {
  return useMutation({
    mutationFn: (findingId: string) =>
      apiFetch<DraftPocQueued>(`/vr/findings/${findingId}/draft-poc`, { method: "POST" }),
  });
}

export interface LedgerDecisionRequest {
  requestId: number;
  approver_branch_id: string;
  approve: boolean;
  reason: string;
}

export interface LedgerDecisionResult {
  decision_id: number;
  request_id: number;
  approved: boolean;
  ratified: boolean;
}

export function useLedgerDecision(id: string | null) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ requestId, ...body }: LedgerDecisionRequest) =>
      apiFetch<LedgerDecisionResult>(`/vr/investigations/${id}/ledger/requests/${requestId}/decision`, {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["vr", "ledger", id] });
      void queryClient.invalidateQueries({ queryKey: ["vr", "dispatch", id] });
    },
  });
}
