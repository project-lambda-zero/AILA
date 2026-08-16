import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "./client";
import type { Branch, DispatchState, Hypothesis, Investigation, LedgerRow, McpCall, Message } from "./types";

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
    queryFn: () => apiFetch<Investigation>(`/vr/investigations/${id}`),
    enabled: Boolean(id),
  });
}

export function useMessages(id: string | null) {
  return useQuery({
    queryKey: ["vr", "messages", id],
    queryFn: () => apiFetch<Message[]>(`/vr/investigations/${id}/messages?limit=1000`),
    enabled: Boolean(id),
    refetchInterval: 8000,
  });
}

export function useBranches(id: string | null) {
  return useQuery({
    queryKey: ["vr", "branches", id],
    queryFn: () => apiFetch<Branch[]>(`/vr/investigations/${id}/branches`),
    enabled: Boolean(id),
  });
}

export function useHypotheses(id: string | null) {
  return useQuery({
    queryKey: ["vr", "hypotheses", id],
    queryFn: () => apiFetch<Hypothesis[]>(`/vr/investigations/${id}/hypotheses`),
    enabled: Boolean(id),
  });
}

export function useDispatch(id: string | null) {
  return useQuery({
    queryKey: ["vr", "dispatch", id],
    queryFn: () => apiFetch<DispatchState>(`/vr/investigations/${id}/dispatch`),
    enabled: Boolean(id),
    retry: false,
    refetchInterval: 8000,
  });
}

export function useLedger(id: string | null) {
  return useQuery({
    queryKey: ["vr", "ledger", id],
    queryFn: () => apiFetch<LedgerRow[]>(`/vr/investigations/${id}/ledger`),
    enabled: Boolean(id),
    retry: false,
    refetchInterval: 8000,
  });
}

export function useMcpCalls(id: string | null) {
  return useQuery({
    queryKey: ["vr", "mcp-calls", id],
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

