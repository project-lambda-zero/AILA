import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "./client";

export interface SessionMessage {
  message_id: string;
  role: "user" | "assistant" | "system";
  content: string;
  run_id?: string | null;
  created_at?: string;
}

export interface SessionSummary {
  session_id: string;
  user_id: number;
  title: string;
  created_at: string;
  last_message_at?: string | null;
  last_message_preview?: string | null;
  message_count: number;
}

export interface SessionListResponse {
  total: number;
  items: SessionSummary[];
}

export interface SessionResponse {
  session_id: string;
  user_id: number;
  title: string;
  created_at: string;
}

export interface SessionMessagesResponse {
  session_id: string;
  messages: SessionMessage[];
}

export function useSessions() {
  return useQuery<SessionListResponse>({
    queryKey: ["sessions"],
    queryFn: () => apiFetch<SessionListResponse>("/sessions?page=1&page_size=50"),
    staleTime: 10_000,
  });
}

export function useSessionMessages(sessionId: string | null) {
  return useQuery<SessionMessagesResponse>({
    queryKey: ["sessions", sessionId, "messages"],
    queryFn: () => apiFetch<SessionMessagesResponse>(`/sessions/${sessionId}/messages`),
    enabled: Boolean(sessionId),
    staleTime: 5_000,
    refetchInterval: 10_000,
  });
}

export function useCreateSession() {
  const qc = useQueryClient();
  return useMutation<SessionResponse, Error, { title?: string }>({
    mutationFn: (body) =>
      apiFetch<SessionResponse>("/sessions", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["sessions"] });
    },
  });
}

export function usePostSessionMessage(sessionId: string | null) {
  const qc = useQueryClient();
  return useMutation<SessionMessage, Error, { content: string }>({
    mutationFn: (body) =>
      apiFetch<SessionMessage>(`/sessions/${sessionId}/messages`, {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["sessions", sessionId, "messages"] });
      qc.invalidateQueries({ queryKey: ["sessions"] });
    },
  });
}
