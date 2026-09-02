import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "./client";

/** Dante proposal shape (frozen contract). A dante assistant turn carries
 *  `actions: DanteAction[]` (empty when the reply is pure conversation). The
 *  backend validates every action; only well-formed actions arrive here. */
export interface DanteAction {
  kind: "open_wizard" | "enqueue_scan" | "create_tag" | "delete_tag" | "steer_investigation";
  label: string;
  summary?: string;
  // open_wizard / steer_investigation
  module_id?: string;
  target_id?: string | null;
  investigation_id?: string | null;
  steering_text?: string;
  // enqueue_scan
  query?: string;
  system_ids?: string[];
  // create_tag / delete_tag
  key?: string;
}

export interface SessionMessage {
  message_id: string;
  role: "user" | "assistant" | "system";
  content: string;
  run_id?: string | null;
  created_at?: string;
  actions?: DanteAction[];
}

export interface SessionSummary {
  session_id: string;
  user_id: string;
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
  user_id: string;
  title: string;
  created_at: string;
}

/** GET /sessions/{id}/messages -- backend returns PaginatedResponse[SessionMessageResponse].
 *  Messages live under `items`, NOT a `messages` key. */
export interface SessionMessagesResponse {
  total: number;
  page: number;
  page_size: number;
  pages: number;
  items: SessionMessage[];
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
  return useMutation<SessionMessage, Error, { content: string; sessionId?: string }>({
    // `sessionId` override lets the caller post to a session that was just
    // created in the same tick, before the hook re-binds to the new id.
    // Backend SessionMessageRequest forbids extra fields, so send only content.
    mutationFn: (body) =>
      apiFetch<SessionMessage>(`/sessions/${body.sessionId ?? sessionId}/messages`, {
        method: "POST",
        body: JSON.stringify({ content: body.content }),
      }),
    onSuccess: (_data, vars) => {
      const sid = vars.sessionId ?? sessionId;
      qc.invalidateQueries({ queryKey: ["sessions", sid, "messages"] });
      qc.invalidateQueries({ queryKey: ["sessions"] });
    },
  });
}
