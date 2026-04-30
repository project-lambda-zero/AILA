/**
 * Chat data layer (Phase 176c).
 *
 * Wraps the existing /sessions REST endpoints with TanStack Query hooks,
 * plus a specialised POST-SSE "send message" hook that streams assistant
 * tokens via sseStreamPost.
 *
 * The chat endpoints return plain SessionResponse / SessionMessagesResponse
 * shapes (no DataEnvelope). Error envelopes are handled globally by the
 * shared apiErrorHandler attached to the QueryClient.
 */
import { useCallback, useRef, useState } from "react";
import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";

import { authorizedRequestJson } from "@platform/api/http";
import { getAuthTokenStandalone } from "@platform/auth/useAuthStore";
import { sseStreamPost } from "@/lib/sseClient";

// ---------------------------------------------------------------------------
// Shared types -- mirror the backend Pydantic schemas.
// ---------------------------------------------------------------------------

export interface SessionSummary {
  session_id: string;
  user_id: string;
  title: string;
  created_at: string;
  last_message_at: string | null;
  last_message_preview: string | null;
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

export type ChatRole = "user" | "assistant";

export interface ChatMessage {
  message_id: string;
  role: ChatRole;
  content: string;
  run_id: string | null;
  created_at: string;
}

export interface ChatMessagesResponse {
  total: number;
  page: number;
  page_size: number;
  pages: number;
  items: ChatMessage[];
}

export const chatQueryKeys = {
  all: ["platform", "chat"] as const,
  sessions: () => [...chatQueryKeys.all, "sessions"] as const,
  messages: (sessionId: string) =>
    [...chatQueryKeys.all, "messages", sessionId] as const,
};

// ---------------------------------------------------------------------------
// Read hooks
// ---------------------------------------------------------------------------

export function useSessions() {
  return useQuery({
    queryKey: chatQueryKeys.sessions(),
    queryFn: () => authorizedRequestJson<SessionListResponse>("/sessions"),
  });
}

export function useSessionMessages(sessionId: string) {
  return useQuery({
    queryKey: chatQueryKeys.messages(sessionId),
    enabled: sessionId.trim().length > 0,
    queryFn: () =>
      authorizedRequestJson<ChatMessagesResponse>(
        `/sessions/${encodeURIComponent(sessionId)}/messages`,
      ),
  });
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

export function useCreateSession() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (title?: string) =>
      authorizedRequestJson<SessionResponse>("/sessions", {
        method: "POST",
        body: { title: title?.trim() || "New chat" },
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: chatQueryKeys.sessions(),
      });
    },
  });
}

// ---------------------------------------------------------------------------
// Streaming send-message hook
// ---------------------------------------------------------------------------

export interface StreamingAssistantState {
  /** True while the SSE stream is open. */
  isStreaming: boolean;
  /** Tokens received so far for the in-flight assistant message. */
  buffer: string;
  /** run_id emitted by the backend on the final `{type:"done"}` event, if any. */
  runId: string | null;
  /** Non-null if the stream ended with an error. */
  error: Error | null;
}

const INITIAL_STREAM_STATE: StreamingAssistantState = {
  isStreaming: false,
  buffer: "",
  runId: null,
  error: null,
};

/**
 * Open an SSE stream for POST /sessions/{id}/messages and accumulate tokens.
 *
 * Returned object includes:
 *   - state: StreamingAssistantState (reactive)
 *   - send:  (content: string) => Promise<void>
 *   - abort: () => void        cancel the in-flight stream
 *   - reset: () => void        clear the buffer once the caller has consumed it
 */
export function useSendMessage(sessionId: string) {
  const [state, setState] = useState<StreamingAssistantState>(INITIAL_STREAM_STATE);
  const abortRef = useRef<AbortController | null>(null);
  const queryClient = useQueryClient();

  const reset = useCallback(() => {
    setState(INITIAL_STREAM_STATE);
  }, []);

  const abort = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
  }, []);

  const send = useCallback(
    async (content: string) => {
      if (!sessionId.trim() || !content.trim()) {
        return;
      }
      // Cancel any previous in-flight request on this session.
      abortRef.current?.abort();
      const controller = new AbortController();
      abortRef.current = controller;

      setState({ isStreaming: true, buffer: "", runId: null, error: null });

      const token = await getAuthTokenStandalone();

      await sseStreamPost(
        `/sessions/${encodeURIComponent(sessionId)}/messages`,
        {
          token,
          body: { content },
          signal: controller.signal,
          onToken: (tok) => {
            setState((prev) =>
              prev.isStreaming
                ? { ...prev, buffer: prev.buffer + tok }
                : prev,
            );
          },
          onDone: (payload) => {
            setState((prev) => ({
              ...prev,
              isStreaming: false,
              runId: payload.run_id ?? null,
            }));
          },
          onError: (err) => {
            setState((prev) => ({
              ...prev,
              isStreaming: false,
              error:
                err instanceof Error
                  ? err
                  : new Error(typeof err === "string" ? err : "Stream failed"),
            }));
          },
        },
      );

      // Either the server emitted `done` or the stream ended without one --
      // ensure isStreaming is cleared either way and invalidate caches so
      // useSessionMessages refetches the persisted assistant message.
      setState((prev) => ({ ...prev, isStreaming: false }));
      if (abortRef.current === controller) {
        abortRef.current = null;
      }
      void queryClient.invalidateQueries({
        queryKey: chatQueryKeys.messages(sessionId),
      });
      void queryClient.invalidateQueries({
        queryKey: chatQueryKeys.sessions(),
      });
    },
    [queryClient, sessionId],
  );

  return { state, send, abort, reset };
}
