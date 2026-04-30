import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { ApiHttpError, authorizedRequestJson } from "@platform/api/http";
import { getAuthTokenStandalone } from "@platform/auth/useAuthStore";
import { streamJsonEvents } from "@platform/api/sse";

export type TaskStatus =
  | "queued"
  | "waiting"
  | "running"
  | "paused"
  | "done"
  | "failed"
  | "cancelled";

export interface TaskSummary {
  task_id: string;
  track: string;
  status: TaskStatus;
  user_id: string;
  group_id: string;
  fn_path: string;
  fn_module: string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  heartbeat_at: string | null;
  error: string | null;
  result_path: string | null;
  has_checkpoint: boolean;
}

export interface TaskListResponse {
  tasks: TaskSummary[];
  total: number;
}

export interface ScanSubmissionRequest {
  query_text: string;
  targets: string[];
}

export interface ScanSubmitResponse {
  run_id: string;
  status: "submitted";
}

export interface ScanStatusResponse {
  run_id: string;
  status: TaskStatus;
  track: string | null;
  started_at: string | null;
  completed_at: string | null;
  result_path: string | null;
}

export interface ScanEvent {
  stage?: string | null;
  message?: string | null;
  percent?: number | null;
  timestamp?: string | null;
}

function buildSearchPath(pathname: string, params: Record<string, string | number | undefined>) {
  const searchParams = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === "") {
      continue;
    }
    searchParams.set(key, String(value));
  }
  const search = searchParams.toString();
  return search ? `${pathname}?${search}` : pathname;
}

function isTerminalStatus(status: TaskStatus | undefined) {
  return status === "done" || status === "failed" || status === "cancelled";
}

export function useTasks(track?: string, status?: TaskStatus) {
  return useQuery({
    queryKey: ["platform", "tasks", track ?? "", status ?? ""],
    queryFn: () =>
      authorizedRequestJson<TaskListResponse>(
        buildSearchPath("/tasks", {
          track,
          status,
        }),
      ),
  });
}

export function useTaskDetail(taskId: string) {
  return useQuery({
    queryKey: ["platform", "task-detail", taskId],
    enabled: taskId.trim().length > 0,
    queryFn: () => authorizedRequestJson<TaskSummary>(`/tasks/${encodeURIComponent(taskId)}`),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status && !isTerminalStatus(status) ? 5000 : false;
    },
  });
}

export function useScanStatus(runId: string) {
  return useQuery({
    queryKey: ["platform", "scan-status", runId],
    enabled: runId.trim().length > 0,
    queryFn: () => authorizedRequestJson<ScanStatusResponse>(`/scans/${encodeURIComponent(runId)}`),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status && !isTerminalStatus(status) ? 5000 : false;
    },
  });
}

export function useSubmitScan() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (payload: ScanSubmissionRequest) =>
      authorizedRequestJson<ScanSubmitResponse>("/analyze", {
        method: "POST",
        body: payload,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "tasks"] });
    },
  });
}

export function useCancelTask(taskId: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: () =>
      authorizedRequestJson<{ task_id: string; status: TaskStatus }>(
        `/tasks/${encodeURIComponent(taskId)}/cancel`,
        {
          method: "POST",
        },
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "tasks"] });
      void queryClient.invalidateQueries({ queryKey: ["platform", "task-detail", taskId] });
      void queryClient.invalidateQueries({ queryKey: ["platform", "scan-status", taskId] });
    },
  });
}

export function useResumeTask(taskId: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: () =>
      authorizedRequestJson<{ task_id: string; status: TaskStatus }>(
        `/tasks/${encodeURIComponent(taskId)}/resume`,
        {
          method: "POST",
        },
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "tasks"] });
      void queryClient.invalidateQueries({ queryKey: ["platform", "task-detail", taskId] });
      void queryClient.invalidateQueries({ queryKey: ["platform", "scan-status", taskId] });
    },
  });
}

export function useScanEventFeed(runId: string) {
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [status, setStatus] = useState<"idle" | "connecting" | "live" | "unavailable" | "closed" | "error">("idle");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!runId.trim()) {
      setEvents([]);
      setStatus("idle");
      setError(null);
      return;
    }

    const controller = new AbortController();
    let closedByAbort = false;
    setEvents([]);
    setStatus("connecting");
    setError(null);

    void getAuthTokenStandalone()
      .then((token) =>
        streamJsonEvents<ScanEvent>(`/scans/${encodeURIComponent(runId)}/events`, {
          token,
          signal: controller.signal,
          onEvent: (event) => {
            const message = event.data?.message ?? "";
            if (message === "Redis not configured - no progress stream available") {
              setStatus("unavailable");
            } else {
              setStatus("live");
            }
            setEvents((current) => [...current, event.data]);
          },
        }),
      )
      .then(() => {
        if (!closedByAbort) {
          setStatus((current) => (current === "idle" ? current : "closed"));
        }
      })
      .catch((streamError: unknown) => {
        if (closedByAbort || controller.signal.aborted) {
          return;
        }
        const message =
          streamError instanceof ApiHttpError || streamError instanceof Error
            ? streamError.message
            : "Scan event streaming failed.";
        setStatus("error");
        setError(message);
      });

    return () => {
      closedByAbort = true;
      controller.abort();
    };
  }, [runId]);

  return { events, status, error };
}
