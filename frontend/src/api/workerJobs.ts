/** Generic worker-task completion, JSON-result, and binary-artifact helpers. */

import { ApiError, apiFetch, authorizedFetch } from "./client";

export interface TaskActionResponse {
  task_id: string;
  status: string;
}

interface TaskStatusView {
  status: string;
  error: string | null;
}

const POLL_INTERVAL_MS = 2000;
const FAILED_STATES: Record<string, true> = { failed: true, cancelled: true, dead_letter: true };

function taskPath(taskId: string): string {
  return `/tasks/${encodeURIComponent(taskId)}`;
}

/** Poll immediately and then every two seconds until the worker succeeds or
 * reaches a terminal failure state. */
export async function waitForWorkerTask(taskId: string): Promise<void> {
  for (;;) {
    const task = await apiFetch<TaskStatusView>(taskPath(taskId));
    if (task.status === "done") return;
    if (FAILED_STATES[task.status] === true) {
      const detail = task.error?.trim();
      throw new Error(`worker task ${taskId} ${task.status}${detail ? `: ${detail}` : ""}`);
    }
    await new Promise<void>((resolve) => {
      setTimeout(resolve, POLL_INTERVAL_MS);
    });
  }
}

/** Wait for a worker task and return its DataEnvelope-unwrapped JSON result. */
export async function fetchWorkerResult<T>(taskId: string): Promise<T> {
  await waitForWorkerTask(taskId);
  return apiFetch<T>(`${taskPath(taskId)}/result`);
}

function safeFilename(filename: string): string {
  const basename = filename.split(/[\\/]/).pop() ?? "";
  const cleaned = basename.replace(/[\u0000-\u001f\u007f<>:"|?*]/g, "_").trim();
  return cleaned === "" || cleaned === "." || cleaned === ".." ? "worker-artifact" : cleaned;
}

/** Wait for a worker task and save its streamed artifact under a local basename. */
export async function downloadWorkerArtifact(taskId: string, filename: string): Promise<void> {
  await waitForWorkerTask(taskId);
  const res = await authorizedFetch(`${taskPath(taskId)}/artifact`);
  if (res.status === 401) {
    throw new ApiError(401, "Session expired -- sign in again.");
  }
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new ApiError(res.status, detail || res.statusText);
  }

  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  try {
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = safeFilename(filename);
    anchor.click();
  } finally {
    URL.revokeObjectURL(url);
  }
}
