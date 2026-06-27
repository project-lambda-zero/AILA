import { useNavigate, useSearchParams } from "react-router";
import { ClipboardText } from "@phosphor-icons/react/dist/csr/ClipboardText";

import { AilaCard } from "@/components/aila/AilaCard";
import { AilaBadge, type TaskStatus as BadgeTaskStatus } from "@/components/aila/AilaBadge";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { EmptyState } from "@/components/aila/EmptyState";
import { useTaskDetail, useTasks, type TaskStatus, type TaskSummary } from "@platform/features/scans/api";
import { useTransitions } from "./useTransitions";
import { TransitionTimeline } from "./TransitionTimeline";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatTimestamp(value: string | null) {
  return value ? new Date(value).toLocaleString() : "--";
}

function normalizeTaskStatus(value: string | null): TaskStatus | undefined {
  const allowed: TaskStatus[] = [
    "queued", "waiting", "running", "paused", "done", "failed", "cancelled",
  ];
  return allowed.includes(value as TaskStatus) ? (value as TaskStatus) : undefined;
}

function updateSearchParams(
  searchParams: URLSearchParams,
  patches: Record<string, string | null | undefined>,
) {
  const next = new URLSearchParams(searchParams);
  for (const [key, value] of Object.entries(patches)) {
    if (value === null || value === undefined || value === "") {
      next.delete(key);
    } else {
      next.set(key, value);
    }
  }
  return next;
}

type BadgeSeverity = "neutral" | "info" | "medium" | "critical" | "low";

function statusSeverity(status: TaskStatus): BadgeSeverity {
  switch (status) {
    case "done": return "low";
    case "running": return "info";
    case "failed": return "critical";
    case "cancelled": return "neutral";
    case "paused": return "medium";
    default: return "neutral";
  }
}

/**
 * Map internal TaskStatus (from backend) to the AilaBadge status namespace
 * (D-05 / D-21 / D-22). Returns undefined for statuses we don't have a
 * dedicated colour for yet (e.g. "cancelled") so callers fall back to the
 * severity-based rendering.
 */
function statusToken(status: TaskStatus): BadgeTaskStatus | undefined {
  switch (status) {
    case "done": return "completed";
    case "running": return "running";
    case "failed": return "failed";
    case "queued": return "queued";
    case "waiting": return "waiting";
    case "paused": return "paused";
    default: return undefined;
  }
}

// ---------------------------------------------------------------------------
// Task detail panel
// ---------------------------------------------------------------------------

function TaskDetailPanel({ taskId }: { taskId: string }) {
  const taskDetailQuery = useTaskDetail(taskId);
  const transitionsQuery = useTransitions(taskId);

  if (!taskId) {
    return (
      <AilaCard variant="default" padding="md" techBorder glow><p className="font-mono text-xs text-text-muted">
        Select a task row to inspect its lifecycle details.
      </p></AilaCard>
    );
  }

  if (taskDetailQuery.isLoading) {
    return (
      <AilaCard variant="default" padding="md" techBorder glow><LoadingSkeletonGroup lines={6} /></AilaCard>
    );
  }

  if (taskDetailQuery.isError) {
    return (
      <AilaCard variant="default" padding="md" techBorder glow><div className="rounded-[2px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
        {(taskDetailQuery.error as Error).message}
      </div></AilaCard>
    );
  }

  const task = taskDetailQuery.data;
  if (!task) return null;

  return (
    <AilaCard variant="elevated" padding="md" techBorder glow><h2 className="font-mono text-xs font-semibold uppercase tracking-wider text-text-muted mb-3">
      Task Detail
    </h2>
    <div className="flex flex-col gap-2">
      {[
        { label: "Status", value: <AilaBadge severity={statusSeverity(task.status)} size="sm">{task.status}</AilaBadge> },
        { label: "Track", value: task.track },
        { label: "Module", value: task.fn_module },
        { label: "Function", value: task.fn_path },
        { label: "Created", value: formatTimestamp(task.created_at) },
        { label: "Started", value: formatTimestamp(task.started_at) },
        { label: "Completed", value: formatTimestamp(task.completed_at) },
        { label: "Heartbeat", value: formatTimestamp(task.heartbeat_at) },
        { label: "Checkpoint", value: task.has_checkpoint ? "Available" : "None" },
      ].map(({ label, value }) => (
        <div key={label} className="flex items-start justify-between gap-2 border-b border-border pb-1.5 last:border-0">
          <span className="font-mono text-xs text-text-muted shrink-0">{label}</span>
          <span className="font-mono text-xs text-text text-right break-all">{value}</span>
        </div>
      ))}
      {task.error && (
        <div className="rounded-[2px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
          {task.error}
        </div>
      )}
      {task.result_path && (
        <div className="flex flex-col gap-0.5">
          <span className="font-mono text-xs text-text-muted">Result path</span>
          <code className="font-mono text-xs text-text break-all bg-base px-2 py-1 rounded-[2px]">
            {task.result_path}
          </code>
        </div>
      )}
    </div>
    <TransitionTimeline
      rows={transitionsQuery.data ?? []}
      isLoading={transitionsQuery.isLoading}
      isError={transitionsQuery.isError}
    /></AilaCard>
  );
}

// ---------------------------------------------------------------------------
// Task row
// ---------------------------------------------------------------------------

function TaskRow({
  task,
  isSelected,
  onSelect,
}: {
  task: TaskSummary;
  isSelected: boolean;
  onSelect: () => void;
}) {
  const token = statusToken(task.status);
  const activate = (event: React.SyntheticEvent) => {
    // Preserve D-32 escape hatch: inline interactive elements stop propagation.
    // Guard must exclude the row itself (which has role="button"), else every click short-circuits.
    const target = event.target as HTMLElement | null;
    const row = event.currentTarget as HTMLElement;
    if (target) {
      const hit = target.closest(
        'button, a, input, select, textarea, [role="button"], .no-row-click',
      ) as HTMLElement | null;
      if (hit && hit !== row && row.contains(hit)) {
        return;
      }
    }
    onSelect();
  };
  return (
    <tr
      className={`border-b border-border font-mono text-xs transition-colors cursor-pointer hover:bg-elevated focus:outline focus:outline-2 focus:outline-accent ${
        isSelected ? "bg-accent/5" : ""
      }`}
      role="button"
      tabIndex={0}
      data-testid="task-row"
      data-task-id={task.task_id}
      onClick={activate}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          if (event.key === " ") event.preventDefault();
          activate(event);
        }
      }}
    >
      <td className="py-2 px-3 text-text-muted max-w-[120px] truncate">
        {task.task_id.slice(0, 8)}…
      </td>
      <td className="py-2 px-3 text-text">{task.track}</td>
      <td className="py-2 px-3">
        {token ? (
          <AilaBadge status={token} size="sm">
            {task.status}
          </AilaBadge>
        ) : (
          <AilaBadge severity={statusSeverity(task.status)} size="sm">
            {task.status}
          </AilaBadge>
        )}
      </td>
      <td className="py-2 px-3 text-text-muted hidden sm:table-cell">
        {task.fn_module}
      </td>
      <td className="py-2 px-3 text-text-muted hidden lg:table-cell">
        {formatTimestamp(task.created_at)}
      </td>
    </tr>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function TasksPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const trackFilter = searchParams.get("track") ?? "";
  const statusFilter = normalizeTaskStatus(searchParams.get("status"));
  const selectedTaskId = searchParams.get("task") ?? "";

  const tasksQuery = useTasks(trackFilter || undefined, statusFilter);
  const tasks = tasksQuery.data?.tasks ?? [];

  return (
    <div className="flex flex-col gap-4 p-3 sm:p-4 lg:p-6">
      {/* Page header */}

      {/* Filters */}
      <AilaCard variant="default" padding="md" techBorder glow><div className="flex flex-wrap items-center gap-3">
        <div className="flex flex-col gap-1 min-w-[140px]">
          <label className="font-mono text-xs text-text-muted" htmlFor="task-track">Track</label>
          <input
            id="task-track"
            className="touch-target h-8 rounded-[2px] border border-border bg-base px-2.5 font-mono text-xs text-text outline-none focus:border-border-hover transition-colors min-w-[120px]"
            type="text"
            value={trackFilter}
            onChange={(e) =>
              setSearchParams(updateSearchParams(searchParams, { track: e.target.value }))
            }
            placeholder="vulnerability"
          />
        </div>
        <div className="flex flex-col gap-1 min-w-[120px]">
          <label className="font-mono text-xs text-text-muted" htmlFor="task-status">Status</label>
          <select
            id="task-status"
            className="touch-target h-8 rounded-[2px] border border-border bg-base px-2 font-mono text-xs text-text outline-none focus:border-border-hover transition-colors"
            value={statusFilter ?? ""}
            onChange={(e) =>
              setSearchParams(updateSearchParams(searchParams, { status: e.target.value || null }))
            }
          >
            <option value="">all</option>
            <option value="queued">queued</option>
            <option value="waiting">waiting</option>
            <option value="running">running</option>
            <option value="paused">paused</option>
            <option value="done">done</option>
            <option value="failed">failed</option>
            <option value="cancelled">cancelled</option>
          </select>
        </div>
      </div></AilaCard>

      {/* Error */}
      {tasksQuery.isError && (
        <div className="rounded-[2px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-sm text-destructive">
          {(tasksQuery.error as Error).message}
        </div>
      )}

      {/* Loading */}
      {tasksQuery.isLoading && (
        <AilaCard variant="default" padding="md" techBorder glow><LoadingSkeletonGroup lines={6} /></AilaCard>
      )}

      {/* Split layout: table + detail */}
      {!tasksQuery.isLoading && (
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start">
          {/* Task table -- takes remaining width */}
          <div className="flex-1 min-w-0">
            {tasks.length === 0 ? (
              <EmptyState
                icon={<ClipboardText size={40} />}
                title="No tasks"
                description="Tasks appear here when scans are running. Submit a scan to get started."
                action={{ label: "Go to Console", href: "/console" }}
              />
            ) : (
              <AilaCard variant="default" padding="none" techBorder glow><div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-border">
                      <th className="py-2 px-3 text-left font-mono text-xs text-text-muted">Task ID</th>
                      <th className="py-2 px-3 text-left font-mono text-xs text-text-muted">Track</th>
                      <th className="py-2 px-3 text-left font-mono text-xs text-text-muted">Status</th>
                      <th className="py-2 px-3 text-left font-mono text-xs text-text-muted hidden sm:table-cell">Module</th>
                      <th className="py-2 px-3 text-left font-mono text-xs text-text-muted hidden lg:table-cell">Created</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tasks.map((task) => (
                      <TaskRow
                        key={task.task_id}
                        task={task}
                        isSelected={task.task_id === selectedTaskId}
                        onSelect={() => {
                          // D-04 + D-14: navigate to /tasks/:taskId detail route.
                          // The detail route currently reuses TasksPage; the
                          // ?task= param keeps the side-panel selection in sync.
                          navigate(`/tasks/${encodeURIComponent(task.task_id)}`);
                          setSearchParams(
                            updateSearchParams(searchParams, { task: task.task_id }),
                          );
                        }}
                      />
                    ))}
                  </tbody>
                </table>
              </div></AilaCard>
            )}
          </div>

          {/* Detail panel -- fixed width on desktop */}
          <div className="w-full lg:w-80 xl:w-96 shrink-0">
            <TaskDetailPanel taskId={selectedTaskId} />
          </div>
        </div>
      )}
    </div>
  );
}
