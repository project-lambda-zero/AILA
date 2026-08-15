import { useNavigate, useSearchParams } from "react-router";

import { WindowPanel } from "@/components/aila/WindowPanel";
import {
  SectionHeader,
  DataGrid,
  MonoBadge,
} from "@/components/aila/mock";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { EmptyState } from "@/components/aila/EmptyState";
import {
  useTaskDetail,
  useTasks,
  type TaskStatus,
  type TaskSummary,
} from "@platform/features/scans/api";
import { useTransitions } from "./useTransitions";
import { TransitionTimeline } from "./TransitionTimeline";
import { ActivityTimeline } from "@platform/features/activity/ActivityTimeline";
import { SavedViews } from "@platform/features/saved-views";
import { usePreferences } from "@/providers/PreferencesProvider";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ALLOWED_STATUSES: readonly TaskStatus[] = [
  "queued",
  "waiting",
  "running",
  "paused",
  "done",
  "failed",
  "cancelled",
];

function formatTimestamp(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "--";
}

function normalizeTaskStatus(value: string | null): TaskStatus | undefined {
  return ALLOWED_STATUSES.includes(value as TaskStatus)
    ? (value as TaskStatus)
    : undefined;
}

function updateSearchParams(
  searchParams: URLSearchParams,
  patches: Record<string, string | null | undefined>,
): URLSearchParams {
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

/** Mono tone for a task status chip. */
function statusTone(status: TaskStatus): string {
  switch (status) {
    case "done":
      return "ok";
    case "running":
      return "info";
    case "failed":
      return "critical";
    case "cancelled":
      return "muted";
    case "paused":
      return "warn";
    case "queued":
    case "waiting":
    default:
      return "muted";
  }
}

// ---------------------------------------------------------------------------
// Shared inline chrome
// ---------------------------------------------------------------------------

const INPUT_STYLE: React.CSSProperties = {
  height: 32,
  fontSize: 12,
  padding: "0 10px",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  outline: "none",
  minWidth: 140,
};

const FIELD_LABEL_STYLE: React.CSSProperties = {
  fontSize: 9.5,
  color: "var(--text-muted)",
  textTransform: "uppercase",
  letterSpacing: "0.12em",
};

// ---------------------------------------------------------------------------
// Task detail panel
// ---------------------------------------------------------------------------

function TaskDetailPanel({ taskId }: { taskId: string }) {
  const taskDetailQuery = useTaskDetail(taskId);
  const transitionsQuery = useTransitions(taskId);

  if (!taskId) {
    return (
      <WindowPanel title="task detail" tone="muted">
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--text-muted)" }}
        >
          select a task row to inspect its lifecycle details.
        </p>
      </WindowPanel>
    );
  }

  if (taskDetailQuery.isLoading) {
    return (
      <WindowPanel title="task detail" status="LOADING" tone="muted">
        <LoadingSkeletonGroup lines={6} />
      </WindowPanel>
    );
  }

  if (taskDetailQuery.isError) {
    return (
      <WindowPanel title="task detail" tone="warn">
        <div
          className="font-mono"
          style={{
            border:
              "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
            background:
              "color-mix(in srgb, var(--status-warn) 10%, transparent)",
            color: "var(--status-warn)",
            padding: "8px 12px",
            fontSize: 11,
            borderRadius: 3,
          }}
        >
          {(taskDetailQuery.error as Error).message}
        </div>
      </WindowPanel>
    );
  }

  const task = taskDetailQuery.data;
  if (!task) return null;

  const rows: { label: string; value: React.ReactNode }[] = [
    {
      label: "status",
      value: <MonoBadge tone={statusTone(task.status)}>{task.status}</MonoBadge>,
    },
    { label: "track", value: task.track },
    { label: "module", value: task.fn_module },
    { label: "function", value: task.fn_path },
    { label: "created", value: formatTimestamp(task.created_at) },
    { label: "started", value: formatTimestamp(task.started_at) },
    { label: "completed", value: formatTimestamp(task.completed_at) },
    { label: "heartbeat", value: formatTimestamp(task.heartbeat_at) },
    {
      label: "checkpoint",
      value: task.has_checkpoint ? "available" : "none",
    },
  ];

  return (
    <div className="flex flex-col" style={{ gap: 12 }}>
      <WindowPanel title="task detail">
        <div className="flex flex-col">
          {rows.map(({ label, value }) => (
            <div
              key={label}
              className="flex items-start justify-between"
              style={{
                gap: 10,
                padding: "6px 0",
                borderBottom: "1px solid var(--border-faint)",
              }}
            >
              <span
                className="font-mono shrink-0"
                style={{
                  fontSize: 10,
                  color: "var(--text-muted)",
                  textTransform: "uppercase",
                  letterSpacing: "0.12em",
                }}
              >
                {label}
              </span>
              <span
                className="font-mono text-right"
                style={{
                  fontSize: 11,
                  color: "var(--text-primary)",
                  wordBreak: "break-all",
                }}
              >
                {value}
              </span>
            </div>
          ))}
          {task.error && (
            <div
              className="font-mono"
              style={{
                marginTop: 8,
                border:
                  "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
                background:
                  "color-mix(in srgb, var(--status-warn) 10%, transparent)",
                color: "var(--status-warn)",
                padding: "8px 12px",
                fontSize: 11,
                borderRadius: 3,
              }}
            >
              {task.error}
            </div>
          )}
        </div>
      </WindowPanel>

      <TransitionTimeline
        rows={transitionsQuery.data ?? []}
        isLoading={transitionsQuery.isLoading}
        isError={transitionsQuery.isError}
      />

      <WindowPanel title="activity" flush>
        <div style={{ padding: 10 }}>
          <ActivityTimeline
            runId={taskId}
            label="Task"
            live={
              task.status === "running" ||
              task.status === "queued" ||
              task.status === "waiting"
            }
          />
        </div>
      </WindowPanel>
    </div>
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
  const { defaultPageSize, setDefaultPageSize, allowedPageSizes } =
    usePreferences();

  const tasksQuery = useTasks(trackFilter || undefined, statusFilter);
  const tasks = tasksQuery.data?.tasks ?? [];

  const savedViews = (
    <SavedViews<{
      track: string;
      status: TaskStatus | "";
      pageSize: number;
    }>
      entityType="task"
      entityLabel="Task queue"
      currentState={{
        track: trackFilter,
        status: statusFilter ?? "",
        pageSize: defaultPageSize,
      }}
      onApply={(state) => {
        setSearchParams(
          updateSearchParams(searchParams, {
            track: state.track || null,
            status: state.status || null,
          }),
        );
        if (
          typeof state.pageSize === "number" &&
          allowedPageSizes.includes(state.pageSize) &&
          state.pageSize !== defaultPageSize
        ) {
          setDefaultPageSize(state.pageSize);
        }
      }}
    />
  );

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <SectionHeader
        icon={"\u25a0"}
        title="task queue"
        actions={
          <div className="flex items-center" style={{ gap: 10 }}>
            <div className="flex flex-col" style={{ gap: 3 }}>
              <label htmlFor="task-track" style={FIELD_LABEL_STYLE}>
                track
              </label>
              <input
                id="task-track"
                type="text"
                value={trackFilter}
                onChange={(e) =>
                  setSearchParams(
                    updateSearchParams(searchParams, { track: e.target.value }),
                  )
                }
                placeholder="vulnerability"
                className="font-mono"
                style={INPUT_STYLE}
              />
            </div>
            <div className="flex flex-col" style={{ gap: 3 }}>
              <label htmlFor="task-status" style={FIELD_LABEL_STYLE}>
                status
              </label>
              <select
                id="task-status"
                value={statusFilter ?? ""}
                onChange={(e) =>
                  setSearchParams(
                    updateSearchParams(searchParams, {
                      status: e.target.value || null,
                    }),
                  )
                }
                className="font-mono"
                style={{ ...INPUT_STYLE, minWidth: 120 }}
              >
                <option value="">all</option>
                {ALLOWED_STATUSES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </div>
            <div style={{ alignSelf: "flex-end" }}>{savedViews}</div>
          </div>
        }
      />

      {tasksQuery.isError && (
        <div
          className="font-mono"
          style={{
            border:
              "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
            background:
              "color-mix(in srgb, var(--status-warn) 10%, transparent)",
            color: "var(--status-warn)",
            padding: "10px 14px",
            fontSize: 12,
            borderRadius: 3,
          }}
        >
          {(tasksQuery.error as Error).message}
        </div>
      )}

      {tasksQuery.isLoading ? (
        <WindowPanel title="task queue" status="LOADING" tone="muted">
          <LoadingSkeletonGroup lines={6} />
        </WindowPanel>
      ) : (
        <div
          className="grid"
          style={{
            gridTemplateColumns: "minmax(0, 1fr) 380px",
            gap: 16,
            alignItems: "start",
          }}
        >
          <div style={{ minWidth: 0 }}>
            {tasks.length === 0 ? (
              <EmptyState
                title="No tasks"
                description="Tasks appear here when scans are running. Submit a scan to get started."
                action={{ label: "Go to Console", href: "/console" }}
              />
            ) : (
              <WindowPanel
                title="task queue"
                status={`${tasks.length} TASK${tasks.length === 1 ? "" : "S"}`}
                tone="muted"
                flush
              >
                <DataGrid<TaskSummary>
                  columns={[
                    { label: "TASK ID", width: "180px" },
                    { label: "TRACK", width: "140px" },
                    { label: "STATUS", width: "110px" },
                    { label: "MODULE", width: "minmax(120px, 1fr)" },
                    { label: "CREATED", width: "180px", align: "right" },
                  ]}
                  rows={tasks}
                  getKey={(t) => t.task_id}
                  onRowClick={(t) => {
                    // D-04 + D-14: navigate to /tasks/:taskId detail route.
                    // The detail route currently reuses TasksPage; the
                    // ?task= param keeps the side-panel selection in sync.
                    navigate(`/tasks/${encodeURIComponent(t.task_id)}`);
                    setSearchParams(
                      updateSearchParams(searchParams, { task: t.task_id }),
                    );
                  }}
                  renderCells={(t) => [
                    <span
                      data-testid="task-row"
                      data-task-id={t.task_id}
                      className="truncate"
                      style={{ color: "var(--accent)", fontSize: 11 }}
                    >
                      {t.task_id.slice(0, 8)}
                      {"\u2026"}
                    </span>,
                    <span
                      style={{ color: "var(--text-primary)", fontSize: 11 }}
                    >
                      {t.track}
                    </span>,
                    <MonoBadge tone={statusTone(t.status)}>
                      {t.status}
                    </MonoBadge>,
                    <span
                      className="truncate"
                      style={{ color: "var(--text-muted)", fontSize: 11 }}
                    >
                      {t.fn_module}
                    </span>,
                    <span
                      className="tabular-nums"
                      style={{ color: "var(--text-muted)", fontSize: 10 }}
                    >
                      {formatTimestamp(t.created_at)}
                    </span>,
                  ]}
                />
              </WindowPanel>
            )}
          </div>

          <div style={{ width: 380 }}>
            <TaskDetailPanel taskId={selectedTaskId} />
          </div>
        </div>
      )}
    </div>
  );
}
