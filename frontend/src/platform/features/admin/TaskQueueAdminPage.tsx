/**
 * TaskQueueAdminPage -- admin controls for the platform task queue.
 *
 * Endpoints:
 *   GET  /tasks/queue-depth                    -- task counts by status
 *   POST /tasks/drain                          -- pause new submissions
 *   POST /tasks/requeue-failed                 -- requeue recent failures
 *   GET  /admin/tasks/dead-letter              -- list dead-lettered tasks
 *   POST /admin/tasks/dead-letter/{id}/requeue -- manual dead-letter recovery
 *   POST /admin/reconcile                      -- heal drift for a task
 */
import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import {
  SectionHeader,
  DataGrid,
  MonoBadge,
  BigStat,
  StatBar,
  toneColor,
} from "@/components/aila/mock";
import { authorizedRequestJson } from "@platform/api/http";
import {
  useReconcileTask,
  type ReconcileReport,
} from "./platformInfraQueries";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface DataEnvelope<T> {
  data: T;
  meta?: Record<string, unknown>;
}

type QueueDepth = Record<string, number>;

interface DrainQueueResponse {
  pending: number;
  draining: boolean;
}

interface RequeueFailedResponse {
  requeued: number;
}

interface DeadLetterEntry {
  task_id: string;
  track: string;
  fn_path: string;
  fn_module: string;
  user_id: string;
  error: string;
  attempts: number;
  exception_class: string;
  dead_lettered_at: string;
}

type Tone = "critical" | "high" | "medium" | "low" | "ok" | "info" | "warn" | "muted";

function statusTone(status: string): Tone {
  const s = status.toLowerCase();
  if (s === "running") return "info";
  if (s === "failed" || s === "dead_letter") return "critical";
  if (s === "paused") return "warn";
  if (s === "done") return "ok";
  if (s === "queued" || s === "waiting") return "medium";
  return "muted";
}

function statusColor(status: string): string {
  return toneColor(statusTone(status));
}

// ---------------------------------------------------------------------------
// Mock chrome primitives
// ---------------------------------------------------------------------------

const BTN_STYLE: React.CSSProperties = {
  height: 26,
  fontSize: 9.5,
  padding: "0 11px",
  letterSpacing: "0.08em",
  borderRadius: 3,
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  cursor: "pointer",
  fontFamily: "var(--font-mono)",
  textTransform: "uppercase",
};

const BTN_ACCENT_STYLE: React.CSSProperties = {
  ...BTN_STYLE,
  border: "1px solid var(--accent)",
  background: "color-mix(in srgb, var(--accent) 14%, transparent)",
  color: "var(--accent)",
};

const BTN_DANGER_STYLE: React.CSSProperties = {
  ...BTN_STYLE,
  border: "1px solid color-mix(in srgb, var(--status-warn) 55%, transparent)",
  background: "color-mix(in srgb, var(--status-warn) 12%, transparent)",
  color: "var(--status-warn)",
};

const INPUT_STYLE: React.CSSProperties = {
  height: 28,
  fontSize: 11,
  padding: "0 10px",
  borderRadius: 3,
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  outline: "none",
  fontFamily: "var(--font-mono)",
  width: "100%",
};

function ErrorBox({ children }: { children: React.ReactNode }) {
  return (
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
      {children}
    </div>
  );
}

function SuccessBox({ children }: { children: React.ReactNode }) {
  return (
    <div
      className="font-mono"
      style={{
        border:
          "1px solid color-mix(in srgb, var(--status-ok) 40%, transparent)",
        background:
          "color-mix(in srgb, var(--status-ok) 10%, transparent)",
        color: "var(--status-ok)",
        padding: "8px 12px",
        fontSize: 11,
        borderRadius: 3,
      }}
    >
      {children}
    </div>
  );
}

/**
 * Modal shell: fixed backdrop + centered WindowPanel. Escapes and backdrop
 * clicks close via `onClose`. Rebuilt in-file to keep the shadcn dialog
 * primitives out of the tree.
 */
function ModalShell({
  open,
  title,
  onClose,
  width = 460,
  tone = "accent",
  children,
}: {
  open: boolean;
  title: React.ReactNode;
  onClose: () => void;
  width?: number;
  tone?: "accent" | "ok" | "info" | "warn" | "muted";
  children: React.ReactNode;
}) {
  useEffect(() => {
    if (!open) return;
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div
      role="dialog"
      aria-modal="true"
      onClick={onClose}
      style={{
        position: "fixed",
        inset: 0,
        background: "color-mix(in srgb, var(--surface-page) 78%, transparent)",
        backdropFilter: "blur(2px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 20,
        zIndex: 60,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{ width, maxWidth: "100%" }}
      >
        <WindowPanel
          title={title}
          tone={tone}
          actions={
            <button
              type="button"
              aria-label="Close"
              onClick={onClose}
              className="font-mono"
              style={{
                width: 22,
                height: 22,
                border: "1px solid var(--border-soft)",
                background: "var(--surface-sunk)",
                color: "var(--text-primary)",
                fontSize: 10,
                cursor: "pointer",
                borderRadius: 2,
              }}
            >
              {"\u2715"}
            </button>
          }
        >
          {children}
        </WindowPanel>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Drain confirmation dialog
// ---------------------------------------------------------------------------

function DrainConfirmDialog({
  open,
  isPending,
  onConfirm,
  onClose,
}: {
  open: boolean;
  isPending: boolean;
  onConfirm: () => Promise<unknown>;
  onClose: () => void;
}) {
  const [error, setError] = useState<string | null>(null);

  async function handleConfirm() {
    setError(null);
    try {
      await onConfirm();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to drain queue");
    }
  }

  function handleClose() {
    setError(null);
    onClose();
  }

  return (
    <ModalShell
      open={open}
      title="drain task queue"
      onClose={handleClose}
      tone="warn"
      width={420}
    >
      <div className="flex flex-col" style={{ gap: 12 }}>
        <div
          className="font-mono"
          style={{
            border:
              "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
            background:
              "color-mix(in srgb, var(--status-warn) 10%, transparent)",
            color: "var(--status-warn)",
            padding: "10px 12px",
            fontSize: 11,
            borderRadius: 3,
          }}
        >
          <p style={{ fontWeight: 600, marginBottom: 4 }}>
            new task submissions will be rejected.
          </p>
          <p style={{ color: "var(--text-muted)" }}>
            in-flight tasks continue to run until completion. use before
            maintenance or restarts. the queue stays drained until the
            platform is restarted.
          </p>
        </div>
        {error && <ErrorBox>{error}</ErrorBox>}
        <div className="flex" style={{ gap: 8 }}>
          <button
            type="button"
            className="font-mono uppercase"
            style={{ ...BTN_ACCENT_STYLE, flex: 1 }}
            onClick={handleConfirm}
            disabled={isPending}
          >
            {isPending ? "DRAINING\u2026" : "CONFIRM DRAIN"}
          </button>
          <button
            type="button"
            className="font-mono uppercase"
            style={BTN_STYLE}
            onClick={handleClose}
          >
            CANCEL
          </button>
        </div>
      </div>
    </ModalShell>
  );
}

// ---------------------------------------------------------------------------
// Requeue-failed dialog
// ---------------------------------------------------------------------------

function RequeueFailedDialog({
  open,
  isPending,
  onConfirm,
  onClose,
}: {
  open: boolean;
  isPending: boolean;
  onConfirm: (maxAgeHours: number) => Promise<RequeueFailedResponse>;
  onClose: () => void;
}) {
  const [maxAgeHours, setMaxAgeHours] = useState("24");
  const [error, setError] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<number | null>(null);

  function handleClose() {
    setError(null);
    setLastResult(null);
    onClose();
  }

  async function handleConfirm() {
    setError(null);
    setLastResult(null);
    const parsed = Number.parseInt(maxAgeHours, 10);
    if (Number.isNaN(parsed) || parsed < 1 || parsed > 168) {
      setError("max_age_hours must be an integer between 1 and 168.");
      return;
    }
    try {
      const result = await onConfirm(parsed);
      setLastResult(result.requeued);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to requeue");
    }
  }

  return (
    <ModalShell
      open={open}
      title="requeue failed tasks"
      onClose={handleClose}
      width={420}
    >
      <div className="flex flex-col" style={{ gap: 12 }}>
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--text-muted)" }}
        >
          requeue tasks that failed within the lookback window. backend caps
          the window at 168 hours (7 days).
        </p>
        <div className="flex flex-col" style={{ gap: 4 }}>
          <label
            className="font-mono uppercase"
            htmlFor="rq-age"
            style={{
              fontSize: 9,
              letterSpacing: "0.1em",
              color: "var(--text-faint)",
            }}
          >
            max age (hours)
          </label>
          <input
            id="rq-age"
            type="number"
            min={1}
            max={168}
            value={maxAgeHours}
            onChange={(e) => setMaxAgeHours(e.target.value)}
            style={INPUT_STYLE}
          />
        </div>
        {lastResult !== null && (
          <SuccessBox>
            requeued {lastResult} task{lastResult === 1 ? "" : "s"}.
          </SuccessBox>
        )}
        {error && <ErrorBox>{error}</ErrorBox>}
        <div className="flex" style={{ gap: 8 }}>
          <button
            type="button"
            className="font-mono uppercase"
            style={{ ...BTN_ACCENT_STYLE, flex: 1 }}
            onClick={handleConfirm}
            disabled={isPending}
          >
            {isPending ? "REQUEUEING\u2026" : "REQUEUE FAILED"}
          </button>
          <button
            type="button"
            className="font-mono uppercase"
            style={BTN_STYLE}
            onClick={handleClose}
          >
            CLOSE
          </button>
        </div>
      </div>
    </ModalShell>
  );
}

// ---------------------------------------------------------------------------
// Reconcile dialog
// ---------------------------------------------------------------------------

function ReconcileDialog({
  open,
  initialTaskId,
  onClose,
}: {
  open: boolean;
  initialTaskId: string;
  onClose: () => void;
}) {
  const [taskId, setTaskId] = useState(initialTaskId);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<ReconcileReport | null>(null);
  const reconcileMutation = useReconcileTask();

  useEffect(() => {
    if (open) {
      setTaskId(initialTaskId);
      setError(null);
      setReport(null);
    }
  }, [open, initialTaskId]);

  function handleClose() {
    setError(null);
    setReport(null);
    onClose();
  }

  async function handleRun() {
    setError(null);
    const trimmed = taskId.trim();
    if (!trimmed) {
      setError("Task id is required.");
      return;
    }
    try {
      const envelope = await reconcileMutation.mutateAsync(trimmed);
      setReport(envelope.data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Reconcile failed");
    }
  }

  const heartbeatLabel = report?.signals.task_heartbeat_at
    ? new Date(report.signals.task_heartbeat_at).toLocaleString()
    : "--";

  return (
    <ModalShell
      open={open}
      title="reconcile task state"
      onClose={handleClose}
      width={540}
    >
      <div className="flex flex-col" style={{ gap: 12 }}>
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--text-muted)" }}
        >
          cross-checks TaskRecord status, workflow cursor, and ARQ lock and
          heals drift. idempotent: a consistent row returns healed=false.
        </p>
        <div className="flex flex-col" style={{ gap: 4 }}>
          <label
            className="font-mono uppercase"
            style={{
              fontSize: 9,
              letterSpacing: "0.1em",
              color: "var(--text-faint)",
            }}
          >
            task id
          </label>
          <input
            value={taskId}
            onChange={(e) => setTaskId(e.target.value)}
            placeholder="task_..."
            style={INPUT_STYLE}
          />
        </div>
        {error && <ErrorBox>{error}</ErrorBox>}
        {report && (
          <div
            className="flex flex-col"
            style={{
              gap: 10,
              padding: 10,
              borderRadius: 3,
              border: "1px solid var(--border-soft)",
              background: "var(--surface-sunk)",
            }}
          >
            <div className="flex items-center" style={{ gap: 8 }}>
              <MonoBadge tone={report.healed ? "warn" : "ok"}>
                {report.healed ? "HEALED" : "NO DRIFT"}
              </MonoBadge>
              <span
                className="font-mono truncate"
                style={{ fontSize: 10.5, color: "var(--text-muted)" }}
              >
                {report.task_id}
              </span>
            </div>
            <div>
              <p
                className="font-mono uppercase"
                style={{
                  fontSize: 9,
                  letterSpacing: "0.1em",
                  color: "var(--text-faint)",
                  marginBottom: 4,
                }}
              >
                signals
              </p>
              <div
                className="grid font-mono"
                style={{
                  gridTemplateColumns: "max-content 1fr",
                  columnGap: 10,
                  rowGap: 3,
                  fontSize: 10.5,
                }}
              >
                <span style={{ color: "var(--text-faint)" }}>
                  task_status
                </span>
                <span style={{ color: "var(--text-primary)" }}>
                  {report.signals.task_status ?? "--"}
                </span>
                <span style={{ color: "var(--text-faint)" }}>
                  heartbeat_at
                </span>
                <span style={{ color: "var(--text-primary)" }}>
                  {heartbeatLabel}
                </span>
                <span style={{ color: "var(--text-faint)" }}>
                  cursor_state
                </span>
                <span style={{ color: "var(--text-primary)" }}>
                  {report.signals.cursor_state ?? "--"}
                </span>
                <span style={{ color: "var(--text-faint)" }}>
                  lock_present
                </span>
                <span style={{ color: "var(--text-primary)" }}>
                  {report.signals.lock_present === null
                    ? "--"
                    : report.signals.lock_present
                      ? "true"
                      : "false"}
                </span>
              </div>
            </div>
            <div>
              <p
                className="font-mono uppercase"
                style={{
                  fontSize: 9,
                  letterSpacing: "0.1em",
                  color: "var(--text-faint)",
                  marginBottom: 4,
                }}
              >
                actions ({report.actions.length})
              </p>
              {report.actions.length === 0 ? (
                <p
                  className="font-mono"
                  style={{ fontSize: 10.5, color: "var(--text-muted)" }}
                >
                  no mutations required.
                </p>
              ) : (
                <ul
                  className="flex flex-col"
                  style={{ gap: 3, listStyle: "none", padding: 0 }}
                >
                  {report.actions.map((action, idx) => (
                    <li
                      key={`${action.kind}-${idx}`}
                      className="font-mono"
                      style={{
                        border: "1px solid var(--border-faint)",
                        background: "var(--surface-card)",
                        padding: "4px 8px",
                        fontSize: 10.5,
                        borderRadius: 2,
                      }}
                    >
                      <code style={{ color: "var(--accent)" }}>
                        {action.kind}
                      </code>
                      <span
                        style={{ color: "var(--text-muted)", marginLeft: 8 }}
                      >
                        {action.reason}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        )}
        <div className="flex" style={{ gap: 8 }}>
          <button
            type="button"
            className="font-mono uppercase"
            style={{ ...BTN_ACCENT_STYLE, flex: 1 }}
            onClick={handleRun}
            disabled={reconcileMutation.isPending}
          >
            {reconcileMutation.isPending ? "RECONCILING\u2026" : "RUN RECONCILE"}
          </button>
          <button
            type="button"
            className="font-mono uppercase"
            style={BTN_STYLE}
            onClick={handleClose}
          >
            CLOSE
          </button>
        </div>
      </div>
    </ModalShell>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function TaskQueueAdminPage() {
  const queryClient = useQueryClient();
  const [drainOpen, setDrainOpen] = useState(false);
  const [requeueOpen, setRequeueOpen] = useState(false);
  const [reconcileOpen, setReconcileOpen] = useState(false);
  const [reconcileTaskId, setReconcileTaskId] = useState("");

  const queueDepthQuery = useQuery({
    queryKey: ["platform", "tasks", "queue-depth"],
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<QueueDepth>>("/tasks/queue-depth"),
    refetchInterval: 15_000,
  });

  const deadLetterQuery = useQuery({
    queryKey: ["platform", "tasks", "dead-letter"],
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<DeadLetterEntry[]>>(
        "/admin/tasks/dead-letter",
      ),
    refetchInterval: 30_000,
  });

  const drainMutation = useMutation({
    mutationFn: () =>
      authorizedRequestJson<DataEnvelope<DrainQueueResponse>>("/tasks/drain", {
        method: "POST",
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["platform", "tasks", "queue-depth"],
      });
    },
  });

  const requeueFailedMutation = useMutation({
    mutationFn: (maxAgeHours: number) =>
      authorizedRequestJson<DataEnvelope<RequeueFailedResponse>>(
        `/tasks/requeue-failed?max_age_hours=${maxAgeHours}`,
        { method: "POST" },
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["platform", "tasks", "queue-depth"],
      });
    },
  });

  const requeueDeadLetterMutation = useMutation({
    mutationFn: (taskId: string) =>
      authorizedRequestJson<DataEnvelope<{ task_id: string; status: string }>>(
        `/admin/tasks/dead-letter/${encodeURIComponent(taskId)}/requeue`,
        { method: "POST" },
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["platform", "tasks", "queue-depth"],
      });
      void queryClient.invalidateQueries({
        queryKey: ["platform", "tasks", "dead-letter"],
      });
    },
  });

  const queueDepth = queueDepthQuery.data?.data ?? {};
  const deadLetterEntries = deadLetterQuery.data?.data ?? [];

  const totalQueued = useMemo(
    () => Object.values(queueDepth).reduce((sum, count) => sum + count, 0),
    [queueDepth],
  );

  const sortedStatuses = useMemo(() => {
    const preferred = [
      "queued",
      "waiting",
      "running",
      "paused",
      "done",
      "failed",
      "cancelled",
      "dead_letter",
    ];
    const known = preferred.filter((s) => s in queueDepth);
    const extra = Object.keys(queueDepth)
      .filter((s) => !preferred.includes(s))
      .sort();
    return [...known, ...extra];
  }, [queueDepth]);

  const drainResult = drainMutation.data?.data;
  const runningCount = queueDepth["running"] ?? 0;
  const failedCount = queueDepth["failed"] ?? 0;

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <SectionHeader
        icon={"\u25a0"}
        title="Task queue"
        actions={
          <div className="flex items-center" style={{ gap: 8 }}>
            <button
              type="button"
              style={BTN_STYLE}
              onClick={() => void queueDepthQuery.refetch()}
              disabled={queueDepthQuery.isFetching}
            >
              REFRESH
            </button>
            <button
              type="button"
              style={BTN_DANGER_STYLE}
              onClick={() => setDrainOpen(true)}
              disabled={drainMutation.isPending}
            >
              {drainMutation.isPending ? "DRAINING\u2026" : "PAUSE / DRAIN"}
            </button>
            <button
              type="button"
              style={BTN_ACCENT_STYLE}
              onClick={() => setRequeueOpen(true)}
              disabled={requeueFailedMutation.isPending}
            >
              REQUEUE FAILED
            </button>
            <button
              type="button"
              style={BTN_ACCENT_STYLE}
              onClick={() => {
                setReconcileTaskId("");
                setReconcileOpen(true);
              }}
            >
              {"RECONCILE\u2026"}
            </button>
          </div>
        }
      />

      {drainResult?.draining && (
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
          {`QUEUE DRAINING \u00b7 ${drainResult.pending} task${drainResult.pending === 1 ? "" : "s"} pending \u00b7 new submissions rejected until platform restart.`}
        </div>
      )}

      {/* Top BigStats */}
      <div
        className="grid"
        style={{
          gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
          gap: 12,
        }}
      >
        <WindowPanel title="total tasks">
          <BigStat value={totalQueued} sub="across all statuses" />
        </WindowPanel>
        <WindowPanel title="running">
          <BigStat value={runningCount} sub="in-flight workers" />
        </WindowPanel>
        <WindowPanel title="failed">
          <BigStat value={failedCount} sub="recent lookback" />
        </WindowPanel>
        <WindowPanel title="dead-lettered">
          <BigStat
            value={deadLetterEntries.length}
            sub="awaiting manual recovery"
          />
        </WindowPanel>
      </div>

      {/* Per-status depth + latency panels */}
      <WindowPanel
        title="queue depth by status"
        tone="muted"
      >
        {queueDepthQuery.isLoading && <LoadingSkeletonGroup lines={3} />}
        {queueDepthQuery.isError && (
          <ErrorBox>
            failed to load queue depth:{" "}
            {(queueDepthQuery.error as Error).message}
          </ErrorBox>
        )}
        {!queueDepthQuery.isLoading &&
          !queueDepthQuery.isError &&
          sortedStatuses.length === 0 && (
            <p
              className="font-mono"
              style={{ fontSize: 11, color: "var(--text-muted)" }}
            >
              no tasks in the queue.
            </p>
          )}
        {!queueDepthQuery.isLoading && sortedStatuses.length > 0 && (
          <div className="flex flex-col" style={{ gap: 6 }}>
            {sortedStatuses.map((status) => (
              <StatBar
                key={status}
                label={status.toUpperCase()}
                color={statusColor(status)}
                value={queueDepth[status] ?? 0}
                max={totalQueued || 1}
              />
            ))}
          </div>
        )}
      </WindowPanel>

      {/* Dead-letter queue */}
      <WindowPanel
        title="dead-letter queue"
        tone="warn"
        actions={
          <button
            type="button"
            style={BTN_STYLE}
            onClick={() => void deadLetterQuery.refetch()}
            disabled={deadLetterQuery.isFetching}
          >
            REFRESH
          </button>
        }
        flush
      >
        {deadLetterQuery.isLoading && (
          <div style={{ padding: 12 }}>
            <LoadingSkeletonGroup lines={3} />
          </div>
        )}
        {deadLetterQuery.isError && (
          <div style={{ padding: 12 }}>
            <ErrorBox>
              failed to load dead-letter entries:{" "}
              {(deadLetterQuery.error as Error).message}
            </ErrorBox>
          </div>
        )}
        {!deadLetterQuery.isLoading && !deadLetterQuery.isError && (
          <DataGrid
            columns={[
              { label: "TASK ID", width: "150px" },
              { label: "TRACK", width: "110px" },
              { label: "FUNCTION", width: "1fr" },
              { label: "ATTEMPTS", width: "80px", align: "right" },
              { label: "EXCEPTION", width: "150px" },
              { label: "DEAD AT", width: "160px" },
              { label: "ACTIONS", width: "170px", align: "right" },
            ]}
            rows={deadLetterEntries}
            getKey={(entry) => `${entry.track}:${entry.task_id}`}
            empty={
              <div
                className="font-mono"
                style={{
                  padding: 34,
                  textAlign: "center",
                  fontSize: 12,
                  color: "var(--text-muted)",
                }}
              >
                no dead-lettered tasks. failures that exhaust their retry
                budget land here for manual triage.
              </div>
            }
            renderCells={(entry) => [
              <span
                key="id"
                title={entry.task_id}
                className="truncate"
                style={{ color: "var(--text-muted)", fontSize: 10.5 }}
              >
                {`${entry.task_id.slice(0, 12)}\u2026`}
              </span>,
              <MonoBadge key="tr" tone="info">
                {entry.track}
              </MonoBadge>,
              <span
                key="fn"
                title={entry.fn_path}
                className="truncate"
                style={{ color: "var(--text-primary)", fontSize: 10.5 }}
              >
                {entry.fn_path}
              </span>,
              <span
                key="at"
                style={{ color: "var(--text-primary)", fontSize: 11 }}
              >
                {entry.attempts}
              </span>,
              <MonoBadge key="ex" tone="critical" title={entry.error}>
                {entry.exception_class || "Exception"}
              </MonoBadge>,
              <span
                key="da"
                style={{ color: "var(--text-faint)", fontSize: 10 }}
              >
                {entry.dead_lettered_at
                  ? new Date(entry.dead_lettered_at).toLocaleString()
                  : "--"}
              </span>,
              <span key="ac" className="flex" style={{ gap: 6, justifyContent: "flex-end" }}>
                <button
                  type="button"
                  style={{ ...BTN_ACCENT_STYLE, height: 22, fontSize: 9 }}
                  disabled={requeueDeadLetterMutation.isPending}
                  onClick={() =>
                    requeueDeadLetterMutation.mutate(entry.task_id)
                  }
                >
                  REQUEUE
                </button>
                <button
                  type="button"
                  style={{ ...BTN_STYLE, height: 22, fontSize: 9 }}
                  onClick={() => {
                    setReconcileTaskId(entry.task_id);
                    setReconcileOpen(true);
                  }}
                  title="Reconcile task state"
                >
                  RECONCILE
                </button>
              </span>,
            ]}
          />
        )}
        {requeueDeadLetterMutation.isError && (
          <div style={{ padding: 12 }}>
            <ErrorBox>
              requeue failed:{" "}
              {(requeueDeadLetterMutation.error as Error).message}
            </ErrorBox>
          </div>
        )}
      </WindowPanel>

      {/* Dialogs */}
      <DrainConfirmDialog
        open={drainOpen}
        isPending={drainMutation.isPending}
        onConfirm={() => drainMutation.mutateAsync()}
        onClose={() => setDrainOpen(false)}
      />
      <RequeueFailedDialog
        open={requeueOpen}
        isPending={requeueFailedMutation.isPending}
        onConfirm={async (maxAgeHours) => {
          const result = await requeueFailedMutation.mutateAsync(maxAgeHours);
          return result.data;
        }}
        onClose={() => setRequeueOpen(false)}
      />
      <ReconcileDialog
        open={reconcileOpen}
        initialTaskId={reconcileTaskId}
        onClose={() => setReconcileOpen(false)}
      />
    </div>
  );
}
