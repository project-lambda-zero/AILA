import { useMemo, useRef } from "react";
import { useNavigate, useSearchParams } from "react-router";

import {
  SectionHeader,
  DataGrid,
  MonoBadge,
  StatBar,
  BigStat,
  FilterChip,
} from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { ActivityTimeline } from "@platform/features/activity/ActivityTimeline";
import { SavedViews } from "@platform/features/saved-views";

import {
  useCancelTask,
  useResumeTask,
  useScanEventFeed,
  useScanStatus,
  useSubmitScan,
  useTaskDetail,
  useTasks,
  type TaskStatus,
} from "./api";

// ---------------------------------------------------------------------------
// Constants + shared styles
// ---------------------------------------------------------------------------

const STATUS_FILTERS: TaskStatus[] = ["queued", "running", "done", "failed"];

type StatusTone = "muted" | "info" | "low" | "critical" | "warn";

const STATUS_TONE: Record<TaskStatus, StatusTone> = {
  queued: "muted",
  waiting: "muted",
  running: "info",
  paused: "warn",
  done: "low",
  failed: "critical",
  cancelled: "muted",
};

const STATUS_COLOR: Record<StatusTone, string> = {
  muted: "var(--text-muted)",
  info: "var(--status-info)",
  low: "var(--status-ok)",
  critical: "var(--accent)",
  warn: "var(--status-warn)",
};

const MONO_BTN: React.CSSProperties = {
  height: 26,
  fontSize: 9.5,
  padding: "0 11px",
  borderRadius: 3,
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  fontFamily: "var(--font-mono)",
  textTransform: "uppercase",
  letterSpacing: "0.08em",
  cursor: "pointer",
  display: "inline-flex",
  alignItems: "center",
  gap: 6,
};

const MONO_BTN_ACCENT: React.CSSProperties = {
  ...MONO_BTN,
  background: "color-mix(in srgb, var(--accent) 20%, transparent)",
  borderColor: "color-mix(in srgb, var(--accent) 45%, transparent)",
  color: "var(--accent)",
};

const MONO_INPUT: React.CSSProperties = {
  width: "100%",
  fontFamily: "var(--font-mono)",
  fontSize: 11,
  padding: "8px 10px",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  color: "var(--text-primary)",
  outline: "none",
};

const LABEL_STYLE: React.CSSProperties = {
  fontFamily: "var(--font-mono)",
  fontSize: 9,
  letterSpacing: "0.14em",
  textTransform: "uppercase",
  color: "var(--text-muted)",
};

const KV_ROW: React.CSSProperties = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "flex-start",
  gap: 10,
  padding: "6px 0",
  borderBottom: "1px solid var(--border-faint)",
  fontFamily: "var(--font-mono)",
  fontSize: 11,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatTimestamp(value: string | null) {
  return value ? new Date(value).toLocaleString() : "\u2014";
}

function parseTargets(value: string) {
  return value
    .split(/[,\n]/)
    .map((t) => t.trim())
    .filter(Boolean);
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

// ---------------------------------------------------------------------------
// Scan form
// ---------------------------------------------------------------------------

interface ScanFormProps {
  queryText: string;
  targetsText: string;
  onQueryChange: (v: string) => void;
  onTargetsChange: (v: string) => void;
  onClear: () => void;
}

function ScanForm({ queryText, targetsText, onQueryChange, onTargetsChange, onClear }: ScanFormProps) {
  const submitScan = useSubmitScan();
  const [searchParams, setSearchParams] = useSearchParams();

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    submitScan.mutate(
      { query_text: queryText.trim(), targets: parseTargets(targetsText) },
      {
        onSuccess: (response) => {
          setSearchParams(updateSearchParams(searchParams, { run: response.run_id }));
        },
      },
    );
  }

  return (
    <WindowPanel title="launch scan" tone="accent">
      <form onSubmit={handleSubmit} className="flex flex-col" style={{ gap: 10 }}>
        <div className="flex flex-col" style={{ gap: 4 }}>
          <label style={LABEL_STYLE} htmlFor="scan-query">
            Scan query *
          </label>
          <input
            id="scan-query"
            value={queryText}
            onChange={(e) => onQueryChange(e.target.value)}
            placeholder="give me a full vulnerability scan of arch-vm"
            required
            style={MONO_INPUT}
          />
        </div>

        <div className="flex flex-col" style={{ gap: 4 }}>
          <label style={LABEL_STYLE} htmlFor="scan-targets">
            Targets
          </label>
          <input
            id="scan-targets"
            value={targetsText}
            onChange={(e) => onTargetsChange(e.target.value)}
            placeholder="arch-vm, ubuntu-vm"
            style={MONO_INPUT}
          />
          <p
            className="font-mono"
            style={{ fontSize: 10, color: "var(--text-muted)" }}
          >
            Comma-separated hostnames or IPs. Leave blank for agent-resolved targets.
          </p>
        </div>

        {submitScan.isError && (
          <div
            className="font-mono"
            style={{
              border: "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
              background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
              color: "var(--status-warn)",
              padding: "6px 10px",
              fontSize: 11,
              borderRadius: 3,
            }}
          >
            {(submitScan.error as Error).message}
          </div>
        )}
        {submitScan.data && (
          <div
            className="font-mono"
            style={{
              border: "1px solid color-mix(in srgb, var(--accent) 40%, transparent)",
              background: "color-mix(in srgb, var(--accent) 10%, transparent)",
              color: "var(--accent)",
              padding: "6px 10px",
              fontSize: 11,
              borderRadius: 3,
            }}
          >
            Scan submitted -- run {submitScan.data.run_id}
          </div>
        )}

        <div className="flex" style={{ gap: 8 }}>
          <button
            type="submit"
            disabled={submitScan.isPending || !queryText.trim()}
            style={{
              ...MONO_BTN_ACCENT,
              opacity: submitScan.isPending || !queryText.trim() ? 0.5 : 1,
            }}
          >
            {submitScan.isPending ? "SUBMITTING\u2026" : "SUBMIT SCAN"}
          </button>
          <button type="button" onClick={onClear} style={MONO_BTN}>
            CLEAR
          </button>
        </div>
      </form>
    </WindowPanel>
  );
}

// ---------------------------------------------------------------------------
// Run detail panel
// ---------------------------------------------------------------------------

function RunDetailPanel({ runId }: { runId: string }) {
  const taskDetailQuery = useTaskDetail(runId);
  const scanStatusQuery = useScanStatus(runId);
  const scanEvents = useScanEventFeed(runId);
  const cancelTask = useCancelTask(runId);
  const resumeTask = useResumeTask(runId);

  const liveEvents = useMemo(
    () =>
      scanEvents.events.filter(
        (e) => e.message || e.stage || typeof e.percent === "number",
      ),
    [scanEvents.events],
  );

  const isTaskLive =
    taskDetailQuery.data?.status === "running" ||
    taskDetailQuery.data?.status === "queued" ||
    taskDetailQuery.data?.status === "waiting";

  if (!runId) {
    return (
      <WindowPanel title="run detail" tone="muted">
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--text-muted)" }}
        >
          Select a run row to inspect its live state and progress stream.
        </p>
      </WindowPanel>
    );
  }

  const isLoading = taskDetailQuery.isLoading || scanStatusQuery.isLoading;
  if (isLoading) {
    return (
      <WindowPanel title="run detail" status="LOADING" tone="muted">
        <LoadingSkeletonGroup lines={5} />
      </WindowPanel>
    );
  }

  const task = taskDetailQuery.data;
  const canCancel = task ? ["queued", "waiting", "running"].includes(task.status) : false;
  const canResume = task?.status === "paused";

  return (
    <div className="flex flex-col" style={{ gap: 14 }}>
      <WindowPanel
        title="selected run"
        tone={task ? STATUS_TONE[task.status] === "critical" ? "warn" : "accent" : "muted"}
      >
        {task ? (
          <div className="flex flex-col">
            <div style={KV_ROW}>
              <span style={{ color: "var(--text-muted)" }}>STATUS</span>
              <MonoBadge tone={STATUS_TONE[task.status]}>
                {task.status.toUpperCase()}
              </MonoBadge>
            </div>
            <div style={KV_ROW}>
              <span style={{ color: "var(--text-muted)" }}>TRACK</span>
              <span style={{ color: "var(--text-primary)", textAlign: "right" }}>
                {task.track}
              </span>
            </div>
            <div style={KV_ROW}>
              <span style={{ color: "var(--text-muted)" }}>RUN ID</span>
              <span
                style={{
                  color: "var(--accent)",
                  textAlign: "right",
                  wordBreak: "break-all",
                }}
              >
                {task.task_id}
              </span>
            </div>
            <div style={KV_ROW}>
              <span style={{ color: "var(--text-muted)" }}>CREATED</span>
              <span style={{ color: "var(--text-primary)", textAlign: "right" }}>
                {formatTimestamp(task.created_at)}
              </span>
            </div>
            <div style={KV_ROW}>
              <span style={{ color: "var(--text-muted)" }}>STARTED</span>
              <span style={{ color: "var(--text-primary)", textAlign: "right" }}>
                {formatTimestamp(task.started_at)}
              </span>
            </div>
            <div style={KV_ROW}>
              <span style={{ color: "var(--text-muted)" }}>COMPLETED</span>
              <span style={{ color: "var(--text-primary)", textAlign: "right" }}>
                {formatTimestamp(task.completed_at)}
              </span>
            </div>

            {task.error && (
              <div
                className="font-mono"
                style={{
                  marginTop: 10,
                  border: "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
                  background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
                  color: "var(--status-warn)",
                  padding: "6px 10px",
                  fontSize: 11,
                  borderRadius: 3,
                }}
              >
                {task.error}
              </div>
            )}

            <div className="flex flex-wrap" style={{ gap: 8, marginTop: 12 }}>
              <button
                type="button"
                disabled={!canCancel || cancelTask.isPending}
                onClick={() => cancelTask.mutate()}
                style={{
                  ...MONO_BTN,
                  opacity: !canCancel || cancelTask.isPending ? 0.5 : 1,
                  cursor: !canCancel ? "not-allowed" : "pointer",
                }}
              >
                {cancelTask.isPending ? "CANCELLING\u2026" : "CANCEL"}
              </button>
              <button
                type="button"
                disabled={!canResume || resumeTask.isPending}
                onClick={() => resumeTask.mutate()}
                style={{
                  ...MONO_BTN,
                  opacity: !canResume || resumeTask.isPending ? 0.5 : 1,
                  cursor: !canResume ? "not-allowed" : "pointer",
                }}
              >
                {resumeTask.isPending ? "RESUMING\u2026" : "RESUME"}
              </button>
            </div>
          </div>
        ) : (
          <p
            className="font-mono"
            style={{ fontSize: 11, color: "var(--text-muted)" }}
          >
            Run detail not found. The run may have been deleted or never existed.
          </p>
        )}
      </WindowPanel>

      {/* Live event stream */}
      <WindowPanel title="live progress" tone="ok">
        {scanEvents.status === "connecting" && (
          <p
            className="font-mono"
            style={{ fontSize: 11, color: "var(--text-muted)" }}
          >
            Connecting to stream{"\u2026"}
          </p>
        )}
        {scanEvents.status === "unavailable" && (
          <p
            className="font-mono"
            style={{ fontSize: 11, color: "var(--text-muted)" }}
          >
            Redis streaming unavailable. Polling reflects run status.
          </p>
        )}
        {scanEvents.status === "error" && (
          <div
            className="font-mono"
            style={{
              border: "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
              background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
              color: "var(--status-warn)",
              padding: "6px 10px",
              fontSize: 11,
              borderRadius: 3,
            }}
          >
            {scanEvents.error}
          </div>
        )}
        {liveEvents.length === 0 && scanEvents.status === "closed" && (
          <p
            className="font-mono"
            style={{ fontSize: 11, color: "var(--text-muted)" }}
          >
            Stream closed without delivering progress events.
          </p>
        )}
        {liveEvents.length > 0 && (
          <div
            className="flex flex-col"
            style={{ gap: 8, maxHeight: 256, overflowY: "auto" }}
          >
            {liveEvents.map((event, index) => (
              <div
                key={`${event.timestamp ?? "event"}-${index}`}
                style={{
                  borderLeft: "2px solid color-mix(in srgb, var(--accent) 45%, transparent)",
                  paddingLeft: 10,
                  paddingTop: 2,
                  paddingBottom: 2,
                }}
              >
                <div className="flex items-center justify-between" style={{ gap: 8 }}>
                  <span
                    className="font-mono uppercase"
                    style={{
                      fontSize: 10,
                      letterSpacing: "0.1em",
                      color: "var(--text-primary)",
                      fontWeight: 600,
                    }}
                  >
                    {event.stage ?? "event"}
                  </span>
                  <span
                    className="font-mono"
                    style={{ fontSize: 10, color: "var(--text-muted)" }}
                  >
                    {typeof event.percent === "number" ? `${event.percent}%` : ""}
                  </span>
                </div>
                <p
                  className="font-mono"
                  style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 2 }}
                >
                  {event.message ?? "No message."}
                </p>
              </div>
            ))}
          </div>
        )}
      </WindowPanel>

      <WindowPanel title="activity" tone="muted">
        <ActivityTimeline runId={runId} label="Scan Run" live={isTaskLive} />
      </WindowPanel>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Metric row -- 3 WindowPanels of StatBar / BigStat
// ---------------------------------------------------------------------------

interface MetricRowProps {
  total: number;
  counts: Record<TaskStatus, number>;
}

function MetricRow({ total, counts }: MetricRowProps) {
  return (
    <div
      className="grid"
      style={{ gridTemplateColumns: "1fr 220px 220px", gap: 12 }}
    >
      <WindowPanel title="status distribution">
        <div className="flex flex-col" style={{ gap: 8 }}>
          <StatBar
            label="RUNNING"
            color={STATUS_COLOR.info}
            value={counts.running}
            max={Math.max(total, 1)}
          />
          <StatBar
            label="QUEUED"
            color={STATUS_COLOR.muted}
            value={counts.queued + counts.waiting}
            max={Math.max(total, 1)}
          />
          <StatBar
            label="DONE"
            color={STATUS_COLOR.low}
            value={counts.done}
            max={Math.max(total, 1)}
          />
          <StatBar
            label="FAILED"
            color={STATUS_COLOR.critical}
            value={counts.failed}
            max={Math.max(total, 1)}
          />
        </div>
      </WindowPanel>
      <WindowPanel title="total scans" tone="info">
        <BigStat value={total} sub="tracked runs" />
      </WindowPanel>
      <WindowPanel title="live" tone="accent">
        <BigStat
          value={counts.running}
          sub={counts.running === 1 ? "run in flight" : "runs in flight"}
        />
      </WindowPanel>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function ScanCenterPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const queryText = searchParams.get("query") ?? "";
  const targetsText = searchParams.get("targets") ?? searchParams.get("target") ?? "";
  const selectedRunId = searchParams.get("run") ?? "";
  const statusFilter = normalizeTaskStatus(searchParams.get("status"));
  const tasksQuery = useTasks("vulnerability", statusFilter);
  const scanFormRef = useRef<HTMLDivElement>(null);

  const tasks = tasksQuery.data?.tasks ?? [];

  const counts = useMemo<Record<TaskStatus, number>>(() => {
    const acc: Record<TaskStatus, number> = {
      queued: 0, waiting: 0, running: 0, paused: 0, done: 0, failed: 0, cancelled: 0,
    };
    for (const t of tasks) acc[t.status] += 1;
    return acc;
  }, [tasks]);

  function focusScanForm() {
    scanFormRef.current?.scrollIntoView({ behavior: "smooth" });
  }

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <SectionHeader
        icon={"\u25ce"}
        title="scan center"
        actions={
          <button type="button" onClick={focusScanForm} style={MONO_BTN_ACCENT}>
            + NEW SCAN
          </button>
        }
      />

      <MetricRow total={tasks.length} counts={counts} />

      <div
        className="grid"
        style={{ gridTemplateColumns: "minmax(0, 1fr) 380px", gap: 16 }}
      >
        <div className="flex flex-col" style={{ gap: 14 }}>
          <div ref={scanFormRef}>
            <ScanForm
              queryText={queryText}
              targetsText={targetsText}
              onQueryChange={(v) =>
                setSearchParams(updateSearchParams(searchParams, { query: v }), { replace: true })
              }
              onTargetsChange={(v) =>
                setSearchParams(updateSearchParams(searchParams, { targets: v }), { replace: true })
              }
              onClear={() =>
                setSearchParams(updateSearchParams(searchParams, { query: "", targets: "" }))
              }
            />
          </div>

          {/* Filter chip row */}
          <div className="flex items-center flex-wrap" style={{ gap: 8 }}>
            {STATUS_FILTERS.map((status) => (
              <FilterChip
                key={status}
                active={statusFilter === status}
                color={STATUS_COLOR[STATUS_TONE[status]]}
                onClick={() =>
                  setSearchParams(
                    updateSearchParams(searchParams, {
                      status: statusFilter === status ? null : status,
                    }),
                  )
                }
              >
                {status.toUpperCase()}
              </FilterChip>
            ))}
            {statusFilter && (
              <button
                type="button"
                onClick={() =>
                  setSearchParams(updateSearchParams(searchParams, { status: null }))
                }
                className="font-mono uppercase"
                style={{
                  fontSize: 9,
                  letterSpacing: "0.1em",
                  color: "var(--text-muted)",
                  background: "transparent",
                  border: "none",
                  cursor: "pointer",
                }}
              >
                CLEAR
              </button>
            )}
            <div style={{ flex: 1 }} />
            <SavedViews<{
              query: string;
              targets: string;
              status: TaskStatus | "";
            }>
              entityType="scan"
              entityLabel="Scan console"
              currentState={{
                query: queryText,
                targets: targetsText,
                status: statusFilter ?? "",
              }}
              onApply={(state) => {
                setSearchParams(
                  updateSearchParams(searchParams, {
                    query: state.query ?? "",
                    targets: state.targets ?? "",
                    status: state.status || null,
                  }),
                );
              }}
            />
          </div>

          {/* Scan list */}
          <WindowPanel title="scan runs" flush>
            {tasksQuery.isLoading && (
              <div style={{ padding: 12 }}>
                <LoadingSkeletonGroup lines={5} />
              </div>
            )}
            {tasksQuery.isError && (
              <div
                className="font-mono"
                style={{
                  margin: 12,
                  border: "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
                  background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
                  color: "var(--status-warn)",
                  padding: "6px 10px",
                  fontSize: 11,
                  borderRadius: 3,
                }}
              >
                {(tasksQuery.error as Error).message}
              </div>
            )}
            {!tasksQuery.isLoading && !tasksQuery.isError && (
              <DataGrid
                columns={[
                  { label: "ID", width: "110px" },
                  { label: "TYPE", width: "120px" },
                  { label: "TARGET", width: "1fr" },
                  { label: "STATUS", width: "110px" },
                  { label: "STARTED", width: "180px" },
                  { label: "ACTIONS", width: "90px", align: "right" },
                ]}
                rows={tasks}
                getKey={(t) => t.task_id}
                onRowClick={(t) => {
                  navigate(`/console/${encodeURIComponent(t.task_id)}`);
                  setSearchParams(updateSearchParams(searchParams, { run: t.task_id }));
                }}
                empty={
                  <div
                    className="flex flex-col items-center justify-center"
                    style={{ padding: 32, gap: 8 }}
                  >
                    <span style={{ fontSize: 22, color: "var(--text-faint)" }}>
                      {"\u25c7"}
                    </span>
                    <p
                      className="font-mono uppercase"
                      style={{
                        fontSize: 10,
                        letterSpacing: "0.14em",
                        color: "var(--text-muted)",
                      }}
                    >
                      No scans yet
                    </p>
                    <button
                      type="button"
                      onClick={focusScanForm}
                      style={MONO_BTN_ACCENT}
                    >
                      + SUBMIT SCAN
                    </button>
                  </div>
                }
                renderCells={(t) => [
                  <span
                    key="id"
                    style={{ color: "var(--accent)", fontSize: 10 }}
                    data-testid="scan-row"
                    data-task-id={t.task_id}
                  >
                    {t.task_id.slice(0, 8)}
                    {"\u2026"}
                  </span>,
                  <span key="type" style={{ color: "var(--text-muted)", fontSize: 10 }}>
                    {t.track}
                  </span>,
                  <span
                    key="target"
                    className="truncate"
                    style={{ color: "var(--text-primary)", fontSize: 10 }}
                  >
                    {t.fn_module || "\u2014"}
                  </span>,
                  <MonoBadge key="status" tone={STATUS_TONE[t.status]}>
                    {t.status.toUpperCase()}
                  </MonoBadge>,
                  <span
                    key="started"
                    style={{ color: "var(--text-muted)", fontSize: 10 }}
                  >
                    {formatTimestamp(t.started_at ?? t.created_at)}
                  </span>,
                  <span
                    key="actions"
                    style={{
                      display: "inline-flex",
                      justifyContent: "flex-end",
                      width: "100%",
                    }}
                  >
                    <MonoBadge tone={t.task_id === selectedRunId ? "accent" : "muted"}>
                      {t.task_id === selectedRunId ? "OPEN" : "VIEW"}
                    </MonoBadge>
                  </span>,
                ]}
              />
            )}
          </WindowPanel>
        </div>

        {/* Right: run detail */}
        <div style={{ minWidth: 0 }}>
          <RunDetailPanel runId={selectedRunId} />
        </div>
      </div>
    </div>
  );
}
