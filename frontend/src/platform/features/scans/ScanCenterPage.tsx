import { useMemo, useRef } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Crosshair, Play } from "@phosphor-icons/react";

import { AilaCard } from "@/components/aila/AilaCard";
import { AilaBadge, type TaskStatus as BadgeTaskStatus } from "@/components/aila/AilaBadge";
import { EmptyState } from "@/components/aila/EmptyState";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { HelpTip } from "@/components/aila/HelpTip";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

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
// Helpers
// ---------------------------------------------------------------------------

function formatTimestamp(value: string | null) {
  return value ? new Date(value).toLocaleString() : "—";
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

const STATUS_FILTERS: TaskStatus[] = ["queued", "running", "done", "failed"];

// ---------------------------------------------------------------------------
// Scan form
// ---------------------------------------------------------------------------

function ScanForm({ queryText, targetsText, onQueryChange, onTargetsChange, onClear }: {
  queryText: string;
  targetsText: string;
  onQueryChange: (v: string) => void;
  onTargetsChange: (v: string) => void;
  onClear: () => void;
}) {
  const submitScan = useSubmitScan();
  const [, setSearchParams] = useSearchParams();
  const [searchParams] = useSearchParams();

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
    <AilaCard variant="elevated" padding="md">
      <div className="flex items-center gap-2 mb-4">
        <h2 className="font-mono text-sm font-semibold text-text">Launch a Scan</h2>
        <HelpTip
          title="Vulnerability Scan"
          description="Scans the target system for installed packages with known CVEs using NVD and GHSA advisory databases."
        />
      </div>

      <form onSubmit={handleSubmit} className="flex flex-col gap-3">
        <div className="flex flex-col gap-1">
          <label className="font-mono text-xs text-text-muted" htmlFor="scan-query">
            Scan query *
          </label>
          <Input
            id="scan-query"
            value={queryText}
            onChange={(e) => onQueryChange(e.target.value)}
            placeholder="give me a full vulnerability scan of arch-vm"
            required
          />
        </div>

        <div className="flex flex-col gap-1">
          <label className="font-mono text-xs text-text-muted" htmlFor="scan-targets">
            Targets
          </label>
          <Input
            id="scan-targets"
            value={targetsText}
            onChange={(e) => onTargetsChange(e.target.value)}
            placeholder="arch-vm, ubuntu-vm"
          />
          <p className="font-mono text-xs text-text-muted">
            Comma-separated hostnames or IPs. Leave blank for agent-resolved targets.
          </p>
        </div>

        {submitScan.isError && (
          <div className="rounded-[2px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
            {(submitScan.error as Error).message}
          </div>
        )}
        {submitScan.data && (
          <div className="rounded-[2px] border border-accent/30 bg-accent/10 px-3 py-2 font-mono text-xs text-accent">
            Scan submitted — run {submitScan.data.run_id}
          </div>
        )}

        <div className="flex gap-2">
          <Button type="submit" size="sm" disabled={submitScan.isPending || !queryText.trim()}>
            {submitScan.isPending ? "Submitting..." : "Submit Scan"}
          </Button>
          <Button type="button" size="sm" variant="outline" onClick={onClear}>
            Clear
          </Button>
        </div>
      </form>
    </AilaCard>
  );
}

// ---------------------------------------------------------------------------
// Run detail panel
// ---------------------------------------------------------------------------

function RunDetailPanel({ runId }: { runId: string }) {
  const [searchParams, setSearchParams] = useSearchParams();
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

  if (!runId) {
    return (
      <AilaCard variant="default" padding="md">
        <p className="font-mono text-xs text-text-muted">
          Select a run row to inspect its live state and progress stream.
        </p>
      </AilaCard>
    );
  }

  const isLoading = taskDetailQuery.isLoading || scanStatusQuery.isLoading;
  if (isLoading) {
    return <AilaCard variant="default" padding="md"><LoadingSkeletonGroup lines={5} /></AilaCard>;
  }

  const task = taskDetailQuery.data;
  const canCancel = task ? ["queued", "waiting", "running"].includes(task.status) : false;
  const canResume = task?.status === "paused";

  return (
    <div className="flex flex-col gap-4">
      <AilaCard variant="elevated" padding="md">
        <h2 className="font-mono text-xs font-semibold uppercase tracking-wider text-text-muted mb-3">
          Selected Run
        </h2>

        {task ? (
          <div className="flex flex-col gap-2">
            {[
              { label: "Status", value: <AilaBadge severity={statusSeverity(task.status)} size="sm">{task.status}</AilaBadge> },
              { label: "Track", value: task.track },
              { label: "Created", value: formatTimestamp(task.created_at) },
              { label: "Started", value: formatTimestamp(task.started_at) },
              { label: "Completed", value: formatTimestamp(task.completed_at) },
            ].map(({ label, value }) => (
              <div key={label} className="flex items-start justify-between gap-2 border-b border-border pb-1.5 last:border-0">
                <span className="font-mono text-xs text-text-muted shrink-0">{label}</span>
                <span className="font-mono text-xs text-text text-right">{value}</span>
              </div>
            ))}

            {task.error && (
              <div className="rounded-[2px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
                {task.error}
              </div>
            )}

            <div className="flex flex-wrap gap-2 pt-1">
              <Button
                size="sm"
                variant="outline"
                disabled={!canCancel || cancelTask.isPending}
                onClick={() => cancelTask.mutate()}
              >
                {cancelTask.isPending ? "Cancelling..." : "Cancel"}
              </Button>
              <Button
                size="sm"
                variant="outline"
                disabled={!canResume || resumeTask.isPending}
                onClick={() => resumeTask.mutate()}
              >
                {resumeTask.isPending ? "Resuming..." : "Resume"}
              </Button>
              {scanStatusQuery.data?.status === "done" && (
                <Link
                  to={`/vulnerability/reports/${encodeURIComponent(runId)}`}
                  className="inline-flex h-7 items-center gap-1 rounded-[min(var(--radius-md),12px)] bg-primary px-2.5 text-[0.8rem] font-medium text-primary-foreground transition-all hover:bg-primary/80"
                >
                  Open Report
                </Link>
              )}
            </div>
          </div>
        ) : (
          <p className="font-mono text-xs text-text-muted">
            Run detail not found. The run may have been deleted or never existed.
          </p>
        )}
      </AilaCard>

      {/* Live event stream */}
      <AilaCard variant="default" padding="md">
        <h2 className="font-mono text-xs font-semibold uppercase tracking-wider text-text-muted mb-3">
          Live Progress
        </h2>

        {scanEvents.status === "connecting" && (
          <p className="font-mono text-xs text-text-muted">Connecting to stream…</p>
        )}
        {scanEvents.status === "unavailable" && (
          <p className="font-mono text-xs text-text-muted">
            Redis streaming unavailable. Polling reflects run status.
          </p>
        )}
        {scanEvents.status === "error" && (
          <div className="rounded-[2px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
            {scanEvents.error}
          </div>
        )}
        {liveEvents.length === 0 && scanEvents.status === "closed" && (
          <p className="font-mono text-xs text-text-muted">
            Stream closed without delivering progress events.
          </p>
        )}
        {liveEvents.length > 0 && (
          <div className="flex flex-col gap-2 max-h-64 overflow-y-auto">
            {liveEvents.map((event, index) => (
              <div
                key={`${event.timestamp ?? "event"}-${index}`}
                className="border-l-2 border-accent/40 pl-3 py-0.5"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs font-semibold text-text">
                    {event.stage ?? "event"}
                  </span>
                  <span className="font-mono text-xs text-text-muted">
                    {typeof event.percent === "number" ? `${event.percent}%` : ""}
                  </span>
                </div>
                <p className="font-mono text-xs text-text-muted mt-0.5">
                  {event.message ?? "No message."}
                </p>
              </div>
            ))}
          </div>
        )}
      </AilaCard>
    </div>
  );

  void setSearchParams; // suppress unused warning
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

  function focusScanForm() {
    scanFormRef.current?.scrollIntoView({ behavior: "smooth" });
  }

  return (
    <div className="flex flex-col gap-4 p-3 sm:p-4 lg:p-6">
      {/* Page header */}
      <div className="flex flex-col gap-1">
        <h1 className="font-mono text-xl font-semibold text-text">Scan Center</h1>
        <p className="font-mono text-sm text-text-muted">
          Launch vulnerability scans, monitor run state, and follow live progress.
        </p>
      </div>

      {/* Main split layout */}
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start">

        {/* Left: form + task list */}
        <div className="flex-1 min-w-0 flex flex-col gap-4">
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

          {/* Task list */}
          <AilaCard variant="default" padding="md">
            <div className="flex flex-col gap-3">
              <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                <h2 className="font-mono text-sm font-semibold text-text">Recent Runs</h2>
                <div className="flex flex-wrap gap-1.5">
                  {STATUS_FILTERS.map((status) => (
                    <button
                      key={status}
                      type="button"
                      onClick={() =>
                        setSearchParams(
                          updateSearchParams(searchParams, {
                            status: statusFilter === status ? null : status,
                          }),
                        )
                      }
                      className="cursor-pointer"
                    >
                      <AilaBadge
                        severity={statusFilter === status ? statusSeverity(status) : "neutral"}
                        size="sm"
                        solid={statusFilter === status}
                      >
                        {status}
                      </AilaBadge>
                    </button>
                  ))}
                  {statusFilter && (
                    <button
                      type="button"
                      onClick={() =>
                        setSearchParams(updateSearchParams(searchParams, { status: null }))
                      }
                      className="font-mono text-xs text-text-muted hover:text-text transition-colors"
                    >
                      Clear
                    </button>
                  )}
                </div>
              </div>

              {tasksQuery.isLoading && <LoadingSkeletonGroup lines={4} />}

              {tasksQuery.isError && (
                <div className="rounded-[2px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
                  {(tasksQuery.error as Error).message}
                </div>
              )}

              {!tasksQuery.isLoading && tasks.length === 0 && (
                <EmptyState
                  icon={<Play size={32} />}
                  title="No scans yet"
                  description="Submit a scan above to start discovering vulnerabilities."
                  action={{ label: "Submit a Scan", onClick: focusScanForm }}
                />
              )}

              {tasks.length > 0 && (
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-border">
                        <th className="py-2 px-3 text-left font-mono text-xs text-text-muted">Run ID</th>
                        <th className="py-2 px-3 text-left font-mono text-xs text-text-muted">Status</th>
                        <th className="py-2 px-3 text-left font-mono text-xs text-text-muted hidden sm:table-cell">Created</th>
                      </tr>
                    </thead>
                    <tbody>
                      {tasks.map((task) => {
                        const activate = (event: React.SyntheticEvent) => {
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
                          // D-04 + D-14: navigate to /console/:runId, keep selection param for panel.
                          navigate(`/console/${encodeURIComponent(task.task_id)}`);
                          setSearchParams(updateSearchParams(searchParams, { run: task.task_id }));
                        };
                        const token = statusToken(task.status);
                        return (
                          <tr
                            key={task.task_id}
                            role="button"
                            tabIndex={0}
                            data-testid="scan-row"
                            data-task-id={task.task_id}
                            className={`border-b border-border font-mono text-xs transition-colors cursor-pointer hover:bg-elevated focus:outline focus:outline-2 focus:outline-accent ${
                              task.task_id === selectedRunId ? "bg-accent/5" : ""
                            }`}
                            onClick={activate}
                            onKeyDown={(event) => {
                              if (event.key === "Enter" || event.key === " ") {
                                if (event.key === " ") event.preventDefault();
                                activate(event);
                              }
                            }}
                          >
                            <td className="py-2 px-3 text-text-muted">
                              {task.task_id.slice(0, 8)}…
                            </td>
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
                              {formatTimestamp(task.created_at)}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </AilaCard>
        </div>

        {/* Right: run detail panel */}
        <div className="w-full lg:w-80 xl:w-96 shrink-0">
          <RunDetailPanel runId={selectedRunId} />
        </div>
      </div>
    </div>
  );
}
