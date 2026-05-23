/**
 * TaskQueueAdminPage -- admin controls for the platform task queue.
 *
 * Operator-facing task list lives at /tasks (TasksPage). This page exposes
 * admin-only queue operations:
 *   GET  /tasks/queue-depth                — task counts by status (OPS-04)
 *   POST /tasks/drain                      — pause new submissions (OPS-05)
 *   POST /tasks/requeue-failed             — requeue recent failures (OPS-05)
 *   GET  /admin/tasks/dead-letter          — list dead-lettered tasks (Phase 178)
 *   POST /admin/tasks/dead-letter/{id}/requeue — manual dead-letter recovery
 *
 * All endpoints require admin role; the route is gated via protectPage("admin").
 */
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowsCounterClockwise,
  Pause,
  Queue,
  Skull,
} from "@phosphor-icons/react";

import { AilaCard } from "@/components/aila/AilaCard";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { EmptyState } from "@/components/aila/EmptyState";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { authorizedRequestJson } from "@platform/api/http";

// ---------------------------------------------------------------------------
// Types — mirror src/aila/api/schemas/tasks.py and admin_dead_letter.py
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

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "--";
  return new Date(value).toLocaleString();
}

type BadgeSeverity = "neutral" | "info" | "medium" | "critical" | "low";

function statusSeverity(status: string): BadgeSeverity {
  const normalized = status.toLowerCase();
  if (normalized === "running") return "info";
  if (normalized === "failed" || normalized === "dead_letter") return "critical";
  if (normalized === "paused") return "medium";
  if (normalized === "done") return "low";
  return "neutral";
}

// ---------------------------------------------------------------------------
// Drain confirmation dialog
// ---------------------------------------------------------------------------

interface DrainConfirmDialogProps {
  open: boolean;
  isPending: boolean;
  onConfirm: () => Promise<unknown>;
  onClose: () => void;
}

function DrainConfirmDialog({ open, isPending, onConfirm, onClose }: DrainConfirmDialogProps) {
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

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) { setError(null); onClose(); } }}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle className="font-mono text-text">Drain task queue</DialogTitle>
        </DialogHeader>

        <div className="flex flex-col gap-4">
          <div className="rounded-[4px] border border-medium/40 bg-medium/10 px-4 py-3">
            <p className="font-mono text-xs text-medium font-semibold mb-1">
              New task submissions will be rejected.
            </p>
            <p className="font-mono text-xs text-text-muted">
              In-flight tasks continue to run until completion. Use this before
              maintenance, restarts, or load shedding. The queue stays drained
              until the platform is restarted.
            </p>
          </div>

          {error && (
            <div className="rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
              {error}
            </div>
          )}

          <div className="flex gap-2">
            <Button
              type="button"
              size="sm"
              className="flex-1"
              onClick={handleConfirm}
              disabled={isPending}
            >
              {isPending ? "Draining..." : "Confirm Drain"}
            </Button>
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => { setError(null); onClose(); }}
            >
              Cancel
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Requeue-failed dialog with max_age_hours input
// ---------------------------------------------------------------------------

interface RequeueDialogProps {
  open: boolean;
  isPending: boolean;
  onConfirm: (maxAgeHours: number) => Promise<RequeueFailedResponse>;
  onClose: () => void;
}

function RequeueFailedDialog({ open, isPending, onConfirm, onClose }: RequeueDialogProps) {
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
    <Dialog open={open} onOpenChange={(v) => { if (!v) handleClose(); }}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle className="font-mono text-text">Requeue failed tasks</DialogTitle>
        </DialogHeader>

        <div className="flex flex-col gap-4">
          <p className="font-mono text-xs text-text-muted">
            Requeue tasks that failed within the lookback window. Backend caps
            the window at 168 hours (7 days).
          </p>

          <div className="flex flex-col gap-1">
            <label className="font-mono text-xs text-text-muted" htmlFor="rq-age">
              Max age (hours)
            </label>
            <Input
              id="rq-age"
              type="number"
              min={1}
              max={168}
              value={maxAgeHours}
              onChange={(e) => setMaxAgeHours(e.target.value)}
              className="font-mono text-sm"
            />
          </div>

          {lastResult !== null && (
            <div className="rounded-[4px] border border-low/40 bg-low/10 px-3 py-2 font-mono text-xs text-low">
              Requeued {lastResult} task{lastResult === 1 ? "" : "s"}.
            </div>
          )}

          {error && (
            <div className="rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
              {error}
            </div>
          )}

          <div className="flex gap-2">
            <Button
              type="button"
              size="sm"
              className="flex-1"
              onClick={handleConfirm}
              disabled={isPending}
            >
              {isPending ? "Requeueing..." : "Requeue Failed"}
            </Button>
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={handleClose}
            >
              Close
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function TaskQueueAdminPage() {
  const queryClient = useQueryClient();
  const [drainOpen, setDrainOpen] = useState(false);
  const [requeueOpen, setRequeueOpen] = useState(false);

  const queueDepthQuery = useQuery({
    queryKey: ["platform", "tasks", "queue-depth"],
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<QueueDepth>>("/tasks/queue-depth"),
    refetchInterval: 15_000,
  });

  const deadLetterQuery = useQuery({
    queryKey: ["platform", "tasks", "dead-letter"],
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<DeadLetterEntry[]>>("/admin/tasks/dead-letter"),
    refetchInterval: 30_000,
  });

  const drainMutation = useMutation({
    mutationFn: () =>
      authorizedRequestJson<DataEnvelope<DrainQueueResponse>>("/tasks/drain", {
        method: "POST",
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "tasks", "queue-depth"] });
    },
  });

  const requeueFailedMutation = useMutation({
    mutationFn: (maxAgeHours: number) =>
      authorizedRequestJson<DataEnvelope<RequeueFailedResponse>>(
        `/tasks/requeue-failed?max_age_hours=${maxAgeHours}`,
        { method: "POST" },
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "tasks", "queue-depth"] });
    },
  });

  const requeueDeadLetterMutation = useMutation({
    mutationFn: (taskId: string) =>
      authorizedRequestJson<DataEnvelope<{ task_id: string; status: string }>>(
        `/admin/tasks/dead-letter/${encodeURIComponent(taskId)}/requeue`,
        { method: "POST" },
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "tasks", "queue-depth"] });
      void queryClient.invalidateQueries({ queryKey: ["platform", "tasks", "dead-letter"] });
    },
  });

  const queueDepth = queueDepthQuery.data?.data ?? {};
  const deadLetterEntries = deadLetterQuery.data?.data ?? [];

  const totalQueued = useMemo(
    () => Object.values(queueDepth).reduce((sum, count) => sum + count, 0),
    [queueDepth],
  );

  const sortedStatuses = useMemo(() => {
    // Preserve a stable order for the common task statuses; unknown statuses
    // appended alphabetically at the end.
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

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      {/* Page header */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
      </div>

      {/* Drain status banner */}
      {drainResult?.draining && (
        <div className="rounded-[4px] border border-medium/40 bg-medium/10 px-4 py-3 font-mono text-xs text-medium">
          Queue is draining. {drainResult.pending} task
          {drainResult.pending === 1 ? "" : "s"} still pending. New
          submissions are rejected until the platform is restarted.
        </div>
      )}

      {/* Top metrics */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Total Tasks
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {queueDepthQuery.isLoading ? "--" : totalQueued}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">
          Across all statuses
        </p></AilaCard>

        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Running
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {queueDepthQuery.isLoading ? "--" : (queueDepth["running"] ?? 0)}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">
          In-flight workers
        </p></AilaCard>

        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Dead-lettered
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {deadLetterQuery.isLoading ? "--" : deadLetterEntries.length}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">
          Awaiting manual recovery
        </p></AilaCard>
      </div>

      {/* Queue depth detail */}
      <AilaCard variant="default" padding="md" techBorder glow><div className="flex items-center justify-between mb-3">
        <h2 className="font-mono text-xs font-semibold uppercase tracking-wider text-text-muted">
          Queue Depth by Status
        </h2>
        <Button
          size="xs"
          variant="outline"
          onClick={() => void queueDepthQuery.refetch()}
          disabled={queueDepthQuery.isFetching}
        >
          <ArrowsCounterClockwise className="h-3 w-3" />
          Refresh
        </Button>
      </div>
      
      {queueDepthQuery.isLoading && <LoadingSkeletonGroup lines={3} />}
      
      {queueDepthQuery.isError && (
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
          Failed to load queue depth: {(queueDepthQuery.error as Error).message}
        </div>
      )}
      
      {!queueDepthQuery.isLoading && !queueDepthQuery.isError && sortedStatuses.length === 0 && (
        <p className="font-mono text-xs text-text-muted">
          No tasks in the queue.
        </p>
      )}
      
      {!queueDepthQuery.isLoading && sortedStatuses.length > 0 && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {sortedStatuses.map((status) => (
            <div
              key={status}
              className="rounded-[4px] border border-border bg-base px-3 py-2 flex flex-col gap-1"
            >
              <AilaBadge severity={statusSeverity(status)} size="sm">
                {status}
              </AilaBadge>
              <p className="font-mono text-lg font-semibold text-text">
                {queueDepth[status] ?? 0}
              </p>
            </div>
          ))}
        </div>
      )}</AilaCard>

      {/* Admin actions */}
      <AilaCard variant="default" padding="md" techBorder glow><h2 className="font-mono text-xs font-semibold uppercase tracking-wider text-text-muted mb-3">
        Admin Actions
      </h2>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div className="rounded-[4px] border border-border p-3 flex flex-col gap-2">
          <div className="flex items-center gap-2">
            <Pause className="h-4 w-4 text-medium" />
            <h3 className="font-mono text-sm font-semibold text-text">Drain Queue</h3>
          </div>
          <p className="font-mono text-xs text-text-muted">
            Reject new submissions; in-flight tasks continue to run.
          </p>
          <Button
            size="sm"
            variant="outline"
            onClick={() => setDrainOpen(true)}
            disabled={drainMutation.isPending}
            className="self-start"
          >
            {drainMutation.isPending ? "Draining..." : "Drain Queue"}
          </Button>
        </div>
      
        <div className="rounded-[4px] border border-border p-3 flex flex-col gap-2">
          <div className="flex items-center gap-2">
            <ArrowsCounterClockwise className="h-4 w-4 text-info" />
            <h3 className="font-mono text-sm font-semibold text-text">Requeue Failed</h3>
          </div>
          <p className="font-mono text-xs text-text-muted">
            Requeue tasks that failed within the configured lookback window.
          </p>
          <Button
            size="sm"
            variant="outline"
            onClick={() => setRequeueOpen(true)}
            disabled={requeueFailedMutation.isPending}
            className="self-start"
          >
            {requeueFailedMutation.isPending ? "Requeueing..." : "Requeue Failed"}
          </Button>
        </div>
      </div></AilaCard>

      {/* Dead-letter queue */}
      <AilaCard variant="default" padding="md" techBorder glow><div className="flex items-center justify-between mb-3">
        <h2 className="font-mono text-xs font-semibold uppercase tracking-wider text-text-muted flex items-center gap-1.5">
          <Skull className="h-3.5 w-3.5 text-critical" />
          Dead Letter Queue
        </h2>
        <Button
          size="xs"
          variant="outline"
          onClick={() => void deadLetterQuery.refetch()}
          disabled={deadLetterQuery.isFetching}
        >
          <ArrowsCounterClockwise className="h-3 w-3" />
          Refresh
        </Button>
      </div>
      
      {deadLetterQuery.isLoading && <LoadingSkeletonGroup lines={3} />}
      
      {deadLetterQuery.isError && (
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
          Failed to load dead-letter entries: {(deadLetterQuery.error as Error).message}
        </div>
      )}
      
      {!deadLetterQuery.isLoading && !deadLetterQuery.isError && deadLetterEntries.length === 0 && (
        <EmptyState
          icon={<Skull className="h-10 w-10" />}
          title="No dead-lettered tasks"
          description="Tasks that exhaust their retry budget land here for manual triage."
        />
      )}
      
      {!deadLetterQuery.isLoading && deadLetterEntries.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <th className="py-2 px-3 text-left font-mono text-xs text-text-muted">Task ID</th>
                <th className="py-2 px-3 text-left font-mono text-xs text-text-muted">Track</th>
                <th className="py-2 px-3 text-left font-mono text-xs text-text-muted hidden md:table-cell">Function</th>
                <th className="py-2 px-3 text-left font-mono text-xs text-text-muted">Attempts</th>
                <th className="py-2 px-3 text-left font-mono text-xs text-text-muted hidden lg:table-cell">Exception</th>
                <th className="py-2 px-3 text-left font-mono text-xs text-text-muted hidden xl:table-cell">Dead-lettered</th>
                <th className="py-2 px-3 text-left font-mono text-xs text-text-muted">Actions</th>
              </tr>
            </thead>
            <tbody>
              {deadLetterEntries.map((entry) => (
                <tr
                  key={`${entry.track}:${entry.task_id}`}
                  className="border-b border-border last:border-0 font-mono text-xs hover:bg-elevated"
                >
                  <td className="py-2 px-3 text-text-muted max-w-[120px] truncate" title={entry.task_id}>
                    {entry.task_id.slice(0, 8)}…
                  </td>
                  <td className="py-2 px-3 text-text">{entry.track}</td>
                  <td className="py-2 px-3 text-text-muted hidden md:table-cell max-w-[280px] truncate" title={entry.fn_path}>
                    {entry.fn_path}
                  </td>
                  <td className="py-2 px-3 text-text">{entry.attempts}</td>
                  <td className="py-2 px-3 text-text-muted hidden lg:table-cell max-w-[200px] truncate" title={entry.error}>
                    <code className="bg-base px-1.5 py-0.5 rounded-[2px]">
                      {entry.exception_class || "Exception"}
                    </code>
                  </td>
                  <td className="py-2 px-3 text-text-muted hidden xl:table-cell whitespace-nowrap">
                    {formatTimestamp(entry.dead_lettered_at)}
                  </td>
                  <td className="py-2 px-3">
                    <Button
                      size="xs"
                      variant="outline"
                      disabled={requeueDeadLetterMutation.isPending}
                      onClick={() =>
                        requeueDeadLetterMutation.mutate(entry.task_id)
                      }
                    >
                      Requeue
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      
      {requeueDeadLetterMutation.isError && (
        <div className="mt-3 rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
          Requeue failed: {(requeueDeadLetterMutation.error as Error).message}
        </div>
      )}</AilaCard>

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
    </div>
  );
}
