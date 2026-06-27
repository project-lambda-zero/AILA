/**
 * DeadLetterPage -- admin dead-letter queue inspection and manual requeue.
 *
 * Phase 178: lists tasks that exhausted poison_attempts and were moved to the
 * `arq:dead-letter:{track}` sorted set. Operators inspect the failure, fix
 * the root cause, then click Requeue to re-submit the same payload.
 *
 * Endpoints (admin only):
 *   GET  /admin/tasks/dead-letter
 *   POST /admin/tasks/dead-letter/{task_id}/requeue
 */
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type ColumnDef } from "@tanstack/react-table";
import { Skull } from "@phosphor-icons/react/dist/csr/Skull";
import { ArrowCounterClockwise } from "@phosphor-icons/react/dist/csr/ArrowCounterClockwise";

import { AilaCard } from "@/components/aila/AilaCard";
import { AilaTable } from "@/components/aila/AilaTable";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { EmptyState } from "@/components/aila/EmptyState";
import { Button } from "@/components/ui/button";
import { authorizedRequestJson } from "@platform/api/http";

// ---------------------------------------------------------------------------
// Types -- mirror src/aila/api/routers/admin_dead_letter.py:DeadLetterEntry
// ---------------------------------------------------------------------------

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

interface DataEnvelope<T> {
  data: T;
  error: string | null;
  meta: Record<string, unknown>;
}

interface RequeueResponse {
  task_id: string;
  status: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "--";
  return new Date(value).toLocaleString();
}

// ---------------------------------------------------------------------------
// Requeue button -- per-row action
// ---------------------------------------------------------------------------

function RequeueButton({
  taskId,
  onRequeue,
  isPending,
}: {
  taskId: string;
  onRequeue: (taskId: string) => Promise<RequeueResponse>;
  isPending: boolean;
}) {
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleClick() {
    setError(null);
    setSubmitting(true);
    try {
      await onRequeue(taskId);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to requeue");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex flex-col items-end gap-1">
      <Button
        size="sm"
        variant="outline"
        className="gap-1.5"
        disabled={submitting || isPending}
        onClick={handleClick}
      >
        <ArrowCounterClockwise className="h-3.5 w-3.5" />
        {submitting ? "Requeueing…" : "Requeue"}
      </Button>
      {error && (
        <span className="font-mono text-xs text-destructive max-w-[160px] text-right">
          {error}
        </span>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Columns
// ---------------------------------------------------------------------------

function buildColumns(
  onRequeue: (taskId: string) => Promise<RequeueResponse>,
  isPending: boolean,
): ColumnDef<DeadLetterEntry>[] {
  return [
    {
      id: "task_id",
      header: "Task ID",
      accessorKey: "task_id",
      cell: ({ getValue }) => (
        <code className="font-mono text-xs text-text-muted">
          {String(getValue()).slice(0, 8)}…
        </code>
      ),
    },
    {
      id: "track",
      header: "Track",
      accessorKey: "track",
      cell: ({ getValue }) => (
        <AilaBadge severity="neutral" size="sm">
          {String(getValue())}
        </AilaBadge>
      ),
    },
    {
      id: "fn_path",
      header: "Function",
      accessorKey: "fn_path",
      cell: ({ getValue }) => (
        <span className="font-mono text-xs text-text break-all">
          {String(getValue()) || "--"}
        </span>
      ),
    },
    {
      id: "exception_class",
      header: "Exception",
      accessorKey: "exception_class",
      cell: ({ getValue }) => (
        <AilaBadge severity="critical" size="sm">
          {String(getValue()) || "Unknown"}
        </AilaBadge>
      ),
    },
    {
      id: "error",
      header: "Error",
      accessorKey: "error",
      enableSorting: false,
      cell: ({ getValue }) => (
        <span
          className="font-mono text-xs text-text-muted line-clamp-2 max-w-[320px] break-all"
          title={String(getValue())}
        >
          {String(getValue()) || "--"}
        </span>
      ),
    },
    {
      id: "attempts",
      header: "Attempts",
      accessorKey: "attempts",
      cell: ({ getValue }) => (
        <span className="font-mono text-xs text-text">{String(getValue())}</span>
      ),
    },
    {
      id: "dead_lettered_at",
      header: "Dead-Lettered",
      accessorKey: "dead_lettered_at",
      cell: ({ getValue }) => (
        <span className="font-mono text-xs text-text-muted whitespace-nowrap">
          {formatTimestamp(getValue() as string)}
        </span>
      ),
    },
    {
      id: "actions",
      header: "Actions",
      enableSorting: false,
      cell: ({ row }) => (
        <RequeueButton
          taskId={row.original.task_id}
          onRequeue={onRequeue}
          isPending={isPending}
        />
      ),
    },
  ];
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function DeadLetterPage() {
  const queryClient = useQueryClient();
  const [trackFilter, setTrackFilter] = useState("");

  const queryKey = ["platform", "admin-dead-letter", trackFilter] as const;
  const queryPath = trackFilter
    ? `/admin/tasks/dead-letter?track=${encodeURIComponent(trackFilter)}`
    : "/admin/tasks/dead-letter";

  const entriesQuery = useQuery({
    queryKey,
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<DeadLetterEntry[]>>(queryPath),
  });

  const requeueMutation = useMutation({
    mutationFn: (taskId: string) =>
      authorizedRequestJson<DataEnvelope<RequeueResponse>>(
        `/admin/tasks/dead-letter/${encodeURIComponent(taskId)}/requeue`,
        { method: "POST" },
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["platform", "admin-dead-letter"],
      });
    },
  });

  const entries = entriesQuery.data?.data ?? [];

  const tracks = useMemo(() => {
    const set = new Set(entries.map((e) => e.track));
    return [...set].sort();
  }, [entries]);

  const columns = useMemo(
    () =>
      buildColumns(
        async (taskId: string) => {
          const res = await requeueMutation.mutateAsync(taskId);
          return res.data;
        },
        requeueMutation.isPending,
      ),
    [requeueMutation],
  );

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      {/* Header */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Dead-Lettered Tasks
        </p>
        <p className="font-mono text-2xl font-semibold text-critical mt-1">
          {entriesQuery.isLoading ? "--" : entries.length}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">
          {trackFilter ? `Track: ${trackFilter}` : "All tracks"}
        </p></AilaCard>
        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Distinct Tracks
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {entriesQuery.isLoading ? "--" : tracks.length}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">
          With at least one dead-lettered task
        </p></AilaCard>
        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Track Filter
        </p>
        <input
          aria-label="Track filter"
          className="mt-2 w-full h-8 rounded-[2px] border border-border bg-base px-2.5 font-mono text-xs text-text outline-none focus:border-border-hover transition-colors"
          type="text"
          value={trackFilter}
          onChange={(e) => setTrackFilter(e.target.value)}
          placeholder="vulnerability"
        />
        <p className="font-mono text-xs text-text-muted mt-1">
          Empty = scan all tracks
        </p></AilaCard>
      </div>

      {/* Error banner */}
      {entriesQuery.isError && (
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-sm text-destructive">
          Failed to load dead-letter entries: {(entriesQuery.error as Error).message}
        </div>
      )}

      {/* Loading */}
      {entriesQuery.isLoading && (
        <AilaCard variant="default" padding="md" techBorder glow><LoadingSkeletonGroup lines={6} /></AilaCard>
      )}

      {/* Empty */}
      {!entriesQuery.isLoading && !entriesQuery.isError && entries.length === 0 && (
        <EmptyState
          icon={<Skull className="h-10 w-10" />}
          title="No dead-lettered tasks"
          description="Tasks land here only after exhausting their retry budget. A clean queue is a healthy queue."
        />
      )}

      {/* Table */}
      {!entriesQuery.isLoading && entries.length > 0 && (
        <AilaTable
          data={entries}
          columns={columns}
          pageSize={25}
          enableSorting
          enableFiltering={false}
        >
          <AilaTable.Header />
          <AilaTable.Body emptyState="No dead-lettered tasks." />
          <AilaTable.Pagination pageSizeOptions={[10, 25, 50]} />
        </AilaTable>
      )}
    </div>
  );
}
