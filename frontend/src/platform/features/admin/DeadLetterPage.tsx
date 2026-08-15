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
import { useMemo, useState, type CSSProperties } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Skull } from "@phosphor-icons/react/dist/csr/Skull";

import {
  SectionHeader,
  DataGrid,
  MonoBadge,
  BigStat,
} from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
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
// Mock-styled button + input primitives
// ---------------------------------------------------------------------------

const ACTION_BTN: CSSProperties = {
  height: 24,
  padding: "0 10px",
  fontSize: 9.5,
  letterSpacing: "0.08em",
  borderRadius: 3,
  cursor: "pointer",
  color: "var(--text-primary)",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
};

const INPUT_STYLE: CSSProperties = {
  height: 28,
  padding: "0 10px",
  fontSize: 11,
  color: "var(--text-primary)",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  outline: "none",
};

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "--";
  return new Date(value).toLocaleString();
}

// ---------------------------------------------------------------------------
// Requeue button + per-row discard placeholder (mock action pair)
// ---------------------------------------------------------------------------

interface RowActionsProps {
  taskId: string;
  onRequeue: (taskId: string) => Promise<RequeueResponse>;
  isPending: boolean;
}

function RowActions({ taskId, onRequeue, isPending }: RowActionsProps) {
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleRequeue() {
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

  const busy = submitting || isPending;

  return (
    <div className="flex flex-col items-end" style={{ gap: 4 }}>
      <div className="flex items-center" style={{ gap: 6 }}>
        <button
          type="button"
          className="font-mono uppercase"
          onClick={handleRequeue}
          disabled={busy}
          style={{
            ...ACTION_BTN,
            opacity: busy ? 0.55 : 1,
            cursor: busy ? "not-allowed" : "pointer",
          }}
        >
          {submitting ? "requeueing" : "requeue"}
        </button>
        <button
          type="button"
          className="font-mono uppercase"
          title="Discard is a placeholder mock action -- no backend endpoint yet."
          style={{
            ...ACTION_BTN,
            color: "var(--text-faint)",
            opacity: 0.6,
            cursor: "not-allowed",
          }}
          disabled
        >
          discard
        </button>
      </div>
      {error && (
        <span
          className="font-mono"
          style={{
            color: "var(--status-warn)",
            fontSize: 10,
            maxWidth: 200,
            textAlign: "right",
          }}
        >
          {error}
        </span>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Expandable error panel
// ---------------------------------------------------------------------------

function ErrorDetailPanel({
  entry,
  onClose,
}: {
  entry: DeadLetterEntry;
  onClose: () => void;
}) {
  return (
    <WindowPanel
      title={`dead-letter · ${entry.task_id.slice(0, 8)}`}
      tone="warn"
      actions={
        <button
          type="button"
          className="font-mono uppercase"
          onClick={onClose}
          style={ACTION_BTN}
        >
          close
        </button>
      }
    >
      <div className="flex flex-col" style={{ gap: 12 }}>
        <div
          className="grid font-mono"
          style={{
            gridTemplateColumns: "120px 1fr",
            rowGap: 6,
            columnGap: 12,
            fontSize: 11,
          }}
        >
          <span style={{ color: "var(--text-muted)" }}>TASK ID</span>
          <span style={{ color: "var(--text-primary)", wordBreak: "break-all" }}>
            {entry.task_id}
          </span>
          <span style={{ color: "var(--text-muted)" }}>TRACK</span>
          <span>
            <MonoBadge tone="muted">{entry.track}</MonoBadge>
          </span>
          <span style={{ color: "var(--text-muted)" }}>FUNCTION</span>
          <span
            style={{ color: "var(--text-primary)", wordBreak: "break-all" }}
          >
            {entry.fn_path || entry.fn_module || "--"}
          </span>
          <span style={{ color: "var(--text-muted)" }}>USER</span>
          <span style={{ color: "var(--text-primary)" }}>
            {entry.user_id || "--"}
          </span>
          <span style={{ color: "var(--text-muted)" }}>ATTEMPTS</span>
          <span
            className="tabular-nums"
            style={{ color: "var(--text-primary)" }}
          >
            {entry.attempts}
          </span>
          <span style={{ color: "var(--text-muted)" }}>DEAD-LETTERED</span>
          <span style={{ color: "var(--text-primary)" }}>
            {formatTimestamp(entry.dead_lettered_at)}
          </span>
          <span style={{ color: "var(--text-muted)" }}>EXCEPTION</span>
          <span>
            <MonoBadge tone="critical">
              {entry.exception_class || "Unknown"}
            </MonoBadge>
          </span>
        </div>

        <div className="flex flex-col" style={{ gap: 6 }}>
          <span
            className="font-mono uppercase"
            style={{
              fontSize: 9,
              letterSpacing: "0.14em",
              color: "var(--text-faint)",
            }}
          >
            error
          </span>
          <pre
            className="font-mono"
            style={{
              margin: 0,
              padding: 10,
              fontSize: 11,
              lineHeight: 1.5,
              color: "var(--status-warn)",
              background:
                "color-mix(in srgb, var(--status-warn) 8%, transparent)",
              border:
                "1px solid color-mix(in srgb, var(--status-warn) 32%, transparent)",
              borderRadius: 3,
              maxHeight: 320,
              overflow: "auto",
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
            }}
          >
            {entry.error || "(no error payload captured)"}
          </pre>
        </div>
      </div>
    </WindowPanel>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function DeadLetterPage() {
  const queryClient = useQueryClient();
  const [trackFilter, setTrackFilter] = useState("");
  const [selected, setSelected] = useState<DeadLetterEntry | null>(null);

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

  async function handleRequeue(taskId: string): Promise<RequeueResponse> {
    const res = await requeueMutation.mutateAsync(taskId);
    return res.data;
  }

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <SectionHeader
        icon={
          <Skull
            size={16}
            weight="duotone"
            style={{ color: "var(--text-on-accent)" }}
            aria-hidden="true"
          />
        }
        title="dead letter queue"
        actions={
          <button
            type="button"
            className="font-mono uppercase"
            onClick={() => void entriesQuery.refetch()}
            disabled={entriesQuery.isFetching}
            style={{
              ...ACTION_BTN,
              opacity: entriesQuery.isFetching ? 0.6 : 1,
            }}
          >
            {entriesQuery.isFetching ? "refreshing" : "refresh"}
          </button>
        }
      />

      {/* Stat panels */}
      <div
        className="grid"
        style={{
          gridTemplateColumns: "repeat(3, minmax(0, 1fr))",
          gap: 12,
        }}
      >
        <WindowPanel title="dead-lettered" tone="warn">
          <BigStat
            value={entries.length}
            sub={trackFilter ? `track: ${trackFilter}` : "all tracks"}
          />
        </WindowPanel>
        <WindowPanel title="distinct tracks" tone="muted">
          <BigStat value={tracks.length} sub="at least one failure" />
        </WindowPanel>
        <WindowPanel title="track filter" tone="muted">
          <div className="flex flex-col" style={{ gap: 6 }}>
            <input
              aria-label="Track filter"
              type="text"
              value={trackFilter}
              onChange={(e) => setTrackFilter(e.target.value)}
              placeholder="vulnerability"
              className="font-mono"
              style={INPUT_STYLE}
            />
            <span
              className="font-mono"
              style={{ color: "var(--text-faint)", fontSize: 10 }}
            >
              empty scans all tracks
            </span>
          </div>
        </WindowPanel>
      </div>

      {/* Error banner */}
      {entriesQuery.isError && (
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
          Failed to load dead-letter entries:{" "}
          {(entriesQuery.error as Error).message}
        </div>
      )}

      {/* Grid */}
      <WindowPanel title="failed jobs" flush>
        {entriesQuery.isLoading ? (
          <div style={{ padding: 16 }}>
            <LoadingSkeletonGroup lines={6} />
          </div>
        ) : (
          <DataGrid<DeadLetterEntry>
            columns={[
              { label: "TASK", width: "120px" },
              { label: "TRACK", width: "120px" },
              { label: "FUNCTION", width: "1.4fr" },
              { label: "EXCEPTION", width: "160px" },
              { label: "ERROR", width: "2fr" },
              { label: "ATTEMPTS", width: "70px", align: "right" },
              { label: "DEAD-LETTERED", width: "160px" },
              { label: "ACTIONS", width: "200px", align: "right" },
            ]}
            rows={entries}
            getKey={(r) => r.task_id}
            onRowClick={(r) => setSelected(r)}
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
                no dead-lettered tasks. a clean queue is a healthy queue.
              </div>
            }
            renderCells={(r) => [
              <code
                key="tid"
                className="font-mono"
                style={{ color: "var(--text-muted)", fontSize: 10 }}
                title={r.task_id}
              >
                {r.task_id.slice(0, 8)}
                {"\u2026"}
              </code>,
              <MonoBadge key="tr" tone="muted">
                {r.track}
              </MonoBadge>,
              <span
                key="fn"
                className="font-mono truncate"
                title={r.fn_path}
                style={{ color: "var(--text-primary)", fontSize: 11 }}
              >
                {r.fn_path || r.fn_module || "--"}
              </span>,
              <MonoBadge key="ex" tone="critical">
                {r.exception_class || "Unknown"}
              </MonoBadge>,
              <span
                key="err"
                className="font-mono truncate"
                title={r.error}
                style={{
                  color: "var(--text-muted)",
                  fontSize: 10.5,
                  display: "block",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                {r.error || "--"}
              </span>,
              <span
                key="att"
                className="font-mono tabular-nums"
                style={{ color: "var(--text-primary)", fontSize: 11 }}
              >
                {r.attempts}
              </span>,
              <span
                key="ts"
                className="font-mono"
                style={{
                  color: "var(--text-muted)",
                  fontSize: 10.5,
                  whiteSpace: "nowrap",
                }}
              >
                {formatTimestamp(r.dead_lettered_at)}
              </span>,
              <RowActions
                key="act"
                taskId={r.task_id}
                onRequeue={handleRequeue}
                isPending={requeueMutation.isPending}
              />,
            ]}
          />
        )}
      </WindowPanel>

      {selected && (
        <ErrorDetailPanel
          entry={selected}
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  );
}
