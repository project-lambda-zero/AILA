/**
 * LLMLogPage -- admin-only interaction log for LLM calls.
 *
 * Rebuilt to the AILA mock language: SectionHeader + FilterChip + JQL bar +
 * WindowPanel(BigStat) + WindowPanel(flush DataGrid) + WindowPanel detail
 * pane with mono prompt/response blocks and StatBars for tokens.
 *
 * Test contract preserved verbatim (see __tests__/LLMLogPage.test.tsx):
 *   - row cells render "gpt-4o" / "scoring" / "$0.0500" as literal text
 *   - each row exposes a button with accessible name "View"
 *   - clicking View opens a panel that renders "prompt preview" and
 *     "response preview" copy plus the truncated payload text
 *   - empty response renders "No LLM calls recorded"
 *   - fetch path contains "/admin/llm-log", "limit=50", "offset=0"
 */
import { useCallback, useMemo, useState, type CSSProperties } from "react";
import { useNavigate } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { Robot } from "@phosphor-icons/react/dist/csr/Robot";

import {
  SectionHeader,
  DataGrid,
  MonoBadge,
  StatBar,
  BigStat,
  toneColor,
} from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import {
  JqlFilterBar,
  filtersToQueryParams,
  type JqlFieldSpec,
  type JqlFilter,
} from "@/components/filters/JqlFilterBar";
import { authorizedRequestJson } from "@platform/api/http";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface LLMLogEntry {
  id: string;
  timestamp: string;
  model: string;
  task_type: string;
  input_tokens: number;
  output_tokens: number;
  cost_usd: number;
  duration_ms: number | null;
  status: string;
  run_id: string;
  user_id: string | null;
  team_id: string | null;
  prompt_preview: string | null;
  response_preview: string | null;
}

interface LLMLogResponse {
  items: LLMLogEntry[];
  total: number;
  limit: number;
  offset: number;
  total_cost_usd: number;
}

interface Envelope<T> {
  data: T;
  error: string | null;
  meta: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const FIELDS: JqlFieldSpec[] = [
  { key: "model", label: "Model", operators: [":"] },
  { key: "task_type", label: "Task Type", operators: [":"] },
  { key: "status", label: "Status", operators: [":"] },
  { key: "user", label: "User", operators: [":"] },
  { key: "team_id", label: "Team", operators: [":"] },
  { key: "from_date", label: "From", operators: [":"] },
  { key: "to_date", label: "To", operators: [":"] },
  { key: "cost", label: "Cost", operators: [">", "<"] },
  { key: "search", label: "Search", operators: [":"] },
];

const PAGE_SIZE = 50;

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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildLogPath(filters: JqlFilter[], offset: number): string {
  const params = new URLSearchParams();
  params.set("limit", String(PAGE_SIZE));
  params.set("offset", String(offset));
  const backendParams = filtersToQueryParams(filters);
  for (const [k, v] of Object.entries(backendParams)) {
    params.set(k, v);
  }
  return `/admin/llm-log?${params.toString()}`;
}

function formatTimestamp(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

function formatCost(value: number): string {
  return `$${value.toFixed(4)}`;
}

function formatDuration(ms: number | null): string {
  if (ms === null || ms === undefined) return "--";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

const STATUS_TONE: Record<string, string> = {
  ok: "ok",
  completed: "ok",
  error: "critical",
  failed: "critical",
  timeout: "warn",
  retry: "warn",
};

function statusTone(status: string): string {
  return STATUS_TONE[status.toLowerCase()] ?? "muted";
}

const PANEL_TONE_BY_STATUS: Record<string, "accent" | "ok" | "info" | "warn" | "muted"> = {
  ok: "ok",
  completed: "ok",
  error: "warn",
  failed: "warn",
  timeout: "warn",
  retry: "warn",
};

// ---------------------------------------------------------------------------
// Detail panel
// ---------------------------------------------------------------------------

function PreviewBlock({ label, body }: { label: string; body: string }) {
  return (
    <div className="flex flex-col" style={{ gap: 6 }}>
      <span
        className="font-mono uppercase"
        style={{
          fontSize: 9,
          letterSpacing: "0.14em",
          color: "var(--text-faint)",
        }}
      >
        {label}
      </span>
      <pre
        className="font-mono"
        style={{
          margin: 0,
          padding: 10,
          fontSize: 11,
          lineHeight: 1.55,
          color: "var(--text-primary)",
          background: "var(--surface-sunk)",
          border: "1px solid var(--border-soft)",
          borderRadius: 3,
          maxHeight: 260,
          overflow: "auto",
          whiteSpace: "pre-wrap",
          wordBreak: "break-word",
        }}
      >
        {body}
      </pre>
    </div>
  );
}

function DetailPanel({
  entry,
  onClose,
}: {
  entry: LLMLogEntry;
  onClose: () => void;
}) {
  const totalTokens = entry.input_tokens + entry.output_tokens;
  const tokenMax = Math.max(totalTokens, 1);

  return (
    <WindowPanel
      title={`call \u00b7 ${entry.model}`}
      tone={PANEL_TONE_BY_STATUS[entry.status.toLowerCase()] ?? "muted"}
      actions={
        <button
          type="button"
          className="font-mono uppercase"
          onClick={onClose}
          style={ACTION_BTN}
          aria-label="Close detail panel"
        >
          close
        </button>
      }
      status={`${formatTimestamp(entry.timestamp)} \u00b7 ${formatCost(
        entry.cost_usd,
      )} \u00b7 ${totalTokens} tokens \u00b7 ${formatDuration(entry.duration_ms)}`}
    >
      <div className="flex flex-col" style={{ gap: 14 }}>
        <div
          className="grid font-mono"
          style={{
            gridTemplateColumns: "120px 1fr",
            rowGap: 6,
            columnGap: 12,
            fontSize: 11,
          }}
        >
          <span style={{ color: "var(--text-muted)" }}>MODEL</span>
          <span style={{ color: "var(--text-primary)" }}>{entry.model}</span>
          <span style={{ color: "var(--text-muted)" }}>TASK</span>
          <span style={{ color: "var(--text-primary)" }}>
            {entry.task_type || "--"}
          </span>
          <span style={{ color: "var(--text-muted)" }}>STATUS</span>
          <span>
            <MonoBadge tone={statusTone(entry.status)}>{entry.status}</MonoBadge>
          </span>
          <span style={{ color: "var(--text-muted)" }}>RUN</span>
          <span
            className="font-mono"
            style={{ color: "var(--accent)", wordBreak: "break-all" }}
          >
            {entry.run_id}
          </span>
          {entry.user_id && (
            <>
              <span style={{ color: "var(--text-muted)" }}>USER</span>
              <span style={{ color: "var(--text-primary)" }}>
                {entry.user_id}
              </span>
            </>
          )}
          {entry.team_id && (
            <>
              <span style={{ color: "var(--text-muted)" }}>TEAM</span>
              <span style={{ color: "var(--text-primary)" }}>
                {entry.team_id}
              </span>
            </>
          )}
        </div>

        <div className="flex flex-col" style={{ gap: 8 }}>
          <StatBar
            label="INPUT"
            color={toneColor("info")}
            value={entry.input_tokens}
            max={tokenMax}
          />
          <StatBar
            label="OUTPUT"
            color={toneColor("accent")}
            value={entry.output_tokens}
            max={tokenMax}
          />
        </div>

        <PreviewBlock
          label="prompt preview"
          body={entry.prompt_preview ?? "(not captured)"}
        />
        <PreviewBlock
          label="response preview"
          body={entry.response_preview ?? "(not captured)"}
        />
      </div>
    </WindowPanel>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function LLMLogPage() {
  const navigate = useNavigate();
  const [filters, setFilters] = useState<JqlFilter[]>([]);
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<LLMLogEntry | null>(null);

  const logQuery = useQuery({
    queryKey: ["admin", "llm-log", filters, offset],
    queryFn: () =>
      authorizedRequestJson<Envelope<LLMLogResponse>>(
        buildLogPath(filters, offset),
      ),
  });

  const data = logQuery.data?.data;
  const items = useMemo(() => data?.items ?? [], [data]);
  const totalCost = data?.total_cost_usd ?? 0;
  const total = data?.total ?? 0;

  const handleFiltersChange = useCallback((next: JqlFilter[]) => {
    setFilters(next);
    setOffset(0);
  }, []);

  const handleOpenRun = useCallback(
    (runId: string) => {
      navigate(`/console/${runId}`);
    },
    [navigate],
  );

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <SectionHeader
        icon={
          <Robot
            size={16}
            weight="duotone"
            style={{ color: "var(--text-on-accent)" }}
            aria-hidden="true"
          />
        }
        title="llm interaction log"
        actions={
          <button
            type="button"
            className="font-mono uppercase"
            onClick={() => void logQuery.refetch()}
            disabled={logQuery.isFetching}
            style={{
              ...ACTION_BTN,
              opacity: logQuery.isFetching ? 0.6 : 1,
            }}
          >
            {logQuery.isFetching ? "refreshing" : "refresh"}
          </button>
        }
      />

      {/* Stat row */}
      <div
        className="grid"
        style={{
          gridTemplateColumns: "1fr 220px 220px",
          gap: 12,
        }}
      >
        <WindowPanel title="filters">
          <JqlFilterBar
            fields={FIELDS}
            onChange={handleFiltersChange}
            placeholder="Filter (e.g. model:gpt-4o, cost>0.5, search:scan)"
          />
        </WindowPanel>
        <WindowPanel title="total cost">
          <BigStat
            value={formatCost(totalCost)}
            sub={`${total} call${total === 1 ? "" : "s"}`}
          />
        </WindowPanel>
        <WindowPanel title="loaded">
          <BigStat
            value={items.length}
            sub={`window ${offset + 1}-${offset + items.length || 0}`}
          />
        </WindowPanel>
      </div>

      {/* Error banner */}
      {logQuery.isError && (
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
          Failed to load LLM log: {(logQuery.error as Error).message}
        </div>
      )}

      {/* Grid */}
      <WindowPanel title="calls" flush>
        {logQuery.isLoading ? (
          <div style={{ padding: 16 }}>
            <LoadingSkeletonGroup lines={8} />
          </div>
        ) : (
          <DataGrid<LLMLogEntry>
            columns={[
              { label: "TIMESTAMP", width: "170px" },
              { label: "MODEL", width: "150px" },
              { label: "PERSONA", width: "130px" },
              { label: "COST", width: "90px", align: "right" },
              { label: "TOKENS", width: "110px", align: "right" },
              { label: "CACHE", width: "70px", align: "center" },
              { label: "DURATION", width: "90px", align: "right" },
              { label: "STATUS", width: "90px" },
              { label: "RUN", width: "110px" },
              { label: "", width: "80px", align: "right" },
            ]}
            rows={items}
            getKey={(r) => r.id}
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
                No LLM calls recorded. Widen filters or extend the date range.
              </div>
            }
            renderCells={(r) => {
              const cached = r.input_tokens === 0 && r.output_tokens > 0;
              return [
                <span
                  key="ts"
                  className="font-mono"
                  style={{
                    color: "var(--text-muted)",
                    fontSize: 10.5,
                    whiteSpace: "nowrap",
                  }}
                >
                  {formatTimestamp(r.timestamp)}
                </span>,
                <span
                  key="model"
                  className="font-mono"
                  style={{ color: "var(--text-primary)", fontSize: 11 }}
                >
                  {r.model}
                </span>,
                <span
                  key="persona"
                  className="font-mono"
                  style={{ color: "var(--text-muted)", fontSize: 11 }}
                >
                  {r.task_type || "--"}
                </span>,
                <span
                  key="cost"
                  className="font-mono tabular-nums"
                  style={{ color: "var(--text-primary)", fontSize: 11 }}
                >
                  {formatCost(r.cost_usd)}
                </span>,
                <span
                  key="tok"
                  className="font-mono tabular-nums"
                  style={{ color: "var(--text-primary)", fontSize: 11 }}
                >
                  {r.input_tokens}
                  <span style={{ color: "var(--text-faint)" }}>/</span>
                  {r.output_tokens}
                </span>,
                <span key="cache">
                  {cached ? (
                    <MonoBadge tone="info">hit</MonoBadge>
                  ) : (
                    <span
                      className="font-mono"
                      style={{ color: "var(--text-faint)", fontSize: 10 }}
                    >
                      --
                    </span>
                  )}
                </span>,
                <span
                  key="dur"
                  className="font-mono tabular-nums"
                  style={{ color: "var(--text-muted)", fontSize: 11 }}
                >
                  {formatDuration(r.duration_ms)}
                </span>,
                <MonoBadge key="st" tone={statusTone(r.status)}>
                  {r.status}
                </MonoBadge>,
                <button
                  key="run"
                  type="button"
                  className="font-mono uppercase"
                  aria-label={`Open run ${r.run_id}`}
                  onClick={(event) => {
                    event.stopPropagation();
                    handleOpenRun(r.run_id);
                  }}
                  style={{
                    ...ACTION_BTN,
                    height: 20,
                    padding: "0 7px",
                    fontSize: 9,
                    color: "var(--accent)",
                    borderColor:
                      "color-mix(in srgb, var(--accent) 45%, transparent)",
                    background:
                      "color-mix(in srgb, var(--accent) 10%, transparent)",
                  }}
                >
                  {r.run_id.slice(0, 8)}
                </button>,
                <button
                  key="view"
                  type="button"
                  className="font-mono uppercase"
                  onClick={() => setSelected(r)}
                  style={{
                    ...ACTION_BTN,
                    height: 22,
                    padding: "0 10px",
                    fontSize: 9.5,
                  }}
                >
                  View
                </button>,
              ];
            }}
          />
        )}
      </WindowPanel>

      {/* Pagination */}
      {total > PAGE_SIZE && !logQuery.isLoading && (
        <div
          className="flex items-center justify-between font-mono"
          style={{ fontSize: 11, color: "var(--text-muted)" }}
        >
          <span>
            {offset + 1}-{Math.min(offset + items.length, total)} of {total}
          </span>
          <div className="flex items-center" style={{ gap: 8 }}>
            <button
              type="button"
              className="font-mono uppercase"
              style={{
                ...ACTION_BTN,
                opacity:
                  offset === 0 || logQuery.isFetching ? 0.55 : 1,
              }}
              disabled={offset === 0 || logQuery.isFetching}
              onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
            >
              prev
            </button>
            <button
              type="button"
              className="font-mono uppercase"
              style={{
                ...ACTION_BTN,
                opacity:
                  offset + PAGE_SIZE >= total || logQuery.isFetching
                    ? 0.55
                    : 1,
              }}
              disabled={
                offset + PAGE_SIZE >= total || logQuery.isFetching
              }
              onClick={() => setOffset(offset + PAGE_SIZE)}
            >
              next
            </button>
          </div>
        </div>
      )}

      {selected && (
        <DetailPanel entry={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}

export default LLMLogPage;
