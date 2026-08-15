/**
 * AuditLogsPage -- admin audit trail with filterable AilaTable and CSV/JSON export.
 *
 * ADM-01: Filterable, sortable audit log table with server-side filtering
 * (run_id, stage, action, status, user_id, since, until) and client-side
 * sort/pagination via AilaTable. Exports current page as CSV or JSON.
 *
 * Fetches up to 250 events per server request (backend max). AilaTable
 * handles local sort/filter/pagination within the fetched set.
 */
import { useState, useCallback, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { type ColumnDef } from "@tanstack/react-table";
import { Download } from "@phosphor-icons/react/dist/csr/Download";
import { ArrowClockwise } from "@phosphor-icons/react/dist/csr/ArrowClockwise";
import { ClipboardText } from "@phosphor-icons/react/dist/csr/ClipboardText";
import { X as XIcon } from "@phosphor-icons/react/dist/csr/X";

import { AilaCard } from "@/components/aila/AilaCard";
import { AilaTable } from "@/components/aila/AilaTable";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { EmptyState } from "@/components/aila/EmptyState";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { authorizedRequestJson } from "@platform/api/http";
import {
  JqlFilterBar,
  filtersToQueryParams,
  type JqlFieldSpec,
  type JqlFilter,
} from "@/components/filters/JqlFilterBar";
import { AuditDetailRenderer } from "./AuditDetailRenderer";
import { AuditSealsTab } from "./AuditSealsTab";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { usePreferences } from "@/providers/PreferencesProvider";
import { SavedViews } from "@platform/features/saved-views";
import { Plus } from "@phosphor-icons/react/dist/csr/Plus";
import { Trash } from "@phosphor-icons/react/dist/csr/Trash";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface AuditEvent {
  id: number | null;
  run_id: string;
  stage: string;
  action: string;
  status: string;
  target: string;
  user_id: string;
  details: Record<string, unknown>;
  created_at: string | null;
}

interface AuditListResponse {
  total: number;
  page: number;
  page_size: number;
  pages: number;
  items: AuditEvent[];
}

interface AuditFilters {
  runId: string;
  stage: string;
  action: string;
  status: string;
  userId: string;
  since: string;
  until: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const EMPTY_FILTERS: AuditFilters = {
  runId: "",
  stage: "",
  action: "",
  status: "",
  userId: "",
  since: "",
  until: "",
};

const SERVER_PAGE_SIZE = 250; // backend max

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function buildAuditPath(filters: AuditFilters): string {
  const params = new URLSearchParams();
  if (filters.runId) params.set("run_id", filters.runId);
  if (filters.stage) params.set("stage", filters.stage);
  if (filters.action) params.set("action", filters.action);
  if (filters.status) params.set("status", filters.status);
  if (filters.userId) params.set("user_id", filters.userId);
  if (filters.since) params.set("since", filters.since);
  if (filters.until) params.set("until", filters.until);
  params.set("page", "1");
  params.set("page_size", String(SERVER_PAGE_SIZE));
  const qs = params.toString();
  return qs ? `/audit/events?${qs}` : "/audit/events";
}

// JQL filter bar field specs -- names match the `AuditFilters` query keys so
// `jqlToAuditFilters()` can translate one to the other without a lookup table.
const AUDIT_JQL_FIELDS: JqlFieldSpec[] = [
  { key: "run_id", label: "Run ID", operators: [":"] },
  { key: "stage", label: "Stage", operators: [":"] },
  { key: "action", label: "Action", operators: [":"] },
  { key: "status", label: "Status", operators: [":"] },
  { key: "user_id", label: "User", operators: [":"] },
  { key: "since", label: "Since", operators: [":"] },
  { key: "until", label: "Until", operators: [":"] },
  { key: "search", label: "Search", operators: [":"] },
];

/** Translate JQL filter chips into the legacy AuditFilters shape. */
function jqlToAuditFilters(filters: JqlFilter[]): AuditFilters {
  const backend = filtersToQueryParams(filters);
  return {
    runId: backend.run_id ?? "",
    stage: backend.stage ?? "",
    action: backend.action ?? "",
    status: backend.status ?? "",
    userId: backend.user_id ?? "",
    since: backend.since ?? "",
    until: backend.until ?? "",
  };
}

function formatTimestamp(value: string | null): string {
  if (!value) return "--";
  return new Date(value).toLocaleString();
}

function auditStatusSeverity(
  status: string,
): "info" | "critical" | "medium" | "neutral" {
  const s = status.toLowerCase();
  if (s === "completed") return "info";
  if (s === "failed") return "critical";
  if (s === "running") return "medium";
  return "neutral";
}

// ---------------------------------------------------------------------------
// Export helpers
// ---------------------------------------------------------------------------

function escapeCsvCell(value: string): string {
  if (value.includes(",") || value.includes('"') || value.includes("\n")) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

function exportAsCsv(items: AuditEvent[]): void {
  const headers = ["run_id", "stage", "action", "status", "user_id", "target", "created_at"];
  const rows = items.map((item) =>
    [
      item.run_id,
      item.stage,
      item.action,
      item.status,
      item.user_id,
      item.target ?? "",
      item.created_at ?? "",
    ]
      .map(escapeCsvCell)
      .join(","),
  );
  const csv = [headers.join(","), ...rows].join("\n");
  triggerDownload(new Blob([csv], { type: "text/csv" }), "audit-logs.csv");
}

function exportAsJson(items: AuditEvent[]): void {
  const json = JSON.stringify(items, null, 2);
  triggerDownload(
    new Blob([json], { type: "application/json" }),
    "audit-logs.json",
  );
}

function triggerDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------------------
// Column definitions
// ---------------------------------------------------------------------------

const AUDIT_COLUMNS: ColumnDef<AuditEvent>[] = [
  {
    id: "run_id",
    header: "Run ID",
    accessorKey: "run_id",
    cell: ({ getValue }) => (
      <span className="font-mono text-xs text-text-muted truncate max-w-[120px] block" title={String(getValue())}>
        {String(getValue()).slice(0, 8)}…
      </span>
    ),
  },
  {
    id: "stage",
    header: "Stage",
    accessorKey: "stage",
    cell: ({ getValue }) => (
      <span className="font-mono text-xs text-text">{String(getValue())}</span>
    ),
  },
  {
    id: "action",
    header: "Action",
    accessorKey: "action",
    cell: ({ getValue }) => (
      <span className="font-mono text-xs text-text">{String(getValue())}</span>
    ),
  },
  {
    id: "status",
    header: "Status",
    accessorKey: "status",
    cell: ({ getValue }) => {
      const s = String(getValue());
      return (
        <AilaBadge severity={auditStatusSeverity(s)} size="sm">
          {s}
        </AilaBadge>
      );
    },
  },
  {
    id: "user_id",
    header: "User",
    accessorKey: "user_id",
    cell: ({ getValue }) => (
      <span className="font-mono text-xs text-text">{String(getValue())}</span>
    ),
  },
  {
    id: "target",
    header: "Target",
    accessorKey: "target",
    cell: ({ getValue }) => {
      const v = String(getValue() ?? "");
      return (
        <span className="font-mono text-xs text-text-muted">{v || "--"}</span>
      );
    },
  },
  {
    id: "created_at",
    header: "Timestamp",
    accessorKey: "created_at",
    cell: ({ getValue }) => (
      <span className="font-mono text-xs text-text-muted whitespace-nowrap">
        {formatTimestamp(getValue() as string | null)}
      </span>
    ),
  },
];

/**
 * Extend AUDIT_COLUMNS with a final "Details" column that opens the
 * AuditDetailRenderer panel for the clicked event. Defined as a builder so
 * the onSelect callback is closure-captured cleanly.
 */
function AUDIT_COLUMNS_WITH_DETAILS(
  onSelect: (event: AuditEvent) => void,
): ColumnDef<AuditEvent>[] {
  return [
    ...AUDIT_COLUMNS,
    {
      id: "details",
      header: "",
      cell: ({ row }) => (
        <Button
          type="button"
          size="sm"
          variant="outline"
          className="h-6 px-2 font-mono text-[10px]"
          onClick={() => onSelect(row.original)}
        >
          View
        </Button>
      ),
    },
  ];
}

// ---------------------------------------------------------------------------
// Filter form
// ---------------------------------------------------------------------------

interface FilterFormProps {
  draft: AuditFilters;
  onDraftChange: (patch: Partial<AuditFilters>) => void;
  onApply: () => void;
  onClear: () => void;
  isFetching: boolean;
}

function FilterForm({
  draft,
  onDraftChange,
  onApply,
  onClear,
  isFetching,
}: FilterFormProps) {
  return (
    <AilaCard variant="elevated" padding="md"><h2 className="font-mono text-sm font-semibold text-text mb-3">
      Filters
    </h2>
    <form
      className="flex flex-col gap-4"
      onSubmit={(e) => {
        e.preventDefault();
        onApply();
      }}
    >
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <div className="flex flex-col gap-1">
          <label className="font-mono text-xs text-text-muted" htmlFor="af-run-id">
            Run ID
          </label>
          <Input
            id="af-run-id"
            value={draft.runId}
            onChange={(e) => onDraftChange({ runId: e.target.value })}
            placeholder="50b5b278-1b3d-…"
            className="font-mono text-xs"
          />
        </div>
    
        <div className="flex flex-col gap-1">
          <label className="font-mono text-xs text-text-muted" htmlFor="af-stage">
            Stage
          </label>
          <Input
            id="af-stage"
            value={draft.stage}
            onChange={(e) => onDraftChange({ stage: e.target.value })}
            placeholder="task,report_lookup"
            className="font-mono text-xs"
          />
        </div>
    
        <div className="flex flex-col gap-1">
          <label className="font-mono text-xs text-text-muted" htmlFor="af-action">
            Action
          </label>
          <Input
            id="af-action"
            value={draft.action}
            onChange={(e) => onDraftChange({ action: e.target.value })}
            placeholder="scan.start"
            className="font-mono text-xs"
          />
        </div>
    
        <div className="flex flex-col gap-1">
          <label className="font-mono text-xs text-text-muted" htmlFor="af-status">
            Status
          </label>
          <Input
            id="af-status"
            value={draft.status}
            onChange={(e) => onDraftChange({ status: e.target.value })}
            placeholder="completed,failed"
            className="font-mono text-xs"
          />
        </div>
    
        <div className="flex flex-col gap-1">
          <label className="font-mono text-xs text-text-muted" htmlFor="af-user">
            User ID
          </label>
          <Input
            id="af-user"
            value={draft.userId}
            onChange={(e) => onDraftChange({ userId: e.target.value })}
            placeholder="system"
            className="font-mono text-xs"
          />
        </div>
      </div>
    
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div className="flex flex-col gap-1">
          <label className="font-mono text-xs text-text-muted" htmlFor="af-since">
            Since (ISO 8601)
          </label>
          <Input
            id="af-since"
            type="datetime-local"
            value={draft.since}
            onChange={(e) => onDraftChange({ since: e.target.value })}
            className="font-mono text-xs"
          />
        </div>
    
        <div className="flex flex-col gap-1">
          <label className="font-mono text-xs text-text-muted" htmlFor="af-until">
            Until (ISO 8601)
          </label>
          <Input
            id="af-until"
            type="datetime-local"
            value={draft.until}
            onChange={(e) => onDraftChange({ until: e.target.value })}
            className="font-mono text-xs"
          />
        </div>
      </div>
    
      <div className="flex gap-2">
        <Button type="submit" size="sm" disabled={isFetching}>
          {isFetching ? "Loading…" : "Apply Filters"}
        </Button>
        <Button
          type="button"
          size="sm"
          variant="outline"
          onClick={onClear}
        >
          Clear
        </Button>
      </div>
    </form></AilaCard>
  );
}

// ---------------------------------------------------------------------------
// Advanced filter builder
//
// Additive to the existing JQL bar / legacy form. Each row targets one of the
// server-supported comma-OR fields (action / status / user_id / stage) and
// the operator adds values as chips within that row. Multiple rows on the
// same field merge (a chip added on any row for `stage` OR-joins with every
// other `stage` chip -- matches the backend semantics for a single query
// param). A dedicated since/until row drives the date range.
// ---------------------------------------------------------------------------

type BuilderField = "action" | "status" | "user_id" | "stage";

interface BuilderConditionRow {
  /** stable client id; not persisted */
  rowId: string;
  field: BuilderField;
  values: string[];
}

interface AdvancedBuilderState {
  conditions: BuilderConditionRow[];
  since: string;
  until: string;
}

const EMPTY_BUILDER: AdvancedBuilderState = {
  conditions: [],
  since: "",
  until: "",
};

const BUILDER_FIELDS: readonly { key: BuilderField; label: string; placeholder: string }[] = [
  { key: "action", label: "Action", placeholder: "scan.start" },
  { key: "status", label: "Status", placeholder: "completed, failed" },
  { key: "user_id", label: "User", placeholder: "system, admin" },
  { key: "stage", label: "Stage", placeholder: "task, report_lookup" },
];

/** Merge a builder state into the AuditFilters shape driving GET /audit/events. */
function builderToAuditFilters(state: AdvancedBuilderState): AuditFilters {
  const collected: Record<BuilderField, string[]> = {
    action: [],
    status: [],
    user_id: [],
    stage: [],
  };
  for (const row of state.conditions) {
    for (const raw of row.values) {
      const trimmed = raw.trim();
      if (trimmed && !collected[row.field].includes(trimmed)) {
        collected[row.field].push(trimmed);
      }
    }
  }
  return {
    runId: "",
    stage: collected.stage.join(","),
    action: collected.action.join(","),
    status: collected.status.join(","),
    userId: collected.user_id.join(","),
    since: state.since,
    until: state.until,
  };
}

function newBuilderRow(field: BuilderField = "action"): BuilderConditionRow {
  return {
    rowId:
      typeof crypto !== "undefined" && "randomUUID" in crypto
        ? crypto.randomUUID()
        : `row-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    field,
    values: [],
  };
}

interface AdvancedFilterBuilderProps {
  state: AdvancedBuilderState;
  onChange: (next: AdvancedBuilderState) => void;
  onApply: () => void;
  onClear: () => void;
  isFetching: boolean;
}

function AdvancedFilterBuilder({
  state,
  onChange,
  onApply,
  onClear,
  isFetching,
}: AdvancedFilterBuilderProps) {
  const [draftValues, setDraftValues] = useState<Record<string, string>>({});

  function updateRow(rowId: string, patch: Partial<BuilderConditionRow>) {
    onChange({
      ...state,
      conditions: state.conditions.map((row) =>
        row.rowId === rowId ? { ...row, ...patch } : row,
      ),
    });
  }

  function commitDraft(rowId: string) {
    const raw = draftValues[rowId] ?? "";
    // Support paste-in comma-separated values in one keystroke: split, trim,
    // dedupe, and append to whichever row we're editing.
    const additions = raw
      .split(",")
      .map((v) => v.trim())
      .filter(Boolean);
    if (additions.length === 0) return;
    const row = state.conditions.find((r) => r.rowId === rowId);
    if (!row) return;
    const merged = [...row.values];
    for (const value of additions) {
      if (!merged.includes(value)) merged.push(value);
    }
    updateRow(rowId, { values: merged });
    setDraftValues((prev) => ({ ...prev, [rowId]: "" }));
  }

  return (
    <AilaCard variant="elevated" padding="md">
      <div className="flex items-center justify-between mb-3">
        <h2 className="font-mono text-sm font-semibold text-text">
          Advanced Filter Builder
        </h2>
        <div className="flex gap-2">
          <Button
            type="button"
            size="sm"
            variant="outline"
            className="gap-1.5"
            onClick={() =>
              onChange({
                ...state,
                conditions: [...state.conditions, newBuilderRow()],
              })
            }
          >
            <Plus className="h-3.5 w-3.5" />
            Add condition
          </Button>
        </div>
      </div>

      <div className="flex flex-col gap-2">
        {state.conditions.length === 0 && (
          <p className="font-mono text-xs text-text-muted">
            No conditions yet. Add a condition to filter by action, status, user, or stage.
          </p>
        )}
        {state.conditions.map((row, index) => {
          const spec = BUILDER_FIELDS.find((f) => f.key === row.field) ?? BUILDER_FIELDS[0];
          const draft = draftValues[row.rowId] ?? "";
          const fieldSelectId = `builder-field-${row.rowId}`;
          const valueInputId = `builder-value-${row.rowId}`;
          return (
            <div
              key={row.rowId}
              className="flex flex-wrap items-start gap-2 border border-border rounded-sharp-md p-2 bg-surface"
            >
              <div className="flex flex-col gap-1">
                <label
                  className="font-mono text-[10px] text-text-muted uppercase tracking-wider"
                  htmlFor={fieldSelectId}
                >
                  {index === 0 ? "Where" : "And"}
                </label>
                <select
                  id={fieldSelectId}
                  value={row.field}
                  onChange={(e) =>
                    updateRow(row.rowId, {
                      field: e.target.value as BuilderField,
                    })
                  }
                  className="h-8 rounded-sharp border border-border bg-base px-2 font-mono text-xs text-text outline-none focus:border-border-hover transition-colors"
                >
                  {BUILDER_FIELDS.map((field) => (
                    <option key={field.key} value={field.key}>
                      {field.label}
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex-1 min-w-[160px] flex flex-col gap-1">
                <label
                  className="font-mono text-[10px] text-text-muted uppercase tracking-wider"
                  htmlFor={valueInputId}
                >
                  Any of (comma-OR)
                </label>
                <div className="flex flex-wrap items-center gap-1.5 min-h-[2rem] border border-border rounded-sharp bg-base px-2 py-1">
                  {row.values.map((value) => (
                    <span
                      key={value}
                      className="inline-flex items-center gap-1 px-1.5 py-0.5 bg-accent/10 border border-accent/30 rounded-sharp text-accent font-mono text-[11px]"
                    >
                      {value}
                      <button
                        type="button"
                        onClick={() =>
                          updateRow(row.rowId, {
                            values: row.values.filter((v) => v !== value),
                          })
                        }
                        className="text-accent/70 hover:text-accent"
                        aria-label={`Remove ${value}`}
                      >
                        <XIcon className="h-3 w-3" />
                      </button>
                    </span>
                  ))}
                  <input
                    id={valueInputId}
                    value={draft}
                    onChange={(e) =>
                      setDraftValues((prev) => ({
                        ...prev,
                        [row.rowId]: e.target.value,
                      }))
                    }
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === ",") {
                        e.preventDefault();
                        commitDraft(row.rowId);
                      } else if (
                        e.key === "Backspace" &&
                        draft === "" &&
                        row.values.length > 0
                      ) {
                        updateRow(row.rowId, {
                          values: row.values.slice(0, -1),
                        });
                      }
                    }}
                    onBlur={() => commitDraft(row.rowId)}
                    placeholder={spec.placeholder}
                    className="flex-1 min-w-[80px] bg-transparent outline-none font-mono text-xs text-text placeholder:text-text-muted"
                  />
                </div>
              </div>
              <button
                type="button"
                onClick={() =>
                  onChange({
                    ...state,
                    conditions: state.conditions.filter(
                      (r) => r.rowId !== row.rowId,
                    ),
                  })
                }
                className="mt-5 text-text-muted hover:text-critical transition-colors"
                aria-label={`Remove condition ${index + 1}`}
                title="Remove condition"
              >
                <Trash size={14} />
              </button>
            </div>
          );
        })}

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 mt-1">
          <div className="flex flex-col gap-1">
            <label
              className="font-mono text-[10px] text-text-muted uppercase tracking-wider"
              htmlFor="builder-since"
            >
              Since (ISO 8601)
            </label>
            <Input
              id="builder-since"
              type="datetime-local"
              value={state.since}
              onChange={(e) => onChange({ ...state, since: e.target.value })}
              className="font-mono text-xs"
            />
          </div>
          <div className="flex flex-col gap-1">
            <label
              className="font-mono text-[10px] text-text-muted uppercase tracking-wider"
              htmlFor="builder-until"
            >
              Until (ISO 8601)
            </label>
            <Input
              id="builder-until"
              type="datetime-local"
              value={state.until}
              onChange={(e) => onChange({ ...state, until: e.target.value })}
              className="font-mono text-xs"
            />
          </div>
        </div>

        <div className="flex gap-2 mt-2">
          <Button type="button" size="sm" onClick={onApply} disabled={isFetching}>
            {isFetching ? "Loading…" : "Apply Builder"}
          </Button>
          <Button type="button" size="sm" variant="outline" onClick={onClear}>
            Clear Builder
          </Button>
        </div>
      </div>
    </AilaCard>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

/**
 * Serialized shape stored under entity_type='audit' in /saved-filters.
 * `mode` records which UI produced the preset so applying it restores the
 * matching input surface; `filters` is always the merged AuditFilters that
 * drives GET /audit/events, and `builder` is the optional builder scaffold
 * for round-tripping the chip UI.
 */
interface AuditSavedViewState {
  mode: "jql" | "form" | "builder";
  filters: AuditFilters;
  builder?: AdvancedBuilderState;
}

export function AuditLogsPage() {
  const [draftFilters, setDraftFilters] = useState<AuditFilters>(EMPTY_FILTERS);
  const [activeFilters, setActiveFilters] = useState<AuditFilters>(EMPTY_FILTERS);
  const [filterMode, setFilterMode] = useState<"jql" | "form" | "builder">("jql");
  const [builderState, setBuilderState] = useState<AdvancedBuilderState>(EMPTY_BUILDER);
  // Operator preference drives the AilaTable page window; the server fetch
  // stays at SERVER_PAGE_SIZE (backend max) so filter-narrowed sets remain
  // representative regardless of the chosen client-side page size.
  const { defaultPageSize } = usePreferences();
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);

  const auditQuery = useQuery({
    queryKey: ["platform", "audit-events", activeFilters],
    queryFn: () =>
      authorizedRequestJson<AuditListResponse>(buildAuditPath(activeFilters)),
  });

  const items = useMemo(() => auditQuery.data?.items ?? [], [auditQuery.data]);

  const applyFilters = useCallback(() => {
    setActiveFilters({ ...draftFilters });
  }, [draftFilters]);

  const clearFilters = useCallback(() => {
    setDraftFilters(EMPTY_FILTERS);
    setActiveFilters(EMPTY_FILTERS);
    setBuilderState(EMPTY_BUILDER);
  }, []);

  const handleJqlChange = useCallback((filters: JqlFilter[]) => {
    setActiveFilters(jqlToAuditFilters(filters));
  }, []);

  const applyBuilder = useCallback(() => {
    setActiveFilters(builderToAuditFilters(builderState));
  }, [builderState]);

  const clearBuilder = useCallback(() => {
    setBuilderState(EMPTY_BUILDER);
    setActiveFilters(EMPTY_FILTERS);
  }, []);

  const savedViewState: AuditSavedViewState = useMemo(
    () => ({
      mode: filterMode,
      filters: activeFilters,
      builder: filterMode === "builder" ? builderState : undefined,
    }),
    [filterMode, activeFilters, builderState],
  );

  const applySavedView = useCallback((state: AuditSavedViewState) => {
    // Applied views may originate from any mode; restore the mode too so the
    // matching surface is what the operator sees post-apply. `filters` is
    // authoritative for the query -- `builder` is UI scaffolding.
    if (state.mode === "builder" && state.builder) {
      setBuilderState({
        conditions: state.builder.conditions.map((row) => ({ ...row })),
        since: state.builder.since,
        until: state.builder.until,
      });
    }
    if (state.mode === "form") {
      setDraftFilters({ ...state.filters });
    }
    setFilterMode(state.mode);
    setActiveFilters({ ...state.filters });
  }, []);

  const hasDateRange = activeFilters.since || activeFilters.until;
  const dateRangeLabel = hasDateRange
    ? [activeFilters.since, activeFilters.until].filter(Boolean).join(" → ")
    : "All time";

  const [tab, setTab] = useState<string>("events");

  return (
    <div className="flex flex-col gap-4 p-4 lg:p-6">
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList variant="line" className="mb-2">
          <TabsTrigger value="events">Events</TabsTrigger>
          <TabsTrigger value="seals">Seals</TabsTrigger>
        </TabsList>

        <TabsContent value="events">
        <div className="flex flex-col gap-6">
      {/* Page header */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">

        {items.length > 0 && (
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="outline"
              className="gap-1.5"
              onClick={() => exportAsCsv(items)}
            >
              <Download className="h-4 w-4" />
              Export CSV
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="gap-1.5"
              onClick={() => exportAsJson(items)}
            >
              <Download className="h-4 w-4" />
              Export JSON
            </Button>
          </div>
        )}
      </div>

      {/* Filter bar -- JQL chip input is default; legacy form and advanced
          builder available on demand. Each mode drives the same
          `activeFilters` state and the SavedViews control persists the
          currently active mode + filters under entity_type='audit'. */}
      <div className="flex flex-col gap-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="font-mono text-xs text-text-muted uppercase tracking-wider">
            Filters
          </h2>
          <div
            role="tablist"
            aria-label="Audit filter mode"
            className="flex items-center gap-1 border border-border rounded-sharp-md p-0.5"
          >
            {(
              [
                { key: "jql", label: "Filter bar" },
                { key: "builder", label: "Builder" },
                { key: "form", label: "Form" },
              ] as const
            ).map((option) => {
              const active = filterMode === option.key;
              return (
                <button
                  key={option.key}
                  type="button"
                  role="tab"
                  aria-selected={active}
                  onClick={() => setFilterMode(option.key)}
                  className={`h-6 px-2 font-mono text-[10px] rounded-sharp transition-colors ${
                    active
                      ? "bg-accent/15 text-accent"
                      : "text-text-muted hover:text-text"
                  }`}
                >
                  {option.label}
                </button>
              );
            })}
          </div>
        </div>
        {filterMode === "jql" && (
          <JqlFilterBar
            fields={AUDIT_JQL_FIELDS}
            onChange={handleJqlChange}
            placeholder="Filter (e.g. stage:ssh, status:failed, search:web01)"
          />
        )}
        {filterMode === "form" && (
          <FilterForm
            draft={draftFilters}
            onDraftChange={(patch) =>
              setDraftFilters((prev) => ({ ...prev, ...patch }))
            }
            onApply={applyFilters}
            onClear={clearFilters}
            isFetching={auditQuery.isFetching}
          />
        )}
        {filterMode === "builder" && (
          <AdvancedFilterBuilder
            state={builderState}
            onChange={setBuilderState}
            onApply={applyBuilder}
            onClear={clearBuilder}
            isFetching={auditQuery.isFetching}
          />
        )}
        <SavedViews<AuditSavedViewState>
          entityType="audit"
          entityLabel="Audit log"
          currentState={savedViewState}
          onApply={applySavedView}
          className="mt-1"
        />
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <AilaCard variant="elevated" padding="md"><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Total Events
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {auditQuery.data?.total ?? "--"}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">
          Matching active filters
        </p></AilaCard>

        <AilaCard variant="elevated" padding="md"><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Loaded Events
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {items.length}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">
          This page (max {SERVER_PAGE_SIZE})
        </p></AilaCard>

        <AilaCard variant="elevated" padding="md"><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Date Range
        </p>
        <p className="font-mono text-sm font-semibold text-text mt-1 truncate" title={dateRangeLabel}>
          {dateRangeLabel}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">
          Active filter range
        </p></AilaCard>
      </div>

      {/* Error banner */}
      {auditQuery.isError && (
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-sm text-destructive">
          Failed to load audit events:{" "}
          {(auditQuery.error as Error).message}
        </div>
      )}

      {/* Loading skeleton */}
      {auditQuery.isLoading && (
        <AilaCard variant="default" padding="md"><LoadingSkeletonGroup lines={8} /></AilaCard>
      )}

      {/* Empty state */}
      {!auditQuery.isLoading && !auditQuery.isError && items.length === 0 && (
        <EmptyState
          icon={<ClipboardText className="h-10 w-10" />}
          title="No audit events"
          description="No events matched the current filters. Try clearing the filters or adjusting the date range."
          action={{ label: "Clear Filters", onClick: clearFilters }}
        />
      )}

      {/* Audit table */}
      {!auditQuery.isLoading && items.length > 0 && (
        <div>
          <div className="flex items-center justify-between mb-2">
            <h2 className="font-mono text-sm font-semibold text-text">
              Audit Trail
            </h2>
            <Button
              size="sm"
              variant="outline"
              className="gap-1.5"
              onClick={() => auditQuery.refetch()}
              disabled={auditQuery.isFetching}
            >
              <ArrowClockwise
                className={`h-3.5 w-3.5 ${auditQuery.isFetching ? "animate-spin" : ""}`}
              />
              Refresh
            </Button>
          </div>

          <AilaTable
            data={items}
            columns={AUDIT_COLUMNS_WITH_DETAILS(setSelectedEvent)}
            pageSize={defaultPageSize}
            enableSorting
            enableFiltering={false}
          >
            <AilaTable.Header />
            <AilaTable.Body
              emptyState="No events match the current table filter."
            />
            <AilaTable.Pagination pageSizeOptions={[10, 25, 50, 100]} />
          </AilaTable>

          <p className="font-mono text-xs text-text-muted mt-2">
            Showing first {items.length} of {auditQuery.data?.total ?? items.length} total events.
            {(auditQuery.data?.total ?? 0) > SERVER_PAGE_SIZE &&
              " Narrow the filters to see more."}
          </p>

          {selectedEvent && (
            <AilaCard variant="elevated" padding="md" className="mt-4 relative"><div className="flex items-start justify-between gap-2 mb-3">
              <div>
                <h3 className="font-mono text-sm font-semibold text-text">
                  {selectedEvent.stage} · {selectedEvent.action}
                  <AilaBadge
                    severity={auditStatusSeverity(selectedEvent.status)}
                    size="sm"
                    className="ml-2"
                  >
                    {selectedEvent.status}
                  </AilaBadge>
                </h3>
                <p className="font-mono text-[10px] text-text-muted mt-1">
                  {formatTimestamp(selectedEvent.created_at)} · user {selectedEvent.user_id} ·
                  run {selectedEvent.run_id}
                </p>
              </div>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                className="h-7 w-7 p-0"
                onClick={() => setSelectedEvent(null)}
                aria-label="Close audit details"
              >
                <XIcon className="h-4 w-4" />
              </Button>
            </div>
            <AuditDetailRenderer details={selectedEvent.details} /></AilaCard>
          )}
        </div>
      )}
        </div>
        </TabsContent>

        <TabsContent value="seals">
          <AuditSealsTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
