/**
 * AuditLogsPage -- admin audit trail rebuilt to the AILA mock language.
 *
 * Layout:
 *   SectionHeader (title + view segmented events/seals + export actions)
 *   FilterChip row: jql / builder / form mode + saved views hook
 *   Selected filter panel (JqlFilterBar | AdvancedFilterBuilder | FilterForm)
 *   Stat row (WindowPanels: total / loaded / date range as BigStat)
 *   Error banner (tokenized)
 *   WindowPanel('audit trail', flush) DataGrid
 *   Selected event detail WindowPanel with AuditDetailRenderer inside
 *
 * ADM-01 preserved: server-side filters (run_id, stage, action, status,
 * user_id, since, until), CSV/JSON export, JQL bar, form, and advanced
 * builder all drive the same activeFilters query. Saved views round-trip
 * through /saved-filters under entity_type='audit'.
 */
import {
  useState,
  useCallback,
  useMemo,
  type CSSProperties,
  type ReactNode,
} from "react";
import { useQuery } from "@tanstack/react-query";
import { Download } from "@phosphor-icons/react/dist/csr/Download";
import { ClipboardText } from "@phosphor-icons/react/dist/csr/ClipboardText";
import { Plus } from "@phosphor-icons/react/dist/csr/Plus";
import { Trash } from "@phosphor-icons/react/dist/csr/Trash";

import {
  SectionHeader,
  DataGrid,
  MonoBadge,
  FilterChip,
  Segmented,
  BigStat,
} from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { authorizedRequestJson } from "@platform/api/http";
import {
  JqlFilterBar,
  filtersToQueryParams,
  type JqlFieldSpec,
  type JqlFilter,
} from "@/components/filters/JqlFilterBar";
import { AuditDetailRenderer } from "./AuditDetailRenderer";
import { AuditSealsTab } from "./AuditSealsTab";
import { usePreferences } from "@/providers/PreferencesProvider";
import { SavedViews } from "@platform/features/saved-views";

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

const SERVER_PAGE_SIZE = 250;

const ACTION_BTN: CSSProperties = {
  height: 26,
  padding: "0 11px",
  fontSize: 9.5,
  letterSpacing: "0.08em",
  borderRadius: 3,
  cursor: "pointer",
  color: "var(--text-primary)",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
};

const PRIMARY_BTN: CSSProperties = {
  ...ACTION_BTN,
  color: "var(--text-on-accent)",
  background: "var(--accent)",
  borderColor: "var(--accent)",
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

const STATUS_TONE: Record<string, string> = {
  ok: "ok",
  completed: "ok",
  running: "info",
  pending: "info",
  failed: "critical",
  error: "critical",
  cancelled: "warn",
  timeout: "warn",
};

function statusTone(status: string): string {
  return STATUS_TONE[status.toLowerCase()] ?? "muted";
}

// ---------------------------------------------------------------------------
// Query builder + JQL translation
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

// ---------------------------------------------------------------------------
// Export helpers
// ---------------------------------------------------------------------------

function escapeCsvCell(value: string): string {
  if (value.includes(",") || value.includes('"') || value.includes("\n")) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
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

function exportAsCsv(items: AuditEvent[]): void {
  const headers = [
    "run_id",
    "stage",
    "action",
    "status",
    "user_id",
    "target",
    "created_at",
  ];
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

// ---------------------------------------------------------------------------
// Shared field wrapper for form + builder
// ---------------------------------------------------------------------------

function LabeledField({
  label,
  htmlFor,
  children,
}: {
  label: string;
  htmlFor?: string;
  children: ReactNode;
}) {
  return (
    <div className="flex flex-col" style={{ gap: 4 }}>
      <label
        htmlFor={htmlFor}
        className="font-mono uppercase"
        style={{
          fontSize: 9.5,
          letterSpacing: "0.12em",
          color: "var(--text-muted)",
        }}
      >
        {label}
      </label>
      {children}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Legacy form (mock-styled)
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
    <form
      className="flex flex-col"
      style={{ gap: 12 }}
      onSubmit={(e) => {
        e.preventDefault();
        onApply();
      }}
    >
      <div
        className="grid"
        style={{
          gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
          gap: 10,
        }}
      >
        <LabeledField label="Run ID" htmlFor="af-run-id">
          <input
            id="af-run-id"
            value={draft.runId}
            onChange={(e) => onDraftChange({ runId: e.target.value })}
            placeholder="50b5b278-1b3d-..."
            className="font-mono"
            style={INPUT_STYLE}
          />
        </LabeledField>
        <LabeledField label="Stage" htmlFor="af-stage">
          <input
            id="af-stage"
            value={draft.stage}
            onChange={(e) => onDraftChange({ stage: e.target.value })}
            placeholder="task,report_lookup"
            className="font-mono"
            style={INPUT_STYLE}
          />
        </LabeledField>
        <LabeledField label="Action" htmlFor="af-action">
          <input
            id="af-action"
            value={draft.action}
            onChange={(e) => onDraftChange({ action: e.target.value })}
            placeholder="scan.start"
            className="font-mono"
            style={INPUT_STYLE}
          />
        </LabeledField>
        <LabeledField label="Status" htmlFor="af-status">
          <input
            id="af-status"
            value={draft.status}
            onChange={(e) => onDraftChange({ status: e.target.value })}
            placeholder="completed,failed"
            className="font-mono"
            style={INPUT_STYLE}
          />
        </LabeledField>
        <LabeledField label="User ID" htmlFor="af-user">
          <input
            id="af-user"
            value={draft.userId}
            onChange={(e) => onDraftChange({ userId: e.target.value })}
            placeholder="system"
            className="font-mono"
            style={INPUT_STYLE}
          />
        </LabeledField>
      </div>

      <div
        className="grid"
        style={{
          gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
          gap: 10,
        }}
      >
        <LabeledField label="Since (ISO 8601)" htmlFor="af-since">
          <input
            id="af-since"
            type="datetime-local"
            value={draft.since}
            onChange={(e) => onDraftChange({ since: e.target.value })}
            className="font-mono"
            style={INPUT_STYLE}
          />
        </LabeledField>
        <LabeledField label="Until (ISO 8601)" htmlFor="af-until">
          <input
            id="af-until"
            type="datetime-local"
            value={draft.until}
            onChange={(e) => onDraftChange({ until: e.target.value })}
            className="font-mono"
            style={INPUT_STYLE}
          />
        </LabeledField>
      </div>

      <div className="flex items-center" style={{ gap: 8 }}>
        <button
          type="submit"
          className="font-mono uppercase"
          disabled={isFetching}
          style={{
            ...PRIMARY_BTN,
            opacity: isFetching ? 0.6 : 1,
          }}
        >
          {isFetching ? "loading" : "apply filters"}
        </button>
        <button
          type="button"
          className="font-mono uppercase"
          onClick={onClear}
          style={ACTION_BTN}
        >
          clear
        </button>
      </div>
    </form>
  );
}

// ---------------------------------------------------------------------------
// Advanced filter builder (chip rows per field + since/until)
// ---------------------------------------------------------------------------

type BuilderField = "action" | "status" | "user_id" | "stage";

interface BuilderConditionRow {
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

const BUILDER_FIELDS: readonly {
  key: BuilderField;
  label: string;
  placeholder: string;
}[] = [
  { key: "action", label: "Action", placeholder: "scan.start" },
  { key: "status", label: "Status", placeholder: "completed, failed" },
  { key: "user_id", label: "User", placeholder: "system, admin" },
  { key: "stage", label: "Stage", placeholder: "task, report_lookup" },
];

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
    <div className="flex flex-col" style={{ gap: 10 }}>
      <div className="flex items-center justify-between" style={{ gap: 8 }}>
        <span
          className="font-mono uppercase"
          style={{
            fontSize: 9.5,
            letterSpacing: "0.12em",
            color: "var(--text-muted)",
          }}
        >
          conditions
        </span>
        <button
          type="button"
          className="font-mono uppercase flex items-center"
          onClick={() =>
            onChange({
              ...state,
              conditions: [...state.conditions, newBuilderRow()],
            })
          }
          style={{ ...ACTION_BTN, gap: 6 }}
        >
          <Plus size={11} weight="bold" aria-hidden="true" />
          add condition
        </button>
      </div>

      {state.conditions.length === 0 && (
        <p
          className="font-mono"
          style={{ color: "var(--text-faint)", fontSize: 11 }}
        >
          no conditions yet. add a condition to filter by action, status,
          user, or stage.
        </p>
      )}

      {state.conditions.map((row, index) => {
        const spec =
          BUILDER_FIELDS.find((f) => f.key === row.field) ?? BUILDER_FIELDS[0];
        const draft = draftValues[row.rowId] ?? "";
        const fieldSelectId = `builder-field-${row.rowId}`;
        const valueInputId = `builder-value-${row.rowId}`;
        return (
          <div
            key={row.rowId}
            className="flex items-start flex-wrap"
            style={{
              gap: 8,
              padding: 8,
              borderRadius: 3,
              border: "1px solid var(--border-soft)",
              background: "var(--surface-sunk)",
            }}
          >
            <LabeledField
              label={index === 0 ? "Where" : "And"}
              htmlFor={fieldSelectId}
            >
              <select
                id={fieldSelectId}
                value={row.field}
                onChange={(e) =>
                  updateRow(row.rowId, {
                    field: e.target.value as BuilderField,
                  })
                }
                className="font-mono"
                style={{ ...INPUT_STYLE, minWidth: 120 }}
              >
                {BUILDER_FIELDS.map((field) => (
                  <option key={field.key} value={field.key}>
                    {field.label}
                  </option>
                ))}
              </select>
            </LabeledField>

            <div
              className="flex flex-col"
              style={{ gap: 4, flex: 1, minWidth: 200 }}
            >
              <label
                htmlFor={valueInputId}
                className="font-mono uppercase"
                style={{
                  fontSize: 9.5,
                  letterSpacing: "0.12em",
                  color: "var(--text-muted)",
                }}
              >
                any of (comma-OR)
              </label>
              <div
                className="flex items-center flex-wrap"
                style={{
                  gap: 6,
                  minHeight: 28,
                  padding: "3px 6px",
                  border: "1px solid var(--border-soft)",
                  background: "var(--surface-card)",
                  borderRadius: 3,
                }}
              >
                {row.values.map((value) => (
                  <span
                    key={value}
                    className="inline-flex items-center font-mono"
                    style={{
                      gap: 4,
                      padding: "1px 6px",
                      fontSize: 10.5,
                      color: "var(--accent)",
                      background:
                        "color-mix(in srgb, var(--accent) 12%, transparent)",
                      border:
                        "1px solid color-mix(in srgb, var(--accent) 40%, transparent)",
                      borderRadius: 2,
                    }}
                  >
                    {value}
                    <button
                      type="button"
                      onClick={() =>
                        updateRow(row.rowId, {
                          values: row.values.filter((v) => v !== value),
                        })
                      }
                      aria-label={`Remove ${value}`}
                      style={{
                        cursor: "pointer",
                        background: "transparent",
                        border: 0,
                        color: "var(--accent)",
                        fontSize: 12,
                        lineHeight: 1,
                        padding: 0,
                      }}
                    >
                      {"\u00d7"}
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
                  className="font-mono"
                  style={{
                    flex: 1,
                    minWidth: 80,
                    background: "transparent",
                    outline: "none",
                    border: 0,
                    fontSize: 11,
                    color: "var(--text-primary)",
                  }}
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
              aria-label={`Remove condition ${index + 1}`}
              title="Remove condition"
              style={{
                marginTop: 22,
                cursor: "pointer",
                background: "transparent",
                border: 0,
                color: "var(--text-muted)",
                padding: 4,
              }}
            >
              <Trash size={14} />
            </button>
          </div>
        );
      })}

      <div
        className="grid"
        style={{
          gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
          gap: 10,
        }}
      >
        <LabeledField label="Since (ISO 8601)" htmlFor="builder-since">
          <input
            id="builder-since"
            type="datetime-local"
            value={state.since}
            onChange={(e) => onChange({ ...state, since: e.target.value })}
            className="font-mono"
            style={INPUT_STYLE}
          />
        </LabeledField>
        <LabeledField label="Until (ISO 8601)" htmlFor="builder-until">
          <input
            id="builder-until"
            type="datetime-local"
            value={state.until}
            onChange={(e) => onChange({ ...state, until: e.target.value })}
            className="font-mono"
            style={INPUT_STYLE}
          />
        </LabeledField>
      </div>

      <div className="flex items-center" style={{ gap: 8 }}>
        <button
          type="button"
          className="font-mono uppercase"
          onClick={onApply}
          disabled={isFetching}
          style={{
            ...PRIMARY_BTN,
            opacity: isFetching ? 0.6 : 1,
          }}
        >
          {isFetching ? "loading" : "apply builder"}
        </button>
        <button
          type="button"
          className="font-mono uppercase"
          onClick={onClear}
          style={ACTION_BTN}
        >
          clear builder
        </button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Saved-view payload
// ---------------------------------------------------------------------------

interface AuditSavedViewState {
  mode: "jql" | "form" | "builder";
  filters: AuditFilters;
  builder?: AdvancedBuilderState;
}

// ---------------------------------------------------------------------------
// Selected event detail panel
// ---------------------------------------------------------------------------

function SelectedEventPanel({
  event,
  onClose,
}: {
  event: AuditEvent;
  onClose: () => void;
}) {
  return (
    <WindowPanel
      title={`${event.stage} \u00b7 ${event.action}`}
      tone={statusTone(event.status) === "critical" ? "warn" : "info"}
      actions={
        <button
          type="button"
          className="font-mono uppercase"
          onClick={onClose}
          aria-label="Close audit details"
          style={{ ...ACTION_BTN, height: 22, fontSize: 9 }}
        >
          close
        </button>
      }
      status={`${formatTimestamp(event.created_at)} \u00b7 user ${
        event.user_id
      } \u00b7 run ${event.run_id}`}
    >
      <div className="flex flex-col" style={{ gap: 12 }}>
        <div className="flex items-center flex-wrap" style={{ gap: 8 }}>
          <MonoBadge tone={statusTone(event.status)}>{event.status}</MonoBadge>
          {event.target && (
            <MonoBadge tone="muted">target: {event.target}</MonoBadge>
          )}
        </div>
        <AuditDetailRenderer details={event.details} />
      </div>
    </WindowPanel>
  );
}

// ---------------------------------------------------------------------------
// Events view
// ---------------------------------------------------------------------------

type FilterMode = "jql" | "form" | "builder";

function EventsView() {
  const [draftFilters, setDraftFilters] = useState<AuditFilters>(EMPTY_FILTERS);
  const [activeFilters, setActiveFilters] =
    useState<AuditFilters>(EMPTY_FILTERS);
  const [filterMode, setFilterMode] = useState<FilterMode>("jql");
  const [builderState, setBuilderState] =
    useState<AdvancedBuilderState>(EMPTY_BUILDER);
  const { defaultPageSize } = usePreferences();
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);
  const [pageSize, setPageSize] = useState<number>(defaultPageSize);
  const [pageIndex, setPageIndex] = useState<number>(0);

  const auditQuery = useQuery({
    queryKey: ["platform", "audit-events", activeFilters],
    queryFn: () =>
      authorizedRequestJson<AuditListResponse>(buildAuditPath(activeFilters)),
  });

  const items = useMemo(
    () => auditQuery.data?.items ?? [],
    [auditQuery.data],
  );

  const pagedItems = useMemo(() => {
    const start = pageIndex * pageSize;
    return items.slice(start, start + pageSize);
  }, [items, pageIndex, pageSize]);

  const totalPages = Math.max(1, Math.ceil(items.length / pageSize));

  const applyFilters = useCallback(() => {
    setActiveFilters({ ...draftFilters });
    setPageIndex(0);
  }, [draftFilters]);

  const clearFilters = useCallback(() => {
    setDraftFilters(EMPTY_FILTERS);
    setActiveFilters(EMPTY_FILTERS);
    setBuilderState(EMPTY_BUILDER);
    setPageIndex(0);
  }, []);

  const handleJqlChange = useCallback((filters: JqlFilter[]) => {
    setActiveFilters(jqlToAuditFilters(filters));
    setPageIndex(0);
  }, []);

  const applyBuilder = useCallback(() => {
    setActiveFilters(builderToAuditFilters(builderState));
    setPageIndex(0);
  }, [builderState]);

  const clearBuilder = useCallback(() => {
    setBuilderState(EMPTY_BUILDER);
    setActiveFilters(EMPTY_FILTERS);
    setPageIndex(0);
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
    setPageIndex(0);
  }, []);

  const dateRangeLabel = activeFilters.since || activeFilters.until
    ? [activeFilters.since, activeFilters.until].filter(Boolean).join(" \u2192 ")
    : "All time";

  const totalMatched = auditQuery.data?.total ?? 0;

  return (
    <div className="flex flex-col" style={{ gap: 14 }}>
      {/* Filter mode + panel */}
      <div className="flex flex-col" style={{ gap: 8 }}>
        <div className="flex items-center flex-wrap" style={{ gap: 8 }}>
          <span
            className="font-mono uppercase"
            style={{
              fontSize: 9.5,
              letterSpacing: "0.12em",
              color: "var(--text-muted)",
              marginRight: 4,
            }}
          >
            mode
          </span>
          <FilterChip
            active={filterMode === "jql"}
            onClick={() => setFilterMode("jql")}
          >
            filter bar
          </FilterChip>
          <FilterChip
            active={filterMode === "builder"}
            onClick={() => setFilterMode("builder")}
          >
            builder
          </FilterChip>
          <FilterChip
            active={filterMode === "form"}
            onClick={() => setFilterMode("form")}
          >
            form
          </FilterChip>
          <span style={{ flex: 1 }} />
          {items.length > 0 && (
            <>
              <button
                type="button"
                className="font-mono uppercase flex items-center"
                onClick={() => exportAsCsv(items)}
                style={{ ...ACTION_BTN, gap: 6 }}
              >
                <Download size={11} weight="bold" aria-hidden="true" />
                csv
              </button>
              <button
                type="button"
                className="font-mono uppercase flex items-center"
                onClick={() => exportAsJson(items)}
                style={{ ...ACTION_BTN, gap: 6 }}
              >
                <Download size={11} weight="bold" aria-hidden="true" />
                json
              </button>
            </>
          )}
        </div>

        <WindowPanel title="filters" tone="muted">
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
          <div style={{ marginTop: 10 }}>
            <SavedViews<AuditSavedViewState>
              entityType="audit"
              entityLabel="Audit log"
              currentState={savedViewState}
              onApply={applySavedView}
            />
          </div>
        </WindowPanel>
      </div>

      {/* Stat row */}
      <div
        className="grid"
        style={{
          gridTemplateColumns: "repeat(3, minmax(0, 1fr))",
          gap: 12,
        }}
      >
        <WindowPanel title="total events">
          <BigStat
            value={auditQuery.data?.total ?? "--"}
            sub="matching active filters"
          />
        </WindowPanel>
        <WindowPanel title="loaded" tone="info">
          <BigStat
            value={items.length}
            sub={`this window (max ${SERVER_PAGE_SIZE})`}
          />
        </WindowPanel>
        <WindowPanel title="date range" tone="muted">
          <div className="flex flex-col" style={{ gap: 4 }}>
            <span
              className="font-mono truncate"
              title={dateRangeLabel}
              style={{
                color: "var(--text-primary)",
                fontSize: 12,
              }}
            >
              {dateRangeLabel}
            </span>
            <span
              className="font-mono"
              style={{ color: "var(--text-faint)", fontSize: 10 }}
            >
              active filter range
            </span>
          </div>
        </WindowPanel>
      </div>

      {/* Error banner */}
      {auditQuery.isError && (
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
          Failed to load audit events: {(auditQuery.error as Error).message}
        </div>
      )}

      {/* Data grid */}
      <WindowPanel
        title={`audit trail \u00b7 ${items.length}`}
        flush
        actions={
          <button
            type="button"
            className="font-mono uppercase"
            onClick={() => void auditQuery.refetch()}
            disabled={auditQuery.isFetching}
            style={{
              ...ACTION_BTN,
              height: 22,
              fontSize: 9,
              opacity: auditQuery.isFetching ? 0.6 : 1,
            }}
          >
            {auditQuery.isFetching ? "refreshing" : "refresh"}
          </button>
        }
      >
        {auditQuery.isLoading ? (
          <div style={{ padding: 16 }}>
            <LoadingSkeletonGroup lines={8} />
          </div>
        ) : items.length === 0 && !auditQuery.isError ? (
          <div
            className="flex flex-col items-center justify-center"
            style={{ padding: 36, textAlign: "center", gap: 8 }}
          >
            <span aria-hidden="true" style={{ color: "var(--text-faint)" }}>
              <ClipboardText size={28} weight="duotone" />
            </span>
            <span
              className="font-mono"
              style={{ color: "var(--text-primary)", fontSize: 12 }}
            >
              No audit events
            </span>
            <span
              className="font-mono"
              style={{
                color: "var(--text-muted)",
                fontSize: 10.5,
                maxWidth: 320,
              }}
            >
              No events matched the current filters. Try clearing filters or
              adjusting the date range.
            </span>
            <button
              type="button"
              className="font-mono uppercase"
              onClick={clearFilters}
              style={{ ...ACTION_BTN, marginTop: 6 }}
            >
              clear filters
            </button>
          </div>
        ) : (
          <DataGrid<AuditEvent>
            columns={[
              { label: "TIMESTAMP", width: "170px" },
              { label: "ACTOR", width: "130px" },
              { label: "ACTION", width: "1.2fr" },
              { label: "TARGET", width: "1fr" },
              { label: "OUTCOME", width: "110px" },
              { label: "RUN", width: "110px" },
              { label: "", width: "80px", align: "right" },
            ]}
            rows={pagedItems}
            getKey={(r, i) => r.id ?? `${r.run_id}-${i}`}
            onRowClick={(r) => setSelectedEvent(r)}
            empty={
              <div
                className="font-mono"
                style={{
                  padding: 24,
                  textAlign: "center",
                  fontSize: 11,
                  color: "var(--text-muted)",
                }}
              >
                no events on this page.
              </div>
            }
            renderCells={(r) => [
              <span
                key="ts"
                className="font-mono"
                style={{
                  color: "var(--text-muted)",
                  fontSize: 10.5,
                  whiteSpace: "nowrap",
                }}
              >
                {formatTimestamp(r.created_at)}
              </span>,
              <span
                key="actor"
                className="font-mono truncate"
                style={{ color: "var(--text-primary)", fontSize: 11 }}
              >
                {r.user_id}
              </span>,
              <span
                key="act"
                className="font-mono truncate"
                style={{ color: "var(--text-primary)", fontSize: 11 }}
              >
                <span style={{ color: "var(--text-muted)" }}>
                  {r.stage}
                  {" \u00b7 "}
                </span>
                {r.action}
              </span>,
              <span
                key="tgt"
                className="font-mono truncate"
                title={r.target}
                style={{ color: "var(--text-muted)", fontSize: 10.5 }}
              >
                {r.target || "--"}
              </span>,
              <MonoBadge key="st" tone={statusTone(r.status)}>
                {r.status}
              </MonoBadge>,
              <span
                key="run"
                className="font-mono truncate"
                title={r.run_id}
                style={{ color: "var(--accent)", fontSize: 10.5 }}
              >
                {r.run_id.slice(0, 8)}
                {"\u2026"}
              </span>,
              <button
                key="view"
                type="button"
                className="font-mono uppercase"
                onClick={() => setSelectedEvent(r)}
                style={{
                  ...ACTION_BTN,
                  height: 22,
                  padding: "0 10px",
                  fontSize: 9.5,
                }}
              >
                view
              </button>,
            ]}
          />
        )}
      </WindowPanel>

      {/* Pagination + page size */}
      {items.length > 0 && (
        <div
          className="flex items-center justify-between flex-wrap font-mono"
          style={{ gap: 8, fontSize: 11, color: "var(--text-muted)" }}
        >
          <span>
            Showing {pagedItems.length} of {items.length} loaded events
            {totalMatched > SERVER_PAGE_SIZE
              ? ` (${totalMatched} total; narrow filters to see more)`
              : totalMatched > items.length
              ? ` (${totalMatched} total)`
              : ""}
          </span>
          <div className="flex items-center" style={{ gap: 8 }}>
            <label className="uppercase" style={{ letterSpacing: "0.1em" }}>
              rows
            </label>
            <select
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value));
                setPageIndex(0);
              }}
              className="font-mono"
              style={INPUT_STYLE}
            >
              {[10, 25, 50, 100].map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
            <button
              type="button"
              className="font-mono uppercase"
              disabled={pageIndex === 0}
              onClick={() => setPageIndex((p) => Math.max(0, p - 1))}
              style={{ ...ACTION_BTN, opacity: pageIndex === 0 ? 0.55 : 1 }}
            >
              prev
            </button>
            <span className="tabular-nums">
              {pageIndex + 1} / {totalPages}
            </span>
            <button
              type="button"
              className="font-mono uppercase"
              disabled={pageIndex + 1 >= totalPages}
              onClick={() =>
                setPageIndex((p) => Math.min(totalPages - 1, p + 1))
              }
              style={{
                ...ACTION_BTN,
                opacity: pageIndex + 1 >= totalPages ? 0.55 : 1,
              }}
            >
              next
            </button>
          </div>
        </div>
      )}

      {selectedEvent && (
        <SelectedEventPanel
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page root
// ---------------------------------------------------------------------------

export function AuditLogsPage() {
  const [view, setView] = useState<"events" | "seals">("events");

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <SectionHeader
        icon={
          <ClipboardText
            size={16}
            weight="duotone"
            style={{ color: "var(--text-on-accent)" }}
            aria-hidden="true"
          />
        }
        title="audit trail"
        actions={
          <Segmented
            options={[
              { value: "events", label: "EVENTS" },
              { value: "seals", label: "SEALS" },
            ]}
            value={view}
            onChange={setView}
          />
        }
      />

      {view === "events" ? <EventsView /> : <AuditSealsTab />}
    </div>
  );
}
