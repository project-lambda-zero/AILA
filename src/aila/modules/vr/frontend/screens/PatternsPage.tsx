import { useMemo, useState } from "react";
import { useNavigate } from "react-router";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";
import {
  DataGrid,
  MonoBadge,
  SectionHeader,
} from "@/components/aila/mock";

import { DeleteButton } from "../components/DeleteButton";
import { useDeletePattern } from "../mutations";
import { usePatterns, useWorkspaces } from "../queries";
import { useVRListInvalidation } from "../hooks/useVRListInvalidation";
import type {
  PatternKind,
  PatternScope,
  PatternStatus,
  VRPatternSummary,
} from "../types";

const KINDS: PatternKind[] = [
  "exploitation_technique",
  "fuzzing_strategy",
  "search_heuristic",
  "tool_recipe",
  "triage_rule",
];
const STATUSES: PatternStatus[] = ["draft", "active", "archived"];
const SCOPES: PatternScope[] = ["local", "workspace", "team", "global"];

// Status/scope -> MonoBadge tone.
const STATUS_TONE: Record<PatternStatus, string> = {
  draft: "info",
  active: "ok",
  archived: "high",
};

const SCOPE_TONE: Record<PatternScope, string> = {
  local: "info",
  workspace: "medium",
  team: "high",
  global: "critical",
};

// Mock chrome for raw form controls.
const CTRL: React.CSSProperties = {
  height: 26,
  fontSize: 10.5,
  padding: "0 8px",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-primary)",
  borderRadius: 3,
  letterSpacing: "0.04em",
  outline: "none",
  fontFamily: "var(--font-mono)",
};

export function PatternsPage() {
  const navigate = useNavigate();
  useVRListInvalidation("patterns");
  const { data: workspacesResult } = useWorkspaces();
  const workspaces = workspacesResult?.data ?? [];
  const deleteMut = useDeletePattern();

  const [workspaceFilter, setWorkspaceFilter] = useState("");
  const [kindFilter, setKindFilter] = useState<PatternKind | "">("");
  const [statusFilter, setStatusFilter] = useState<PatternStatus | "">("");
  const [scopeFilter, setScopeFilter] = useState<PatternScope | "">("");

  // /vr/patterns has no `q` server-side param -- quick-filter runs
  // client-side over the loaded page.
  const [query, setQuery] = useState("");

  const { data: result, isLoading, isError } = usePatterns({
    workspaceId: workspaceFilter || undefined,
    kind: kindFilter || undefined,
    status: statusFilter || undefined,
    scope: scopeFilter || undefined,
  });
  const patterns = result?.data ?? [];

  const filteredPatterns = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return patterns;
    return patterns.filter(
      (p) =>
        p.summary.toLowerCase().includes(needle) ||
        p.kind.toLowerCase().includes(needle) ||
        p.status.toLowerCase().includes(needle) ||
        p.scope.toLowerCase().includes(needle),
    );
  }, [patterns, query]);

  // ─── Filter shelf ───
  const filterShelf = (
    <WindowPanel title="filters" tone="muted">
      <div className="flex flex-wrap items-center" style={{ gap: 8 }}>
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="filter (summary / kind)…"
          aria-label="Filter patterns"
          className="font-mono"
          style={{ ...CTRL, width: 260 }}
        />
        <select
          value={workspaceFilter}
          onChange={(e) => setWorkspaceFilter(e.target.value)}
          aria-label="Filter by workspace"
          className="font-mono uppercase"
          style={CTRL}
        >
          <option value="">all workspaces</option>
          {workspaces
            .slice()
            .sort((a, b) => a.name.localeCompare(b.name))
            .map((ws) => (
              <option key={ws.id} value={ws.id}>
                {ws.name}
              </option>
            ))}
        </select>
        <select
          value={kindFilter}
          onChange={(e) => setKindFilter(e.target.value as PatternKind | "")}
          aria-label="Filter by kind"
          className="font-mono uppercase"
          style={CTRL}
        >
          <option value="">all kind</option>
          {KINDS.map((k) => (
            <option key={k} value={k}>
              {k}
            </option>
          ))}
        </select>
        <select
          value={statusFilter}
          onChange={(e) =>
            setStatusFilter(e.target.value as PatternStatus | "")
          }
          aria-label="Filter by status"
          className="font-mono uppercase"
          style={CTRL}
        >
          <option value="">all status</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select
          value={scopeFilter}
          onChange={(e) => setScopeFilter(e.target.value as PatternScope | "")}
          aria-label="Filter by scope"
          className="font-mono uppercase"
          style={CTRL}
        >
          <option value="">all scope</option>
          {SCOPES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <span style={{ flex: 1 }} />
        <span
          className="font-mono"
          style={{
            fontSize: 10,
            color: "var(--text-faint)",
            letterSpacing: "0.06em",
          }}
        >
          {query.trim()
            ? `${filteredPatterns.length} of ${patterns.length}`
            : `${patterns.length}`}
          {" "}pattern{patterns.length === 1 ? "" : "s"}
        </span>
      </div>
    </WindowPanel>
  );

  // ─── Table ───
  const columns: {
    label: string;
    width: string;
    align?: "left" | "right" | "center";
  }[] = [
    { label: "summary", width: "1fr" },
    { label: "kind", width: "160px" },
    { label: "status", width: "90px" },
    { label: "scope", width: "100px" },
    { label: "conf.", width: "70px", align: "right" },
    { label: "used", width: "60px", align: "right" },
    { label: "created", width: "110px" },
    { label: "", width: "40px", align: "center" },
  ];

  function renderCells(p: VRPatternSummary): React.ReactNode[] {
    return [
      <span
        className="font-mono"
        title={p.summary}
        style={{
          fontSize: 11.5,
          color: "var(--text-primary)",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          display: "block",
        }}
      >
        {p.summary}
      </span>,
      <span
        className="font-mono"
        style={{ fontSize: 10.5, color: "var(--text-muted)" }}
      >
        {p.kind}
      </span>,
      <MonoBadge tone={STATUS_TONE[p.status]}>{p.status}</MonoBadge>,
      <MonoBadge tone={SCOPE_TONE[p.scope]}>{p.scope}</MonoBadge>,
      <span
        className="font-mono"
        style={{ fontSize: 11, color: "var(--text-primary)" }}
      >
        {p.confidence}
      </span>,
      <span
        className="font-mono"
        style={{ fontSize: 11, color: "var(--text-primary)" }}
      >
        {p.times_retrieved}
      </span>,
      <span
        className="font-mono"
        style={{ fontSize: 10, color: "var(--text-faint)" }}
      >
        {p.created_at
          ? new Date(p.created_at).toLocaleDateString()
          : "--"}
      </span>,
      <span onClick={(e) => e.stopPropagation()}>
        <DeleteButton
          id={p.id}
          label={`pattern "${p.summary.slice(0, 40)}"`}
          mutation={deleteMut}
          compact
        />
      </span>,
    ];
  }

  const tableActions = (
    <span
      className="font-mono"
      style={{
        fontSize: 10,
        letterSpacing: "0.06em",
        color: "var(--text-faint)",
      }}
    >
      {filteredPatterns.length}
      <span style={{ opacity: 0.5 }}> / {patterns.length}</span>
    </span>
  );

  let tableBody: React.ReactNode;
  if (isLoading) {
    tableBody = (
      <div style={{ padding: 12 }}>
        <LoadingSkeleton size="lg" width="full" />
      </div>
    );
  } else if (isError) {
    tableBody = (
      <div
        className="font-mono"
        style={{
          padding: 24,
          textAlign: "center",
          color: "var(--accent)",
          fontSize: 11,
          letterSpacing: "0.06em",
        }}
      >
        failed to load patterns.
      </div>
    );
  } else {
    tableBody = (
      <DataGrid
        columns={columns}
        rows={filteredPatterns}
        renderCells={renderCells}
        getKey={(p) => p.id}
        onRowClick={(p) => navigate(`/vr/patterns/${p.id}`)}
        empty={
          <div
            className="font-mono"
            style={{
              padding: 34,
              textAlign: "center",
              fontSize: 11.5,
              color: "var(--text-muted)",
              letterSpacing: "0.04em",
            }}
          >
            {query.trim() ||
            workspaceFilter ||
            kindFilter ||
            statusFilter ||
            scopeFilter
              ? "no patterns match the current filters."
              : "no patterns yet -- auto-extraction runs when investigations complete."}
          </div>
        }
      />
    );
  }

  return (
    <div className="flex flex-col" style={{ gap: 14 }}>
      <SectionHeader icon="◈" title="Patterns" />
      {filterShelf}
      <WindowPanel
        title="results"
        tone="accent"
        actions={tableActions}
        flush
      >
        {tableBody}
      </WindowPanel>
    </div>
  );
}
