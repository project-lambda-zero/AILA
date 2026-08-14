import { useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { DeleteButton } from "../components/DeleteButton";
import {
  SortHeader,
  useSortableRows,
  useTableRowNav,
  type SortValue,
} from "../components/tableHelpers";
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

const statusColor: Record<
  PatternStatus,
  "info" | "low" | "medium" | "high" | "critical"
> = {
  draft: "info",
  active: "low",
  archived: "high",
};

const scopeColor: Record<
  PatternScope,
  "info" | "low" | "medium" | "high" | "critical"
> = {
  local: "info",
  workspace: "medium",
  team: "high",
  global: "critical",
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

  const accessors = useMemo<
    Record<string, (p: VRPatternSummary) => SortValue>
  >(
    () => ({
      summary: (p) => p.summary,
      kind: (p) => p.kind,
      status: (p) => p.status,
      scope: (p) => p.scope,
      confidence: (p) => p.confidence,
      times_retrieved: (p) => p.times_retrieved,
      created_at: (p) => (p.created_at ? new Date(p.created_at) : null),
    }),
    [],
  );
  const { sortedRows, sortKey, sortDir, cycleSort } = useSortableRows(
    filteredPatterns,
    accessors,
  );

  const tbodyRef = useRef<HTMLTableSectionElement | null>(null);
  const { tbodyProps, getRowProps } = useTableRowNav(
    sortedRows,
    (p) => navigate(`/vr/patterns/${p.id}`),
    tbodyRef,
  );

  return (
    <div className="space-y-4">

      <AilaCard  techBorder glow><div className="flex items-center gap-2 flex-wrap">
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Filter patterns (summary / kind)…"
          aria-label="Filter patterns"
          className="flex-1 min-w-[220px] max-w-md px-3 py-1.5 text-sm rounded-md bg-surface border border-border-default focus:border-accent focus:outline-none"
        />
        <label className="text-sm text-text-muted">Workspace:</label>
        <select
          value={workspaceFilter}
          onChange={(e) => setWorkspaceFilter(e.target.value)}
          aria-label="Filter by workspace"
          className="px-3 py-1.5 text-sm rounded-md bg-surface border border-border-default"
        >
          <option value="">-- all --</option>
          {workspaces.map((ws) => (
            <option key={ws.id} value={ws.id}>
              {ws.name}
            </option>
          ))}
        </select>
      
        <label className="text-sm text-text-muted ml-2">Kind:</label>
        <select
          value={kindFilter}
          onChange={(e) => setKindFilter(e.target.value as PatternKind | "")}
          aria-label="Filter by kind"
          className="px-3 py-1.5 text-sm font-mono rounded-md bg-surface border border-border-default"
        >
          <option value="">-- all --</option>
          {KINDS.map((k) => (
            <option key={k} value={k}>
              {k}
            </option>
          ))}
        </select>
      
        <label className="text-sm text-text-muted ml-2">Status:</label>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value as PatternStatus | "")}
          aria-label="Filter by status"
          className="px-3 py-1.5 text-sm rounded-md bg-surface border border-border-default"
        >
          <option value="">-- all --</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      
        <label className="text-sm text-text-muted ml-2">Scope:</label>
        <select
          value={scopeFilter}
          onChange={(e) => setScopeFilter(e.target.value as PatternScope | "")}
          aria-label="Filter by scope"
          className="px-3 py-1.5 text-sm rounded-md bg-surface border border-border-default"
        >
          <option value="">-- all --</option>
          {SCOPES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      
        <span className="text-xs text-text-muted ml-auto">
          {query.trim()
            ? `${sortedRows.length} of ${patterns.length} pattern${patterns.length === 1 ? "" : "s"}`
            : `${patterns.length} pattern${patterns.length === 1 ? "" : "s"}`}
        </span>
      </div></AilaCard>

      {isLoading && <LoadingSkeleton size="lg" width="full" />}

      {isError && (
        <AilaCard className="border-border-danger" techBorder glow><p className="text-sm text-text-danger">Failed to load patterns.</p></AilaCard>
      )}

      {!isLoading && !isError && patterns.length === 0 && (
        <AilaCard  techBorder glow><p className="text-center py-6 text-text-muted">
          No patterns. Auto-extraction runs when investigations complete
          successfully; you can also create patterns manually via the API.
        </p></AilaCard>
      )}

      {!isLoading && !isError && patterns.length > 0 && (
        <AilaCard className="overflow-x-auto p-0" techBorder glow><table className="w-full text-sm">
          <caption className="sr-only">Reusable investigation patterns</caption>
          <thead>
            <tr className="border-b border-border-default text-left text-xs uppercase tracking-wide text-text-muted">
              <SortHeader columnKey="summary" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort}>Summary</SortHeader>
              <SortHeader columnKey="kind" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort}>Kind</SortHeader>
              <SortHeader columnKey="status" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort}>Status</SortHeader>
              <SortHeader columnKey="scope" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort}>Scope</SortHeader>
              <SortHeader columnKey="confidence" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort}>Confidence</SortHeader>
              <SortHeader columnKey="times_retrieved" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort} align="right">Used</SortHeader>
              <SortHeader columnKey="created_at" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort}>Created</SortHeader>
              <th className="px-2 py-2"></th>
            </tr>
          </thead>
          <tbody ref={tbodyRef} {...tbodyProps}>
            {sortedRows.map((p, idx) => {
              const rowProps = getRowProps(idx);
              return (
              <tr
                key={p.id}
                {...rowProps}
                onClick={() => navigate(`/vr/patterns/${p.id}`)}
                className={
                  "border-b border-border-default last:border-b-0 cursor-pointer hover:bg-surface transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-inset " +
                  (rowProps["data-row-active"] ? "bg-elevated" : "")
                }
              >
                <td className="px-4 py-2 font-semibold text-foreground max-w-md truncate">
                  {p.summary}
                </td>
                <td className="px-4 py-2 font-mono text-xs text-text-muted">
                  {p.kind}
                </td>
                <td className="px-4 py-2">
                  <AilaBadge severity={statusColor[p.status]} size="sm">
                    {p.status}
                  </AilaBadge>
                </td>
                <td className="px-4 py-2">
                  <AilaBadge severity={scopeColor[p.scope]} size="sm">
                    {p.scope}
                  </AilaBadge>
                </td>
                <td className="px-4 py-2 font-mono text-xs">
                  {p.confidence}
                </td>
                <td className="px-4 py-2 font-mono text-xs text-right">
                  {p.times_retrieved}
                </td>
                <td className="px-4 py-2 font-mono text-xs text-text-muted">
                  {p.created_at
                    ? new Date(p.created_at).toLocaleDateString()
                    : "--"}
                </td>
                <td className="px-2 py-2 text-right">
                  <DeleteButton
                    id={p.id}
                    label={`pattern "${p.summary.slice(0, 40)}"`}
                    mutation={deleteMut}
                    compact
                  />
                </td>
              </tr>
              );
            })}
          </tbody>
        </table></AilaCard>
      )}
    </div>
  );
}
