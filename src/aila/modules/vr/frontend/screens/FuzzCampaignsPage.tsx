import { useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { EmptyState } from "@/components/aila/EmptyState";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { Lightning } from "@phosphor-icons/react/dist/csr/Lightning";

import { DeleteButton } from "../components/DeleteButton";
import {
  SortHeader,
  useSortableRows,
  useTableRowNav,
  type SortValue,
} from "../components/tableHelpers";
import { useDeleteFuzzCampaign } from "../mutations";
import { useFuzzCampaigns, useWorkspaces } from "../queries";
import { useVRListInvalidation } from "../hooks/useVRListInvalidation";
import type { CampaignStatus, VRFuzzCampaignSummary } from "../types";

const STATUS_COLOR: Record<
  CampaignStatus,
  "info" | "low" | "medium" | "high" | "critical"
> = {
  created: "info",
  running: "medium",
  paused: "info",
  completed: "low",
  failed: "high",
  aborted: "high",
};

const STATUSES: CampaignStatus[] = [
  "created", "running", "paused", "completed", "failed", "aborted",
];

export function FuzzCampaignsPage() {
  const navigate = useNavigate();
  useVRListInvalidation("fuzz-campaigns");
  const { data: workspacesResult } = useWorkspaces();
  const workspaces = workspacesResult?.data ?? [];
  const deleteMut = useDeleteFuzzCampaign();

  const [workspaceFilter, setWorkspaceFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState<CampaignStatus | "">("");

  // /vr/fuzz/campaigns has no `q` server-side param -- quick-filter
  // runs client-side.
  const [query, setQuery] = useState("");

  const { data: result, isLoading, isError } = useFuzzCampaigns({
    workspaceId: workspaceFilter || undefined,
    status: statusFilter || undefined,
  });
  const rows = result?.data ?? [];

  const filteredRows = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return rows;
    return rows.filter(
      (c) =>
        c.name.toLowerCase().includes(needle) ||
        c.engine_id.toLowerCase().includes(needle) ||
        c.strategy_id.toLowerCase().includes(needle) ||
        c.status.toLowerCase().includes(needle),
    );
  }, [rows, query]);

  const accessors = useMemo<
    Record<string, (c: VRFuzzCampaignSummary) => SortValue>
  >(
    () => ({
      name: (c) => c.name,
      engine_id: (c) => c.engine_id,
      strategy_id: (c) => c.strategy_id,
      status: (c) => c.status,
      total_execs: (c) => c.total_execs,
      corpus_size: (c) => c.corpus_size,
      coverage_pct: (c) => c.coverage_pct ?? null,
      crashes_found: (c) => c.crashes_found,
      last_progress_at: (c) =>
        c.last_progress_at ? new Date(c.last_progress_at) : null,
    }),
    [],
  );
  const { sortedRows, sortKey, sortDir, cycleSort } = useSortableRows(
    filteredRows,
    accessors,
  );

  const tbodyRef = useRef<HTMLTableSectionElement | null>(null);
  const { tbodyProps, getRowProps } = useTableRowNav(
    sortedRows,
    (c) => navigate(`/vr/fuzz/campaigns/${c.id}`),
    tbodyRef,
  );

  return (
    <div className="space-y-4">

      <AilaCard  techBorder glow><div className="flex items-center gap-2 flex-wrap">
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Filter campaigns (name / engine / strategy)…"
          aria-label="Filter fuzz campaigns"
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
      
        <label className="text-sm text-text-muted ml-2">Status:</label>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value as CampaignStatus | "")}
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
      
        <span className="text-xs text-text-muted ml-auto">
          {query.trim()
            ? `${sortedRows.length} of ${rows.length} campaign${rows.length === 1 ? "" : "s"}`
            : `${rows.length} campaign${rows.length === 1 ? "" : "s"}`}
        </span>
      </div></AilaCard>

      {isLoading && <LoadingSkeleton size="lg" width="full" />}

      {isError && (
        <AilaCard className="border-border-danger" techBorder glow><p className="text-sm text-text-danger">Failed to load campaigns.</p></AilaCard>
      )}

      {!isLoading && !isError && rows.length === 0 && (
        <EmptyState
          icon={<Lightning className="h-7 w-7" weight="duotone" />}
          title="No fuzz campaigns yet"
          description="Campaigns get proposed by the reasoning agent (accept them from an investigation's Fuzz proposals panel) or created directly via POST /vr/fuzz/campaigns."
        />
      )}
      {!isLoading && !isError && rows.length > 0 && (
        <AilaCard className="overflow-x-auto p-0" techBorder glow><table className="w-full text-sm">
          <caption className="sr-only">Fuzz campaigns</caption>
          <thead>
            <tr className="border-b border-border-default text-left text-xs uppercase tracking-wide text-text-muted">
              <SortHeader columnKey="name" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort}>Name</SortHeader>
              <SortHeader columnKey="engine_id" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort}>Engine</SortHeader>
              <SortHeader columnKey="strategy_id" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort}>Strategy</SortHeader>
              <SortHeader columnKey="status" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort}>Status</SortHeader>
              <SortHeader columnKey="total_execs" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort} align="right">Execs</SortHeader>
              <SortHeader columnKey="corpus_size" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort} align="right">Corpus</SortHeader>
              <SortHeader columnKey="coverage_pct" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort} align="right">Cov %</SortHeader>
              <SortHeader columnKey="crashes_found" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort} align="right">Crashes</SortHeader>
              <SortHeader columnKey="last_progress_at" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort}>Last progress</SortHeader>
              <th className="px-2 py-2"></th>
            </tr>
          </thead>
          <tbody ref={tbodyRef} {...tbodyProps}>
            {sortedRows.map((c, idx) => {
              const rowProps = getRowProps(idx);
              return (
              <tr
                key={c.id}
                {...rowProps}
                onClick={() => navigate(`/vr/fuzz/campaigns/${c.id}`)}
                className={
                  "border-b border-border-default last:border-b-0 cursor-pointer hover:bg-surface transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-inset " +
                  (rowProps["data-row-active"] ? "bg-elevated" : "")
                }
              >
                <td className="px-4 py-2 font-semibold text-foreground">
                  {c.name}
                </td>
                <td className="px-4 py-2 font-mono text-xs">{c.engine_id}</td>
                <td className="px-4 py-2 font-mono text-xs">
                  {c.strategy_id}
                </td>
                <td className="px-4 py-2">
                  <AilaBadge severity={STATUS_COLOR[c.status]} size="sm">
                    {c.status}
                  </AilaBadge>
                </td>
                <td className="px-4 py-2 font-mono text-xs text-right">
                  {c.total_execs.toLocaleString()}
                </td>
                <td className="px-4 py-2 font-mono text-xs text-right">
                  {c.corpus_size.toLocaleString()}
                </td>
                <td className="px-4 py-2 font-mono text-xs text-right">
                  {c.coverage_pct != null
                    ? `${c.coverage_pct.toFixed(2)}%`
                    : "--"}
                </td>
                <td className="px-4 py-2 font-mono text-xs text-right">
                  {c.crashes_found}
                </td>
                <td className="px-4 py-2 font-mono text-xs text-text-muted">
                  {c.last_progress_at
                    ? new Date(c.last_progress_at).toLocaleString()
                    : "--"}
                </td>
                <td className="px-2 py-2 text-right">
                  <DeleteButton
                    id={c.id}
                    label={`fuzz campaign "${c.name}"`}
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
