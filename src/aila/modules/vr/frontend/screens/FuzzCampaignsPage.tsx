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
import { useDeleteFuzzCampaign } from "../mutations";
import { useFuzzCampaigns, useWorkspaces } from "../queries";
import { useVRListInvalidation } from "../hooks/useVRListInvalidation";
import type { CampaignStatus, VRFuzzCampaignSummary } from "../types";

// Status -> MonoBadge tone.
const STATUS_TONE: Record<CampaignStatus, string> = {
  created: "info",
  running: "medium",
  paused: "info",
  completed: "ok",
  failed: "high",
  aborted: "high",
};

const STATUSES: CampaignStatus[] = [
  "created",
  "running",
  "paused",
  "completed",
  "failed",
  "aborted",
];

// Mock chrome for raw form controls -- matches sibling filter shelves.
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

  // ─── Filter shelf ───
  const filterShelf = (
    <WindowPanel title="filters" tone="muted">
      <div className="flex flex-wrap items-center" style={{ gap: 8 }}>
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="filter (name / engine / strategy)…"
          aria-label="Filter fuzz campaigns"
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
          value={statusFilter}
          onChange={(e) =>
            setStatusFilter(e.target.value as CampaignStatus | "")
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
            ? `${filteredRows.length} of ${rows.length}`
            : `${rows.length}`}
          {" "}campaign{rows.length === 1 ? "" : "s"}
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
    { label: "name", width: "1fr" },
    { label: "engine", width: "120px" },
    { label: "strategy", width: "120px" },
    { label: "status", width: "100px" },
    { label: "execs", width: "90px", align: "right" },
    { label: "corpus", width: "80px", align: "right" },
    { label: "cov %", width: "70px", align: "right" },
    { label: "crashes", width: "80px", align: "right" },
    { label: "last progress", width: "150px" },
    { label: "", width: "40px", align: "center" },
  ];

  function renderCells(c: VRFuzzCampaignSummary): React.ReactNode[] {
    return [
      <span
        className="font-mono"
        title={c.name}
        style={{
          fontSize: 11.5,
          color: "var(--text-primary)",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          display: "block",
        }}
      >
        {c.name}
      </span>,
      <span
        className="font-mono"
        style={{ fontSize: 10.5, color: "var(--text-muted)" }}
      >
        {c.engine_id}
      </span>,
      <span
        className="font-mono"
        style={{ fontSize: 10.5, color: "var(--text-muted)" }}
      >
        {c.strategy_id}
      </span>,
      <MonoBadge tone={STATUS_TONE[c.status]}>{c.status}</MonoBadge>,
      <span
        className="font-mono"
        style={{ fontSize: 11, color: "var(--text-primary)" }}
      >
        {c.total_execs.toLocaleString()}
      </span>,
      <span
        className="font-mono"
        style={{ fontSize: 11, color: "var(--text-primary)" }}
      >
        {c.corpus_size.toLocaleString()}
      </span>,
      <span
        className="font-mono"
        style={{ fontSize: 11, color: "var(--text-primary)" }}
      >
        {c.coverage_pct != null ? `${c.coverage_pct.toFixed(2)}%` : "--"}
      </span>,
      <span
        className="font-mono"
        style={{
          fontSize: 11,
          color:
            c.crashes_found > 0
              ? "var(--accent)"
              : "var(--text-primary)",
        }}
      >
        {c.crashes_found}
      </span>,
      <span
        className="font-mono"
        style={{ fontSize: 10, color: "var(--text-faint)" }}
      >
        {c.last_progress_at
          ? new Date(c.last_progress_at).toLocaleString()
          : "--"}
      </span>,
      <span onClick={(e) => e.stopPropagation()}>
        <DeleteButton
          id={c.id}
          label={`fuzz campaign "${c.name}"`}
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
      {filteredRows.length}
      <span style={{ opacity: 0.5 }}> / {rows.length}</span>
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
        failed to load campaigns.
      </div>
    );
  } else {
    tableBody = (
      <DataGrid
        columns={columns}
        rows={filteredRows}
        renderCells={renderCells}
        getKey={(c) => c.id}
        onRowClick={(c) => navigate(`/vr/fuzz/campaigns/${c.id}`)}
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
            {query.trim() || workspaceFilter || statusFilter
              ? "no campaigns match the current filters."
              : "no fuzz campaigns yet -- propose one from an investigation's fuzz panel."}
          </div>
        }
      />
    );
  }

  return (
    <div className="flex flex-col" style={{ gap: 14 }}>
      <SectionHeader icon="◈" title="Fuzz Campaigns" />
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
