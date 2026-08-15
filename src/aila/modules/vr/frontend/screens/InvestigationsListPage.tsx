import { useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from "react";
import { useNavigate } from "react-router";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";
import {
  BigStat,
  FilterChip,
  MonoBadge,
  SectionHeader,
  Segmented,
  StatBar,
} from "@/components/aila/mock";

import { DeleteButton } from "../components/DeleteButton";
import { SavedViews } from "../components/SavedViews";
import {
  useDebouncedValue,
  useTableRowNav,
} from "../components/tableHelpers";
import {
  useCreateInvestigation,
  useDeleteInvestigation,
  useToggleInvestigationFavorite,
} from "../mutations";
import {
  useInvestigations,
  useTargetMap,
  useTargets,
  useWorkspaces,
} from "../queries";
import { useVRListInvalidation } from "../hooks/useVRListInvalidation";
import type {
  InvestigationKind,
  InvestigationStatus,
  VRInvestigationSummary,
} from "../types";

// ─────────────────────────────────────────────────────────────────────
// Status vocabulary (mock tokens only).
//   STATUS_TONE  → MonoBadge tone key
//   STATUS_HUE   → raw css var for status dots / StatBar rows
//   STATUS_LABEL → operator-visible label (matches vr-persona-contract)
// ─────────────────────────────────────────────────────────────────────
const STATUS_TONE: Record<InvestigationStatus, string> = {
  created: "muted",
  running: "ok",
  paused: "warn",
  completed: "info",
  failed: "critical",
  abandoned: "muted",
  stalled: "muted",
};

const STATUS_HUE: Record<InvestigationStatus, string> = {
  created: "var(--text-faint)",
  running: "var(--status-ok)",
  paused: "var(--status-warn)",
  completed: "var(--status-info)",
  failed: "var(--accent)",
  abandoned: "var(--text-faint)",
  stalled: "var(--text-faint)",
};

const STATUS_LABEL: Record<InvestigationStatus, string> = {
  created: "created",
  running: "running",
  paused: "paused",
  completed: "completed",
  failed: "failed",
  abandoned: "abandoned",
  stalled: "stalled",
};

// Smart-sort tier: live and actionable first.
const STATUS_PRIORITY: Record<InvestigationStatus, number> = {
  running: 0,
  paused: 1,
  completed: 2,
  failed: 3,
  stalled: 4,
  created: 5,
  abandoned: 6,
};

const STATUS_ORDER: InvestigationStatus[] = [
  "running",
  "paused",
  "completed",
  "failed",
  "created",
  "stalled",
  "abandoned",
];

type SortMode = "smart" | "newest" | "cost";

const SORT_OPTIONS: { value: SortMode; label: string }[] = [
  { value: "smart", label: "smart" },
  { value: "newest", label: "newest" },
  { value: "cost", label: "cost" },
];

// ─────────────────────────────────────────────────────────────────────
// Pure helpers
// ─────────────────────────────────────────────────────────────────────
function relativeTime(value?: string | null): string {
  if (!value) return "--";
  const t = new Date(value).getTime();
  if (Number.isNaN(t)) return "--";
  const delta = Date.now() - t;
  const s = Math.floor(delta / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

function fmtCost(v: number): string {
  if (!Number.isFinite(v) || v <= 0) return "$0.00";
  if (v >= 100) return `$${v.toFixed(0)}`;
  return `$${v.toFixed(2)}`;
}

// ─────────────────────────────────────────────────────────────────────
// Mock chrome styles reused across raw <input>/<select> controls so the
// filter shelf stays visually coherent with FilterChip / Segmented.
// ─────────────────────────────────────────────────────────────────────
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
};

// Column grid track template shared by the honest-grid header + rows so
// keyboard navigation (data-row-index) still lives on the true row DOM.
const COL_TEMPLATE =
  "100px 1fr 100px 180px 80px 80px 90px 40px 100px 40px";

// ─────────────────────────────────────────────────────────────────────
// InvestigationsListPage
// ─────────────────────────────────────────────────────────────────────
export function InvestigationsListPage() {
  const navigate = useNavigate();
  useVRListInvalidation("investigations");

  // Filter surface -- every knob previously exposed on the page is preserved.
  const [searchQ, setSearchQ] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [kindFilter, setKindFilter] = useState<string>("");
  const [workspaceFilter, setWorkspaceFilter] = useState<string>("");
  const [verifierFilter, setVerifierFilter] = useState<string>("");
  const [findingsOnly, setFindingsOnly] = useState(false);
  const [favoritesOnly, setFavoritesOnly] = useState(false);
  const [hideCreated, setHideCreated] = useState(true);
  const [sortMode, setSortMode] = useState<SortMode>("smart");
  const [pageSize, setPageSize] = useState(100);
  const [offset, setOffset] = useState(0);

  const debouncedSearchQ = useDebouncedValue(searchQ.trim(), 300);

  const { data: result, isLoading, isError } = useInvestigations({
    offset,
    limit: pageSize,
    status: statusFilter || undefined,
    kind: kindFilter || undefined,
    q: debouncedSearchQ || undefined,
    favorites: favoritesOnly || undefined,
  });
  const targetMap = useTargetMap();
  const { data: targetsResult } = useTargets();
  const { data: workspacesResult } = useWorkspaces();
  const createMut = useCreateInvestigation();
  const deleteMut = useDeleteInvestigation();
  const favMut = useToggleInvestigationFavorite();

  const [showForm, setShowForm] = useState(false);
  const [formTitle, setFormTitle] = useState("");
  const [formQuestion, setFormQuestion] = useState("");
  const [formTargetId, setFormTargetId] = useState("");
  const [formKind, setFormKind] = useState<InvestigationKind>("discovery");
  const [formBudget, setFormBudget] = useState("50");

  const totalRaw =
    (result?.meta as { total?: number } | undefined)?.total ?? 0;
  const investigationsRaw = result?.data ?? [];
  const workspaces = workspacesResult?.data ?? [];
  const targets = targetsResult?.data ?? [];

  // Client-side filters that don't round-trip through the server.
  const filtered = useMemo(() => {
    let rows: VRInvestigationSummary[] = investigationsRaw;
    if (findingsOnly) {
      rows = rows.filter((i) => i.linked_finding_ids.length > 0);
    }
    if (verifierFilter) {
      rows = rows.filter(
        (i) => (i.verifier_verdict ?? "") === verifierFilter,
      );
    }
    if (workspaceFilter) {
      rows = rows.filter(
        (i) => targetMap.get(i.target_id)?.workspace_id === workspaceFilter,
      );
    }
    if (hideCreated && statusFilter !== "created") {
      rows = rows.filter((i) => i.status !== "created");
    }
    return rows;
  }, [
    investigationsRaw,
    findingsOnly,
    verifierFilter,
    workspaceFilter,
    hideCreated,
    statusFilter,
    targetMap,
  ]);

  // Status-mix distribution (uses the unfiltered server page so the operator
  // still sees the shape of what is hidden by their current status choice).
  const statusCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const s of STATUS_ORDER) counts[s] = 0;
    for (const i of investigationsRaw) {
      counts[i.status] = (counts[i.status] ?? 0) + 1;
    }
    return counts;
  }, [investigationsRaw]);

  const runningCount = statusCounts.running ?? 0;
  const statusMax = Math.max(1, ...STATUS_ORDER.map((s) => statusCounts[s] ?? 0));

  const sorted = useMemo(() => {
    const copy = [...filtered];
    if (sortMode === "cost") {
      copy.sort((a, b) => (b.cost_actual_usd ?? 0) - (a.cost_actual_usd ?? 0));
      return copy;
    }
    if (sortMode === "newest") {
      copy.sort((a, b) => {
        const at = a.created_at ? new Date(a.created_at).getTime() : 0;
        const bt = b.created_at ? new Date(b.created_at).getTime() : 0;
        return bt - at;
      });
      return copy;
    }
    // smart: status tier, then newest first.
    copy.sort((a, b) => {
      const ap = STATUS_PRIORITY[a.status] ?? 99;
      const bp = STATUS_PRIORITY[b.status] ?? 99;
      if (ap !== bp) return ap - bp;
      const at = a.created_at ? new Date(a.created_at).getTime() : 0;
      const bt = b.created_at ? new Date(b.created_at).getTime() : 0;
      return bt - at;
    });
    return copy;
  }, [filtered, sortMode]);

  // Roving-tabindex j/k/Enter nav over the flat honest grid.
  const listContainerRef = useRef<HTMLDivElement | null>(null);
  const {
    tbodyProps: listTbodyProps,
    getRowProps: listGetRowProps,
  } = useTableRowNav(
    sorted,
    (inv) => navigate(`/vr/investigations/${inv.id}`),
    listContainerRef,
  );

  function clearAllFilters() {
    setSearchQ("");
    setStatusFilter("");
    setKindFilter("");
    setWorkspaceFilter("");
    setVerifierFilter("");
    setFindingsOnly(false);
    setFavoritesOnly(false);
    setHideCreated(true);
    setSortMode("smart");
    setOffset(0);
  }

  // Saved-view round-trip: every filter/toggle captured, pagination excluded.
  const currentViewJson = JSON.stringify({
    v: 1,
    q: searchQ,
    status: statusFilter,
    kind: kindFilter,
    workspace: workspaceFilter,
    verifier: verifierFilter,
    findingsOnly,
    favoritesOnly,
    hideCreated,
    sortMode,
    pageSize,
  });

  function applyView(filterJson: string) {
    try {
      const p = JSON.parse(filterJson) as Record<string, unknown>;
      setSearchQ(typeof p.q === "string" ? p.q : "");
      setStatusFilter(typeof p.status === "string" ? p.status : "");
      setKindFilter(typeof p.kind === "string" ? p.kind : "");
      setWorkspaceFilter(
        typeof p.workspace === "string" ? p.workspace : "",
      );
      setVerifierFilter(typeof p.verifier === "string" ? p.verifier : "");
      setFindingsOnly(p.findingsOnly === true);
      setFavoritesOnly(p.favoritesOnly === true);
      setHideCreated(p.hideCreated !== false);
      if (
        p.sortMode === "smart" ||
        p.sortMode === "newest" ||
        p.sortMode === "cost"
      ) {
        setSortMode(p.sortMode);
      } else {
        setSortMode("smart");
      }
      if (typeof p.pageSize === "number" && p.pageSize > 0) {
        setPageSize(p.pageSize);
      }
      setOffset(0);
    } catch {
      // Malformed view -- ignore rather than blank the operator's screen.
    }
  }

  const hasActiveFilters =
    !!searchQ ||
    !!statusFilter ||
    !!kindFilter ||
    !!workspaceFilter ||
    !!verifierFilter ||
    findingsOnly ||
    favoritesOnly ||
    !hideCreated ||
    sortMode !== "smart";

  // ─── Section header actions: Compare + New investigation ───
  const headerActions = (
    <div className="flex items-center" style={{ gap: 8 }}>
      <button
        type="button"
        onClick={() => navigate("/vr/investigations/compare")}
        className="font-mono uppercase"
        style={{
          height: 28,
          padding: "0 12px",
          fontSize: 10,
          letterSpacing: "0.08em",
          background: "var(--surface-sunk)",
          border: "1px solid var(--border-soft)",
          color: "var(--text-primary)",
          borderRadius: 3,
          cursor: "pointer",
        }}
        title="Compare investigations side by side"
      >
        compare
      </button>
      <button
        type="button"
        onClick={() => setShowForm((v) => !v)}
        className="font-mono uppercase"
        style={{
          height: 28,
          padding: "0 12px",
          fontSize: 10,
          letterSpacing: "0.08em",
          background: showForm ? "var(--surface-sunk)" : "var(--accent)",
          border: "1px solid " + (showForm ? "var(--border-soft)" : "var(--accent)"),
          color: showForm ? "var(--text-primary)" : "var(--text-on-accent)",
          borderRadius: 3,
          cursor: "pointer",
        }}
      >
        {showForm ? "cancel" : "+ new"}
      </button>
    </div>
  );

  // ─── Create form (mock language) ───
  const createFormPanel = showForm ? (
    <WindowPanel title="new investigation" tone="accent">
      <div className="flex flex-col" style={{ gap: 10 }}>
        <input
          type="text"
          value={formTitle}
          onChange={(e) => setFormTitle(e.target.value)}
          placeholder="title (e.g. audit V8 InferMaps for missing alias check)"
          aria-label="Investigation title"
          className="font-mono w-full"
          style={{ ...CTRL, height: 30, fontSize: 11 }}
        />
        <textarea
          value={formQuestion}
          onChange={(e) => setFormQuestion(e.target.value)}
          placeholder="initial question -- what should the engine investigate?"
          rows={3}
          aria-label="Initial question"
          className="font-mono w-full"
          style={{
            ...CTRL,
            height: "auto",
            padding: "8px 10px",
            fontSize: 11,
            resize: "vertical",
          }}
        />
        {(() => {
          const byWs = new Map<string, typeof targets>();
          for (const t of targets) {
            const arr = byWs.get(t.workspace_id) ?? [];
            arr.push(t);
            byWs.set(t.workspace_id, arr);
          }
          const wsName = (id: string) =>
            workspaces.find((w) => w.id === id)?.name ?? "(unknown workspace)";
          const orderedWsIds = Array.from(byWs.keys()).sort((a, b) =>
            wsName(a).localeCompare(wsName(b)),
          );
          if (targetsResult === undefined) {
            return (
              <div
                className="font-mono"
                style={{ ...CTRL, height: 30, display: "flex", alignItems: "center", color: "var(--text-muted)" }}
              >
                loading targets…
              </div>
            );
          }
          if (targets.length === 0) {
            return (
              <div
                className="font-mono"
                style={{
                  ...CTRL,
                  height: 30,
                  display: "flex",
                  alignItems: "center",
                  color: "var(--accent)",
                  borderColor: "var(--accent)",
                }}
              >
                no targets exist yet -- create one under workspaces → targets before starting an investigation.
              </div>
            );
          }
          return (
            <select
              value={formTargetId}
              onChange={(e) => setFormTargetId(e.target.value)}
              aria-label="Target"
              className="font-mono w-full"
              style={{ ...CTRL, height: 30, fontSize: 11 }}
            >
              <option value="">-- pick a target --</option>
              {orderedWsIds.map((wsId) => (
                <optgroup key={wsId} label={wsName(wsId)}>
                  {(byWs.get(wsId) ?? [])
                    .slice()
                    .sort((a, b) =>
                      a.display_name.localeCompare(b.display_name),
                    )
                    .map((t) => (
                      <option key={t.id} value={t.id}>
                        {t.display_name} · {t.kind} · {t.primary_language ?? "--"} · {t.analysis_state}
                      </option>
                    ))}
                </optgroup>
              ))}
            </select>
          );
        })()}
        <div className="flex flex-wrap items-center" style={{ gap: 8 }}>
          <select
            value={formKind}
            onChange={(e) => setFormKind(e.target.value as InvestigationKind)}
            aria-label="Investigation kind"
            className="font-mono uppercase"
            style={CTRL}
          >
            <option value="discovery">discovery</option>
            <option value="variant_hunt">variant_hunt</option>
            <option value="triage">triage</option>
            <option value="n_day">n_day</option>
            <option value="audit">audit</option>
          </select>
          <div
            className="flex items-center font-mono"
            style={{
              ...CTRL,
              padding: "0 8px",
              gap: 6,
              color: "var(--text-muted)",
            }}
          >
            <span style={{ fontSize: 10, letterSpacing: "0.08em" }}>budget $</span>
            <input
              type="number"
              step="1"
              min="0"
              value={formBudget}
              onChange={(e) => setFormBudget(e.target.value)}
              aria-label="Budget USD"
              className="font-mono"
              style={{
                width: 56,
                background: "transparent",
                border: 0,
                color: "var(--text-primary)",
                fontSize: 10.5,
                outline: "none",
              }}
            />
          </div>
          <button
            type="button"
            disabled={
              !formTitle.trim() ||
              !formQuestion.trim() ||
              !formTargetId.trim() ||
              createMut.isPending
            }
            onClick={() => {
              const budget = parseFloat(formBudget);
              createMut.mutate(
                {
                  title: formTitle.trim(),
                  initial_question: formQuestion.trim(),
                  target_id: formTargetId.trim(),
                  kind: formKind,
                  cost_budget_usd: Number.isFinite(budget) ? budget : 50,
                },
                {
                  onSuccess: (created) => {
                    setShowForm(false);
                    setFormTitle("");
                    setFormQuestion("");
                    setFormTargetId("");
                    setFormKind("discovery");
                    setFormBudget("50");
                    navigate(`/vr/investigations/${created.data.id}`);
                  },
                },
              );
            }}
            className="font-mono uppercase"
            style={{
              marginLeft: "auto",
              height: 28,
              padding: "0 14px",
              fontSize: 10,
              letterSpacing: "0.08em",
              background: "var(--accent)",
              border: "1px solid var(--accent)",
              color: "var(--text-on-accent)",
              borderRadius: 3,
              cursor: createMut.isPending ? "wait" : "pointer",
              opacity: createMut.isPending ? 0.7 : 1,
            }}
          >
            {createMut.isPending ? "creating…" : "start investigation"}
          </button>
        </div>
      </div>
    </WindowPanel>
  ) : null;

  // ─── Filter shelf ───
  const filterShelf = (
    <WindowPanel title="filters" tone="muted">
      <div className="flex flex-col" style={{ gap: 10 }}>
        <div className="flex flex-wrap items-center" style={{ gap: 8 }}>
          <input
            type="search"
            value={searchQ}
            onChange={(e) => {
              setSearchQ(e.target.value);
              setOffset(0);
            }}
            placeholder="search title (ILIKE)…"
            aria-label="Search investigations"
            className="font-mono"
            style={{ ...CTRL, width: 260 }}
          />
          <select
            value={kindFilter}
            onChange={(e) => {
              setKindFilter(e.target.value);
              setOffset(0);
            }}
            aria-label="Filter by kind"
            className="font-mono uppercase"
            style={CTRL}
          >
            <option value="">all kind</option>
            <option value="discovery">discovery</option>
            <option value="variant_hunt">variant_hunt</option>
            <option value="triage">triage</option>
            <option value="n_day">n_day</option>
            <option value="audit">audit</option>
          </select>
          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setOffset(0);
            }}
            aria-label="Filter by status"
            className="font-mono uppercase"
            style={CTRL}
          >
            <option value="">all status</option>
            {STATUS_ORDER.map((s) => (
              <option key={s} value={s}>
                {STATUS_LABEL[s]}
                {statusCounts[s] ? ` (${statusCounts[s]})` : ""}
              </option>
            ))}
          </select>
          <select
            value={verifierFilter}
            onChange={(e) => {
              setVerifierFilter(e.target.value);
              setOffset(0);
            }}
            aria-label="Filter by verifier verdict"
            className="font-mono uppercase"
            style={CTRL}
          >
            <option value="">all verifier</option>
            <option value="confirmed">confirmed</option>
            <option value="refuted">refuted</option>
            <option value="inconclusive">inconclusive</option>
          </select>
          <select
            value={workspaceFilter}
            onChange={(e) => {
              setWorkspaceFilter(e.target.value);
              setOffset(0);
            }}
            aria-label="Filter by workspace"
            className="font-mono uppercase"
            style={CTRL}
          >
            <option value="">all workspaces</option>
            {workspaces
              .slice()
              .sort((a, b) => a.name.localeCompare(b.name))
              .map((w) => (
                <option key={w.id} value={w.id}>
                  {w.name}
                </option>
              ))}
          </select>
          <FilterChip
            active={favoritesOnly}
            color="var(--status-warn)"
            onClick={() => {
              setFavoritesOnly((v) => !v);
              setOffset(0);
            }}
          >
            ★ favorites
          </FilterChip>
          <FilterChip
            active={findingsOnly}
            color="var(--status-ok)"
            onClick={() => setFindingsOnly((v) => !v)}
          >
            findings only
          </FilterChip>
          <FilterChip
            active={hideCreated}
            color="var(--accent)"
            onClick={() => setHideCreated((v) => !v)}
          >
            hide created
          </FilterChip>
          {hasActiveFilters ? (
            <FilterChip active={false} onClick={clearAllFilters}>
              ✕ clear
            </FilterChip>
          ) : null}
          <span style={{ flex: 1 }} />
          <Segmented<SortMode>
            options={SORT_OPTIONS}
            value={sortMode}
            onChange={setSortMode}
          />
        </div>
        <div style={{ minHeight: 26 }}>
          <SavedViews
            entityType="vr_investigation"
            entityLabel="investigations"
            currentFilterJson={currentViewJson}
            onApply={applyView}
          />
        </div>
      </div>
    </WindowPanel>
  );

  // ─── Stats trio ───
  const statsRow = (
    <div
      className="grid"
      style={{
        gridTemplateColumns: "1fr 1fr 1.6fr",
        gap: 12,
      }}
    >
      <WindowPanel title="total" tone="info">
        <BigStat value={totalRaw.toLocaleString()} sub="investigations" />
      </WindowPanel>
      <WindowPanel title="live" tone="ok">
        <BigStat value={runningCount.toLocaleString()} sub="running" />
      </WindowPanel>
      <WindowPanel title="status mix" tone="muted">
        <div className="flex flex-col" style={{ gap: 6 }}>
          {STATUS_ORDER.map((s) => (
            <StatBar
              key={s}
              label={STATUS_LABEL[s]}
              color={STATUS_HUE[s]}
              value={statusCounts[s] ?? 0}
              max={statusMax}
            />
          ))}
        </div>
      </WindowPanel>
    </div>
  );

  // ─── Main table (honest grid with keyboard nav) ───
  const columns: {
    label: string;
    width: string;
    align?: "left" | "right" | "center";
  }[] = [
    { label: "status", width: "100px" },
    { label: "title", width: "1fr" },
    { label: "kind", width: "100px" },
    { label: "target", width: "180px" },
    { label: "branches", width: "80px", align: "right" },
    { label: "outcomes", width: "80px", align: "right" },
    { label: "cost", width: "90px", align: "right" },
    { label: "fav", width: "40px", align: "center" },
    { label: "updated", width: "100px", align: "right" },
    { label: "", width: "40px", align: "center" },
  ];

  function renderCells(inv: VRInvestigationSummary): React.ReactNode[] {
    const targetName =
      targetMap.get(inv.target_id)?.display_name ?? "loading…";
    return [
      <MonoBadge tone={STATUS_TONE[inv.status]} title={STATUS_LABEL[inv.status]}>
        {STATUS_LABEL[inv.status]}
      </MonoBadge>,
      <span
        className="font-mono"
        title={inv.title}
        style={{
          fontSize: 11.5,
          color: "var(--text-primary)",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          display: "block",
        }}
      >
        {inv.title}
      </span>,
      <MonoBadge tone="muted">{inv.kind}</MonoBadge>,
      <span
        className="font-mono"
        title={targetName}
        style={{
          fontSize: 10.5,
          color: "var(--text-muted)",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          display: "block",
        }}
      >
        {targetName}
      </span>,
      <span
        className="font-mono"
        style={{ fontSize: 11, color: "var(--text-primary)" }}
      >
        {inv.branch_count}
      </span>,
      <span
        className="font-mono"
        style={{ fontSize: 11, color: "var(--text-primary)" }}
      >
        {inv.outcome_count}
      </span>,
      <span
        className="font-mono"
        title={`budget ${fmtCost(inv.cost_budget_usd)}`}
        style={{
          fontSize: 11,
          color:
            inv.cost_budget_usd > 0 &&
            inv.cost_actual_usd >= inv.cost_budget_usd
              ? "var(--accent)"
              : "var(--text-primary)",
        }}
      >
        {fmtCost(inv.cost_actual_usd)}
      </span>,
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          favMut.mutate(inv.id);
        }}
        title={inv.is_favorite ? "Unfavorite" : "Favorite"}
        aria-label={inv.is_favorite ? "Unfavorite" : "Favorite"}
        className="font-mono"
        style={{
          background: "transparent",
          border: 0,
          padding: 0,
          fontSize: 14,
          lineHeight: 1,
          cursor: "pointer",
          color: inv.is_favorite
            ? "var(--status-warn)"
            : "var(--text-faint)",
        }}
      >
        {inv.is_favorite ? "★" : "☆"}
      </button>,
      <span
        className="font-mono"
        title={inv.updated_at ?? inv.created_at ?? ""}
        style={{
          fontSize: 10,
          color: "var(--text-faint)",
          whiteSpace: "nowrap",
        }}
      >
        {relativeTime(inv.updated_at ?? inv.created_at)}
      </span>,
      <span onClick={(e) => e.stopPropagation()}>
        <DeleteButton
          id={inv.id}
          label={`investigation "${inv.title}"`}
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
      {sorted.length}
      <span style={{ opacity: 0.5 }}> / {totalRaw}</span>
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
        failed to load investigations.
      </div>
    );
  } else {
    tableBody = (
      <HonestGrid
        columns={columns}
        rows={sorted}
        renderCells={renderCells}
        getKey={(inv) => inv.id}
        onRowClick={(inv) => navigate(`/vr/investigations/${inv.id}`)}
        containerRef={listContainerRef}
        onKeyDown={listTbodyProps.onKeyDown}
        getRowProps={listGetRowProps}
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
            {hasActiveFilters
              ? "no investigations match the current filters."
              : "no investigations yet -- start one from the header."}
          </div>
        }
      />
    );
  }

  // ─── Pagination footer (mock language) ───
  const pageEnd = Math.min(offset + sorted.length, totalRaw);
  const pagination =
    !isLoading && !isError && totalRaw > pageSize ? (
      <div
        className="flex items-center justify-between font-mono"
        style={{
          padding: "8px 12px",
          border: "1px solid var(--border-soft)",
          background: "var(--surface-sunk)",
          borderRadius: 3,
          fontSize: 10.5,
          color: "var(--text-muted)",
          letterSpacing: "0.04em",
        }}
      >
        <span>
          {offset + 1}–{pageEnd} of {totalRaw}
        </span>
        <div className="flex items-center" style={{ gap: 8 }}>
          <select
            value={pageSize}
            onChange={(e) => {
              setPageSize(parseInt(e.target.value, 10));
              setOffset(0);
            }}
            title="Page size"
            className="font-mono"
            style={CTRL}
          >
            <option value="50">50 / page</option>
            <option value="100">100 / page</option>
            <option value="200">200 / page</option>
            <option value="500">500 / page</option>
          </select>
          <button
            type="button"
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - pageSize))}
            className="font-mono uppercase"
            style={{
              ...CTRL,
              cursor: offset === 0 ? "not-allowed" : "pointer",
              opacity: offset === 0 ? 0.4 : 1,
            }}
          >
            ← prev
          </button>
          <button
            type="button"
            disabled={offset + pageSize >= totalRaw}
            onClick={() => setOffset(offset + pageSize)}
            className="font-mono uppercase"
            style={{
              ...CTRL,
              cursor:
                offset + pageSize >= totalRaw ? "not-allowed" : "pointer",
              opacity: offset + pageSize >= totalRaw ? 0.4 : 1,
            }}
          >
            next →
          </button>
        </div>
      </div>
    ) : null;

  return (
    <div className="flex flex-col" style={{ gap: 14 }}>
      <SectionHeader icon="◈" title="Investigations" actions={headerActions} />
      {createFormPanel}
      {filterShelf}
      {statsRow}
      <WindowPanel title="investigations" tone="accent" actions={tableActions} flush>
        {tableBody}
      </WindowPanel>
      {pagination}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────
// HonestGrid -- local table variant that mirrors the mock DataGrid look
// but accepts per-row keyboard-nav props (data-row-index / tabIndex /
// aria-selected) supplied by `useTableRowNav`. The shared DataGrid in
// @/components/aila/mock intentionally has no rowProps hook, so this
// page composes its own grid at the same visual grammar.
// ─────────────────────────────────────────────────────────────────────
interface HonestColumn {
  label: React.ReactNode;
  width: string;
  align?: "left" | "right" | "center";
}

function HonestGrid<T>({
  columns,
  rows,
  renderCells,
  getKey,
  onRowClick,
  containerRef,
  onKeyDown,
  getRowProps,
  empty,
}: {
  columns: HonestColumn[];
  rows: T[];
  renderCells: (row: T, index: number) => React.ReactNode[];
  getKey: (row: T, index: number) => React.Key;
  onRowClick?: (row: T, index: number) => void;
  containerRef?: React.RefObject<HTMLDivElement | null>;
  onKeyDown?: (event: ReactKeyboardEvent<HTMLElement>) => void;
  getRowProps?: (idx: number) => {
    tabIndex: number;
    "aria-selected": boolean;
    "data-row-index": number;
    "data-row-active"?: "true";
    onFocus: () => void;
  };
  empty?: React.ReactNode;
}) {
  const template = columns.map((c) => c.width).join(" ");
  return (
    <div>
      <div
        className="grid font-mono uppercase"
        style={{
          gridTemplateColumns: template,
          gap: 10,
          padding: "8px 12px",
          background: "var(--surface-sunk)",
          borderBottom: "1px solid var(--border-soft)",
          fontSize: 9,
          letterSpacing: "0.14em",
          color: "var(--text-faint)",
        }}
      >
        {columns.map((c, i) => (
          <span key={i} style={{ textAlign: c.align }}>
            {c.label}
          </span>
        ))}
      </div>
      <div
        ref={containerRef}
        role="listbox"
        onKeyDown={onKeyDown}
        style={{ background: "var(--surface-card)" }}
      >
        {rows.length === 0
          ? empty
          : rows.map((r, ri) => {
              const rowProps = getRowProps ? getRowProps(ri) : undefined;
              return (
                <div
                  key={getKey(r, ri)}
                  role="option"
                  onClick={onRowClick ? () => onRowClick(r, ri) : undefined}
                  {...(rowProps ?? {})}
                  className="grid font-mono"
                  style={{
                    gridTemplateColumns: template,
                    gap: 10,
                    padding: "8px 12px",
                    borderBottom: "1px solid var(--border-faint)",
                    background: rowProps?.["data-row-active"]
                      ? "var(--surface-hover)"
                      : "var(--surface-card)",
                    alignItems: "center",
                    cursor: onRowClick ? "pointer" : undefined,
                    outline: "none",
                  }}
                >
                  {renderCells(r, ri).map((cell, ci) => (
                    <span
                      key={ci}
                      style={{
                        minWidth: 0,
                        textAlign: columns[ci]?.align,
                        overflow: "hidden",
                      }}
                    >
                      {cell}
                    </span>
                  ))}
                </div>
              );
            })}
      </div>
    </div>
  );
}
