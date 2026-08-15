import {
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
} from "react";
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

import { SavedViews } from "../components/SavedViews";
import {
  useSortableRows,
  useTableRowNav,
  type SortDir,
  type SortValue,
} from "../components/tableHelpers";
import { useAllFindings } from "../queries";
import { useVRListInvalidation } from "../hooks/useVRListInvalidation";
import type { DisclosureStatus, VRFinding } from "../types";

// ─────────────────────────────────────────────────────────────────────
// Vocabulary -- disclosure tone mapping (mock tokens only).
// ─────────────────────────────────────────────────────────────────────
const DISCLOSURE_TONE: Record<DisclosureStatus, string> = {
  undisclosed: "warn",
  reported: "info",
  acknowledged: "info",
  patch_pending: "info",
  patched: "ok",
  public: "ok",
};

const DISCLOSURE_HUE: Record<DisclosureStatus, string> = {
  undisclosed: "var(--status-warn)",
  reported: "var(--status-info)",
  acknowledged: "var(--status-info)",
  patch_pending: "var(--status-info)",
  patched: "var(--status-ok)",
  public: "var(--status-ok)",
};

const DISCLOSURE_ORDER: DisclosureStatus[] = [
  "undisclosed",
  "reported",
  "acknowledged",
  "patch_pending",
  "patched",
  "public",
];

// Severity bands mirror the CVE scoring specification. `unscored` covers
// findings with no cvss_score so the operator sees what fraction of the
// current view lacks a score.
type SeverityBand = "critical" | "high" | "medium" | "low" | "unscored";

const SEVERITY_BANDS: ReadonlyArray<{
  key: SeverityBand;
  label: string;
  test: (score: number | null) => boolean;
  hue: string;
  tone: string;
}> = [
  {
    key: "critical",
    label: "critical",
    test: (s) => s != null && s >= 9,
    hue: "var(--accent)",
    tone: "critical",
  },
  {
    key: "high",
    label: "high",
    test: (s) => s != null && s >= 7 && s < 9,
    hue: "var(--status-warn)",
    tone: "warn",
  },
  {
    key: "medium",
    label: "medium",
    test: (s) => s != null && s >= 4 && s < 7,
    hue: "var(--status-info)",
    tone: "info",
  },
  {
    key: "low",
    label: "low",
    test: (s) => s != null && s > 0 && s < 4,
    hue: "var(--status-ok)",
    tone: "ok",
  },
  {
    key: "unscored",
    label: "unscored",
    test: (s) => s == null || s === 0,
    hue: "var(--text-faint)",
    tone: "muted",
  },
];

function bandFor(score: number | null | undefined): SeverityBand {
  const s = score ?? null;
  for (const b of SEVERITY_BANDS) if (b.test(s)) return b.key;
  return "unscored";
}

type SortMode = "smart" | "severity" | "newest" | "evidence";

const SORT_OPTIONS: { value: SortMode; label: string }[] = [
  { value: "smart", label: "smart" },
  { value: "severity", label: "severity" },
  { value: "newest", label: "newest" },
  { value: "evidence", label: "evidence" },
];

// Mock chrome control style shared by raw <input>/<select>.
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

// ─────────────────────────────────────────────────────────────────────
// Saved-view payload -- version-tagged so a future schema change can
// migrate old payloads instead of silently accepting garbage.
// ─────────────────────────────────────────────────────────────────────
interface FindingsViewPayload {
  v: 1;
  q?: string;
  status?: DisclosureStatus | "";
  crash?: string;
  severities?: SeverityBand[];
  sortKey?: string;
  sortDir?: SortDir;
  sortMode?: SortMode;
}

function serializeFindingsView(payload: FindingsViewPayload): string {
  return JSON.stringify({
    v: 1,
    q: payload.q ?? "",
    status: payload.status ?? "",
    crash: payload.crash ?? "",
    severities: (payload.severities ?? []).slice().sort(),
    sortKey: payload.sortKey ?? "",
    sortDir: payload.sortDir ?? null,
    sortMode: payload.sortMode ?? "smart",
  });
}

function parseFindingsView(raw: string): FindingsViewPayload | null {
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== "object") return null;
    const p = parsed as Partial<FindingsViewPayload> & {
      severities?: unknown;
      sortMode?: unknown;
    };
    const validBands: SeverityBand[] = [];
    if (Array.isArray(p.severities)) {
      for (const s of p.severities) {
        if (
          s === "critical" ||
          s === "high" ||
          s === "medium" ||
          s === "low" ||
          s === "unscored"
        ) {
          validBands.push(s);
        }
      }
    }
    const sm = p.sortMode;
    const sortMode: SortMode =
      sm === "smart" || sm === "severity" || sm === "newest" || sm === "evidence"
        ? sm
        : "smart";
    return {
      v: 1,
      q: typeof p.q === "string" ? p.q : "",
      status: (p.status ?? "") as DisclosureStatus | "",
      crash: typeof p.crash === "string" ? p.crash : "",
      severities: validBands,
      sortKey: typeof p.sortKey === "string" ? p.sortKey : "",
      sortDir:
        p.sortDir === "asc" || p.sortDir === "desc" ? p.sortDir : null,
      sortMode,
    };
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────
// FindingsListPage
// ─────────────────────────────────────────────────────────────────────
export function FindingsListPage() {
  const navigate = useNavigate();
  useVRListInvalidation("findings");
  const [statusFilter, setStatusFilter] = useState<DisclosureStatus | "">("");
  const [crashFilter, setCrashFilter] = useState("");
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<Set<SeverityBand>>(
    () => new Set(),
  );
  const [sortMode, setSortMode] = useState<SortMode>("smart");

  const { data, isLoading, isError } = useAllFindings({
    disclosureStatus: statusFilter || undefined,
    crashType: crashFilter || undefined,
    limit: 200,
  });
  const rows = useMemo<VRFinding[]>(() => data?.data ?? [], [data]);

  const filteredRows = useMemo(() => {
    const needle = query.trim().toLowerCase();
    let out = rows;
    if (needle) {
      out = out.filter((r) => {
        const rootHead = (r.root_cause || "").split("\n")[0] ?? "";
        return (
          (r.vulnerable_function ?? "").toLowerCase().includes(needle) ||
          (r.crash_type ?? "").toLowerCase().includes(needle) ||
          (r.cwe_id ?? "").toLowerCase().includes(needle) ||
          (r.assigned_cve_id ?? "").toLowerCase().includes(needle) ||
          (r.disclosure_status ?? "").toLowerCase().includes(needle) ||
          (r.project_id ?? "").toLowerCase().includes(needle) ||
          rootHead.toLowerCase().includes(needle)
        );
      });
    }
    if (severityFilter.size > 0) {
      out = out.filter((r) => severityFilter.has(bandFor(r.cvss_score)));
    }
    return out;
  }, [rows, query, severityFilter]);

  const accessors = useMemo<
    Record<string, (r: VRFinding) => SortValue>
  >(
    () => ({
      vulnerable_function: (r) => {
        if (r.vulnerable_function) return r.vulnerable_function;
        const rootHead = (r.root_cause || "").split("\n")[0]?.trim() ?? "";
        return rootHead;
      },
      crash_type: (r) => r.crash_type ?? null,
      cwe_id: (r) => r.cwe_id ?? null,
      cvss_score: (r) => r.cvss_score ?? null,
      evidence_count: (r) => r.evidence_count ?? 0,
      disclosure_status: (r) => r.disclosure_status ?? null,
      project_id: (r) => r.project_id ?? null,
      assigned_cve_id: (r) => r.assigned_cve_id ?? null,
    }),
    [],
  );
  const { sortedRows, sortKey, sortDir, setSort } = useSortableRows(
    filteredRows,
    accessors,
  );

  // Segmented sort tier trumps sortKey when column-sort not active.
  const displayed = useMemo(() => {
    if (sortKey) return sortedRows;
    const copy = [...filteredRows];
    if (sortMode === "severity") {
      copy.sort((a, b) => (b.cvss_score ?? -1) - (a.cvss_score ?? -1));
      return copy;
    }
    if (sortMode === "evidence") {
      copy.sort((a, b) => (b.evidence_count ?? 0) - (a.evidence_count ?? 0));
      return copy;
    }
    if (sortMode === "newest") {
      copy.sort((a, b) => {
        const at = a.reported_at ? new Date(a.reported_at).getTime() : 0;
        const bt = b.reported_at ? new Date(b.reported_at).getTime() : 0;
        return bt - at;
      });
      return copy;
    }
    // smart: critical/high first, then higher evidence, then higher score
    copy.sort((a, b) => {
      const ac = a.cvss_score ?? 0;
      const bc = b.cvss_score ?? 0;
      const at = ac >= 7 ? 0 : ac >= 4 ? 1 : 2;
      const bt = bc >= 7 ? 0 : bc >= 4 ? 1 : 2;
      if (at !== bt) return at - bt;
      const ae = a.evidence_count ?? 0;
      const be = b.evidence_count ?? 0;
      if (ae !== be) return be - ae;
      return bc - ac;
    });
    return copy;
  }, [filteredRows, sortedRows, sortKey, sortMode]);

  const currentViewJson = serializeFindingsView({
    v: 1,
    q: query,
    status: statusFilter,
    crash: crashFilter,
    severities: Array.from(severityFilter),
    sortKey,
    sortDir,
    sortMode,
  });

  function applyView(filterJson: string) {
    const payload = parseFindingsView(filterJson);
    if (!payload) return;
    setQuery(payload.q ?? "");
    setStatusFilter(payload.status ?? "");
    setCrashFilter(payload.crash ?? "");
    setSeverityFilter(new Set(payload.severities ?? []));
    setSortMode(payload.sortMode ?? "smart");
    setSort(payload.sortKey ?? "", payload.sortDir ?? null);
  }

  function toggleSeverity(band: SeverityBand) {
    setSeverityFilter((prev) => {
      const next = new Set(prev);
      if (next.has(band)) next.delete(band);
      else next.add(band);
      return next;
    });
  }

  function clearAllFilters() {
    setQuery("");
    setStatusFilter("");
    setCrashFilter("");
    setSeverityFilter(new Set());
    setSortMode("smart");
    setSort("", null);
  }

  const hasActiveFilters =
    !!query ||
    !!statusFilter ||
    !!crashFilter ||
    severityFilter.size > 0 ||
    sortMode !== "smart" ||
    !!sortKey;

  const listContainerRef = useRef<HTMLDivElement | null>(null);
  const { tbodyProps, getRowProps } = useTableRowNav(
    displayed,
    (r) => {
      if (r.id) navigate(`/vr/findings/${encodeURIComponent(r.id)}`);
    },
    listContainerRef,
  );

  // Distinct values from the loaded set, used to populate the filters
  // without an extra round-trip.
  const distinctStatuses = useMemo(
    () =>
      Array.from(
        new Set(rows.map((r) => r.disclosure_status).filter(Boolean)),
      ),
    [rows],
  );
  const distinctCrashes = useMemo(
    () =>
      Array.from(
        new Set(
          rows
            .map((r) => r.crash_type)
            .filter((v): v is NonNullable<typeof v> => !!v),
        ),
      ),
    [rows],
  );

  // ─── Distribution (client-aggregated over the sorted view) ───
  const severityCounts = useMemo(() => {
    const counts: Record<SeverityBand, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      unscored: 0,
    };
    for (const r of displayed) counts[bandFor(r.cvss_score)] += 1;
    return counts;
  }, [displayed]);
  const severityMax = Math.max(1, ...SEVERITY_BANDS.map((b) => severityCounts[b.key]));
  const criticalCount = severityCounts.critical;

  const disclosureCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const s of DISCLOSURE_ORDER) counts[s] = 0;
    for (const r of displayed) {
      const k = r.disclosure_status || "undisclosed";
      counts[k] = (counts[k] ?? 0) + 1;
    }
    return counts;
  }, [displayed]);
  const disclosureMax = Math.max(
    1,
    ...DISCLOSURE_ORDER.map((s) => disclosureCounts[s] ?? 0),
  );

  // ─── Filter shelf ───
  const filterShelf = (
    <WindowPanel title="filters" tone="muted">
      <div className="flex flex-col" style={{ gap: 10 }}>
        <div className="flex flex-wrap items-center" style={{ gap: 8 }}>
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="filter findings (fn / crash / cwe / cve)…"
            aria-label="Filter findings"
            className="font-mono"
            style={{ ...CTRL, width: 260 }}
          />
          <select
            value={statusFilter}
            onChange={(e) =>
              setStatusFilter(e.target.value as DisclosureStatus | "")
            }
            aria-label="Filter by disclosure status"
            className="font-mono uppercase"
            style={CTRL}
          >
            <option value="">all disclosure</option>
            {distinctStatuses.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <select
            value={crashFilter}
            onChange={(e) => setCrashFilter(e.target.value)}
            aria-label="Filter by crash type"
            className="font-mono uppercase"
            style={CTRL}
          >
            <option value="">all crash</option>
            {distinctCrashes.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
          {SEVERITY_BANDS.map((b) => (
            <FilterChip
              key={b.key}
              active={severityFilter.has(b.key)}
              color={b.hue}
              onClick={() => toggleSeverity(b.key)}
            >
              {b.label}
            </FilterChip>
          ))}
          {hasActiveFilters ? (
            <FilterChip active={false} onClick={clearAllFilters}>
              ✕ clear
            </FilterChip>
          ) : null}
          <span style={{ flex: 1 }} />
          <Segmented<SortMode>
            options={SORT_OPTIONS}
            value={sortMode}
            onChange={(next) => {
              setSortMode(next);
              setSort("", null);
            }}
          />
        </div>
        <div style={{ minHeight: 26 }}>
          <SavedViews
            entityType="vr_finding"
            entityLabel="findings"
            currentFilterJson={currentViewJson}
            onApply={applyView}
          />
        </div>
      </div>
    </WindowPanel>
  );

  // ─── Stats row ───
  const statsRow =
    !isLoading && !isError && displayed.length > 0 ? (
      <div
        className="grid"
        style={{ gridTemplateColumns: "1fr 1fr 1.2fr", gap: 12 }}
      >
        <WindowPanel title="critical" tone="accent">
          <BigStat value={criticalCount.toLocaleString()} sub="cvss ≥ 9" />
        </WindowPanel>
        <WindowPanel title="severity mix" tone="muted">
          <div className="flex flex-col" style={{ gap: 6 }}>
            {SEVERITY_BANDS.map((b) => (
              <StatBar
                key={b.key}
                label={b.label}
                color={b.hue}
                value={severityCounts[b.key]}
                max={severityMax}
              />
            ))}
          </div>
        </WindowPanel>
        <WindowPanel title="disclosure mix" tone="info">
          <div className="flex flex-col" style={{ gap: 6 }}>
            {DISCLOSURE_ORDER.map((s) => (
              <StatBar
                key={s}
                label={s}
                color={DISCLOSURE_HUE[s]}
                value={disclosureCounts[s] ?? 0}
                max={disclosureMax}
              />
            ))}
          </div>
        </WindowPanel>
      </div>
    ) : null;

  // ─── Table (honest grid with keyboard nav) ───
  const columns: HonestColumn[] = [
    { label: "disclosure", width: "120px" },
    { label: "cve", width: "140px" },
    { label: "severity", width: "110px" },
    { label: "crash", width: "120px" },
    { label: "cwe", width: "100px" },
    { label: "fn", width: "1fr" },
    { label: "evidence", width: "80px", align: "right" },
    { label: "project", width: "90px" },
  ];

  function renderCells(r: VRFinding): React.ReactNode[] {
    const rootHead = (r.root_cause || "").split("\n")[0].trim();
    const display =
      r.vulnerable_function || rootHead.slice(0, 110) || "(no detail)";
    const band = bandFor(r.cvss_score);
    const bandMeta =
      SEVERITY_BANDS.find((b) => b.key === band) ?? SEVERITY_BANDS[4];
    const scoreStr =
      r.cvss_score != null && r.cvss_score > 0
        ? r.cvss_score.toFixed(1)
        : "--";
    const evidenceCount = r.evidence_count ?? 0;
    return [
      <MonoBadge
        tone={DISCLOSURE_TONE[r.disclosure_status] ?? "muted"}
        title={r.disclosure_status}
      >
        {r.disclosure_status}
      </MonoBadge>,
      <span
        className="font-mono"
        style={{
          fontSize: 11,
          color: r.assigned_cve_id
            ? "var(--accent)"
            : "var(--text-faint)",
          letterSpacing: "0.06em",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          display: "block",
        }}
        title={r.assigned_cve_id ?? "no cve"}
      >
        {r.assigned_cve_id ?? "--"}
      </span>,
      <span
        className="flex items-center font-mono"
        style={{ gap: 6 }}
        title={`cvss ${scoreStr}`}
      >
        <MonoBadge tone={bandMeta.tone}>{bandMeta.label}</MonoBadge>
        <span
          style={{
            fontSize: 10.5,
            color: "var(--text-muted)",
            fontVariantNumeric: "tabular-nums",
          }}
        >
          {scoreStr}
        </span>
      </span>,
      r.crash_type ? (
        <MonoBadge tone="warn">{r.crash_type}</MonoBadge>
      ) : (
        <span
          className="font-mono"
          style={{ fontSize: 10, color: "var(--text-faint)" }}
        >
          --
        </span>
      ),
      <span
        className="font-mono"
        style={{
          fontSize: 10.5,
          color: r.cwe_id ? "var(--text-primary)" : "var(--text-faint)",
          letterSpacing: "0.04em",
        }}
      >
        {r.cwe_id ?? "--"}
      </span>,
      <span
        className="font-mono"
        title={display}
        style={{
          fontSize: 11.5,
          color: "var(--text-primary)",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          display: "block",
        }}
      >
        {r.vulnerable_function ? (
          r.vulnerable_function
        ) : (
          <span style={{ color: "var(--text-muted)" }}>{display}</span>
        )}
      </span>,
      evidenceCount > 0 ? (
        <MonoBadge tone="info">{String(evidenceCount)}</MonoBadge>
      ) : (
        <span
          className="font-mono"
          style={{ fontSize: 10, color: "var(--text-faint)" }}
        >
          none
        </span>
      ),
      <span
        className="font-mono"
        style={{
          fontSize: 10,
          color: "var(--text-faint)",
          letterSpacing: "0.04em",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          display: "block",
        }}
        title={r.project_id ?? ""}
      >
        {r.project_id ? r.project_id.slice(0, 8) : "--"}
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
      {displayed.length}
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
        failed to load findings.
      </div>
    );
  } else {
    tableBody = (
      <HonestGrid<VRFinding>
        ariaLabel="Team-wide vulnerability findings"
        columns={columns}
        rows={displayed}
        renderCells={renderCells}
        getKey={(r) => r.id ?? Math.random().toString(36)}
        onRowClick={(r) => {
          if (r.id) navigate(`/vr/findings/${encodeURIComponent(r.id)}`);
        }}
        containerRef={listContainerRef}
        onKeyDown={tbodyProps.onKeyDown}
        getRowProps={getRowProps}
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
            {rows.length === 0
              ? "no findings yet -- findings land here as evidence promotes."
              : "no findings match the current filters."}
          </div>
        }
      />
    );
  }

  return (
    <div className="flex flex-col" style={{ gap: 14 }}>
      <SectionHeader icon="◈" title="Findings" />
      {filterShelf}
      {statsRow}
      <WindowPanel
        title="findings"
        tone="accent"
        actions={tableActions}
        flush
      >
        {tableBody}
      </WindowPanel>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────
// HonestGrid -- local table variant that mirrors the mock DataGrid look
// but accepts per-row keyboard-nav props (data-row-index / tabIndex /
// aria-selected) supplied by `useTableRowNav`.
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
  ariaLabel,
}: {
  columns: HonestColumn[];
  rows: ReadonlyArray<T>;
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
  ariaLabel?: string;
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
        aria-label={ariaLabel}
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
