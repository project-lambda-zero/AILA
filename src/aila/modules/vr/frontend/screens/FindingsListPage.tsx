import { useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { AilaChart } from "@/components/aila/AilaChart";
import { EmptyState } from "@/components/aila/EmptyState";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { Bug } from "@phosphor-icons/react/dist/csr/Bug";
import { useThemeChartColors } from "@platform/features/viz/chartColors";

import {
  SortHeader,
  useSortableRows,
  useTableRowNav,
  type SortValue,
} from "../components/tableHelpers";
import { useAllFindings } from "../queries";
import { useVRListInvalidation } from "../hooks/useVRListInvalidation";
import type { DisclosureStatus, VRFinding } from "../types";

/**
 * Global findings explorer.
 *
 * Operator's stated pain: "I can't explore findings on their own, I
 * don't know which evidence belongs to which finding." The
 * project-scoped FindingsListPage already exists but requires picking a
 * project first; this page hits the team-wide `GET /vr/findings`
 * endpoint and lays every row out with the columns the operator needs
 * to triage: vulnerable function, crash type, CVSS, evidence count,
 * disclosure status, and project. Clicking a row routes to the existing
 * FindingDetailPage where the full evidence list renders.
 */
export function FindingsListPage() {
  const navigate = useNavigate();
  useVRListInvalidation("findings");
  const [statusFilter, setStatusFilter] = useState<DisclosureStatus | "">("");
  const [crashFilter, setCrashFilter] = useState("");

  // /vr/findings has no `q` server-side param -- quick-filter runs
  // client-side over vulnerable_function / crash_type / cwe / cve /
  // disclosure_status / root_cause head.
  const [query, setQuery] = useState("");

  const { data, isLoading, isError } = useAllFindings({
    disclosureStatus: statusFilter || undefined,
    crashType: crashFilter || undefined,
    limit: 200,
  });
  const rows = data?.data ?? [];

  const filteredRows = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return rows;
    return rows.filter((r) => {
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
  }, [rows, query]);

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
  const { sortedRows, sortKey, sortDir, cycleSort } = useSortableRows(
    filteredRows,
    accessors,
  );

  const tbodyRef = useRef<HTMLTableSectionElement | null>(null);
  const { tbodyProps, getRowProps } = useTableRowNav(
    sortedRows,
    (r) => {
      if (r.id) navigate(`/vr/findings/${encodeURIComponent(r.id)}`);
    },
    tbodyRef,
  );

  // Distinct values from the loaded set, used to populate the filters
  // without an extra round-trip. Only includes values actually present
  // so the operator's dropdown can't pick a status with zero rows.
  const distinctStatuses = Array.from(
    new Set(rows.map((r) => r.disclosure_status).filter(Boolean)),
  );
  const distinctCrashes = Array.from(
    new Set(
      rows
        .map((r) => r.crash_type)
        .filter((v): v is NonNullable<typeof v> => !!v),
    ),
  );

  return (
    <div className="space-y-4">
      <AilaCard techBorder glow>
        <div className="flex items-center gap-2 flex-wrap">
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter findings (function / crash / CWE / CVE)…"
            aria-label="Filter findings"
            className="flex-1 min-w-[220px] max-w-md px-3 py-1.5 text-sm rounded-md bg-surface border border-border-default focus:border-accent focus:outline-none"
          />
          <label className="text-sm text-text-muted">Disclosure:</label>
          <select
            value={statusFilter}
            onChange={(e) =>
              setStatusFilter(e.target.value as DisclosureStatus | "")
            }
            aria-label="Filter by disclosure status"
            className="px-3 py-1.5 text-sm rounded-md bg-surface border border-border-default"
          >
            <option value="">-- all --</option>
            {distinctStatuses.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>

          <label className="text-sm text-text-muted ml-2">Crash type:</label>
          <select
            value={crashFilter}
            onChange={(e) => setCrashFilter(e.target.value)}
            aria-label="Filter by crash type"
            className="px-3 py-1.5 text-sm rounded-md bg-surface border border-border-default"
          >
            <option value="">-- all --</option>
            {distinctCrashes.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>

          <span className="text-xs text-text-muted ml-auto">
            {query.trim()
              ? `${sortedRows.length} of ${rows.length} finding${rows.length === 1 ? "" : "s"}`
              : `${rows.length} finding${rows.length === 1 ? "" : "s"}`}
          </span>
        </div>
      </AilaCard>

      {/* Additive distribution panel -- client-aggregates the loaded
          findings so the operator sees the shape of the current view
          without an extra round trip. Purely read-only: the table
          below and every filter above stay authoritative. */}
      {!isLoading && !isError && sortedRows.length > 0 && (
        <FindingsDistributionPanel rows={sortedRows} />
      )}

      {isLoading && <LoadingSkeleton size="lg" width="full" />}

      {isError && (
        <AilaCard className="border-border-danger" techBorder glow>
          <p className="text-sm text-text-danger">Failed to load findings.</p>
        </AilaCard>
      )}

      {!isLoading && !isError && rows.length === 0 && (
        <EmptyState
          icon={<Bug className="h-7 w-7" weight="duotone" />}
          title="No findings yet"
          description="Findings get materialised by vr.crash_triage and investigation workflows once evidence is promoted. They surface here as they land."
        />
      )}

      {!isLoading && !isError && rows.length > 0 && (
        <AilaCard className="overflow-x-auto p-0" techBorder glow>
          <table className="w-full text-sm">
            <caption className="sr-only">Team-wide vulnerability findings</caption>
            <thead>
              <tr className="border-b border-border-default text-left text-xs uppercase tracking-wide text-text-muted">
                <SortHeader columnKey="vulnerable_function" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort}>Vulnerable function</SortHeader>
                <SortHeader columnKey="crash_type" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort}>Crash</SortHeader>
                <SortHeader columnKey="cwe_id" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort}>CWE</SortHeader>
                <SortHeader columnKey="cvss_score" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort} align="right">CVSS</SortHeader>
                <SortHeader columnKey="evidence_count" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort} align="right">Evidence</SortHeader>
                <SortHeader columnKey="disclosure_status" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort}>Disclosure</SortHeader>
                <SortHeader columnKey="project_id" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort}>Project</SortHeader>
                <SortHeader columnKey="assigned_cve_id" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort}>CVE</SortHeader>
              </tr>
            </thead>
            <tbody ref={tbodyRef} {...tbodyProps}>
              {sortedRows.map((r, idx) => {
                if (!r.id) return null;
                const cvssScore = r.cvss_score ?? null;
                const evidenceCount = r.evidence_count ?? 0;
                // Project-less global detail route -- works for every
                // finding regardless of whether project_id is set.
                const target = `/vr/findings/${encodeURIComponent(r.id)}`;
                // Title fallback chain so audit-derived findings with
                // no vulnerable_function (most rows!) show the
                // root_cause head instead of a sea of "(unknown)".
                const rootHead = (r.root_cause || "")
                  .split("\n")[0]
                  .trim();
                const display =
                  r.vulnerable_function ||
                  rootHead.slice(0, 110) ||
                  "(no detail)";
                const rowProps = getRowProps(idx);
                return (
                  <tr
                    key={r.id}
                    {...rowProps}
                    onClick={() => navigate(target)}
                    className={
                      "border-b border-border-default last:border-b-0 cursor-pointer hover:bg-surface transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-inset " +
                      (rowProps["data-row-active"] ? "bg-elevated" : "")
                    }
                  >
                    <td className="px-4 py-2 text-xs text-foreground max-w-[42rem]">
                      <div className="truncate" title={display}>
                        {r.vulnerable_function ? (
                          <span className="font-mono">
                            {r.vulnerable_function}
                          </span>
                        ) : (
                          <span>{display}</span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-2 font-mono text-xs">
                      {r.crash_type ?? "--"}
                    </td>
                    <td className="px-4 py-2 font-mono text-xs">
                      {r.cwe_id ?? "--"}
                    </td>
                    <td className="px-4 py-2 font-mono text-xs text-right">
                      {cvssScore != null ? cvssScore.toFixed(1) : "--"}
                    </td>
                    <td className="px-4 py-2 text-right">
                      {evidenceCount > 0 ? (
                        <AilaBadge severity="info" size="sm">
                          {evidenceCount}
                        </AilaBadge>
                      ) : (
                        <span className="text-xs text-text-muted">none</span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-xs">
                      {r.disclosure_status}
                    </td>
                    <td className="px-4 py-2 font-mono text-3xs text-text-muted">
                      {r.project_id ? r.project_id.slice(0, 8) : "--"}
                    </td>
                    <td className="px-4 py-2 font-mono text-xs">
                      {r.assigned_cve_id ?? "--"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </AilaCard>
      )}
    </div>
  );
}

/** CVSS bands mirror the CVE scoring specification: none (0.0),
 *  low (0.1-3.9), medium (4.0-6.9), high (7.0-8.9), critical (9.0+). A
 *  finding with no cvss_score is bucketed under `unscored` so the
 *  operator sees how much of the current view lacks a score. */
const CVSS_BANDS: ReadonlyArray<{
  name: string;
  test: (score: number | null) => boolean;
  colorKey: "critical" | "high" | "medium" | "low" | "textMuted";
}> = [
  { name: "Critical (9+)", test: (s) => s != null && s >= 9, colorKey: "critical" },
  { name: "High (7-8.9)", test: (s) => s != null && s >= 7 && s < 9, colorKey: "high" },
  { name: "Medium (4-6.9)", test: (s) => s != null && s >= 4 && s < 7, colorKey: "medium" },
  { name: "Low (0.1-3.9)", test: (s) => s != null && s > 0 && s < 4, colorKey: "low" },
  { name: "Unscored", test: (s) => s == null || s === 0, colorKey: "textMuted" },
];

/** Read-only summary panel over the current findings view. Renders a
 *  CVSS-band donut and a disclosure-status bar so the operator can see
 *  the shape of what they're triaging without an extra fetch. Sourced
 *  client-side from the exact rows the table renders below, so filters
 *  and search stay authoritative -- narrow the view and the panel
 *  narrows with it. */
function FindingsDistributionPanel({
  rows,
}: {
  rows: ReadonlyArray<VRFinding>;
}) {
  const colors = useThemeChartColors();
  const cvssData = CVSS_BANDS.map((band) => ({
    name: band.name,
    count: rows.reduce(
      (acc, r) => acc + (band.test(r.cvss_score ?? null) ? 1 : 0),
      0,
    ),
  }));
  const cvssColors = CVSS_BANDS.map((band) => colors[band.colorKey]);
  const cvssHasData = cvssData.some((d) => d.count > 0);

  const statusCounts = new Map<string, number>();
  for (const r of rows) {
    const k = r.disclosure_status || "unknown";
    statusCounts.set(k, (statusCounts.get(k) ?? 0) + 1);
  }
  const statusData = Array.from(statusCounts.entries())
    .map(([status, count]) => ({ status, count }))
    .sort((a, b) => b.count - a.count);
  const statusHasData = statusData.length > 0;
  const scored = rows.filter((r) => r.cvss_score != null && r.cvss_score > 0);

  return (
    <AilaCard techBorder glow>
      <div className="space-y-3">
        <div className="flex items-baseline justify-between flex-wrap gap-2">
          <h2 className="text-sm font-semibold text-foreground">
            Distribution
          </h2>
          <span className="text-3xs text-text-muted font-mono">
            {rows.length} finding{rows.length === 1 ? "" : "s"} in view ·{" "}
            {scored.length} scored
          </span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div>
            <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wide mb-1">
              CVSS bands
            </h3>
            {cvssHasData ? (
              <AilaChart
                type="pie"
                data={cvssData}
                dataKey="count"
                xKey="name"
                colors={cvssColors}
                size="sm"
                ariaLabel="Findings by CVSS band"
              />
            ) : (
              <p className="text-xs text-text-muted">No scored findings.</p>
            )}
          </div>
          <div>
            <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wide mb-1">
              Disclosure status
            </h3>
            {statusHasData ? (
              <AilaChart
                type="bar"
                data={statusData}
                dataKey="count"
                xKey="status"
                colors={[colors.accent]}
                size="sm"
                ariaLabel="Findings by disclosure status"
              />
            ) : (
              <p className="text-xs text-text-muted">
                No disclosure status recorded.
              </p>
            )}
          </div>
        </div>
      </div>
    </AilaCard>
  );
}
