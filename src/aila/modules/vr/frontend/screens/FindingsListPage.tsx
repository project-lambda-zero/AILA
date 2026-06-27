import { useState } from "react";
import { useNavigate } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { useAllFindings } from "../queries";
import type { DisclosureStatus } from "../types";

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
  const [statusFilter, setStatusFilter] = useState<DisclosureStatus | "">("");
  const [crashFilter, setCrashFilter] = useState("");

  const { data, isLoading, isError } = useAllFindings({
    disclosureStatus: statusFilter || undefined,
    crashType: crashFilter || undefined,
    limit: 200,
  });
  const rows = data?.data ?? [];

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
            {rows.length} finding{rows.length === 1 ? "" : "s"}
          </span>
        </div>
      </AilaCard>

      {isLoading && <LoadingSkeleton size="lg" width="full" />}

      {isError && (
        <AilaCard className="border-border-danger" techBorder glow>
          <p className="text-sm text-text-danger">Failed to load findings.</p>
        </AilaCard>
      )}

      {!isLoading && !isError && rows.length === 0 && (
        <AilaCard techBorder glow>
          <p className="text-center py-6 text-text-muted">
            No findings yet. They get materialised by{" "}
            <b>vr.crash_triage</b> + investigation workflows; come back after
            triage runs land.
          </p>
        </AilaCard>
      )}

      {!isLoading && !isError && rows.length > 0 && (
        <AilaCard className="overflow-x-auto p-0" techBorder glow>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border-default text-left text-xs uppercase tracking-wide text-text-muted">
                <th className="px-4 py-2 font-semibold">Vulnerable function</th>
                <th className="px-4 py-2 font-semibold">Crash</th>
                <th className="px-4 py-2 font-semibold">CWE</th>
                <th className="px-4 py-2 font-semibold text-right">CVSS</th>
                <th className="px-4 py-2 font-semibold text-right">Evidence</th>
                <th className="px-4 py-2 font-semibold">Disclosure</th>
                <th className="px-4 py-2 font-semibold">Project</th>
                <th className="px-4 py-2 font-semibold">CVE</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => {
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
                return (
                  <tr
                    key={r.id}
                    onClick={() => navigate(target)}
                    className="border-b border-border-default last:border-b-0 cursor-pointer hover:bg-surface transition-colors"
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
