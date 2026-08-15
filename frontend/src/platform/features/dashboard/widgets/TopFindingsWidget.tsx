import * as React from "react";
import { useQuery } from "@tanstack/react-query";

import { DataGrid, MonoBadge } from "@/components/aila/mock";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { authorizedRequestJson } from "@platform/api/http";

type SeverityLevel = "critical" | "high" | "medium" | "low";

/**
 * Subset of the vulnerability /findings response -- only the fields the widget
 * renders. Mirrors `FindingResponse` from src/aila/api/schemas/findings.py.
 */
interface FindingRow {
  id: number;
  cve_id: string | null;
  severity: string | null;
  host: string | null;
  package: string | null;
  is_kev: boolean;
}

interface FindingsListResponse {
  data: {
    total: number;
    page: number;
    page_size: number;
    pages: number;
    items: FindingRow[];
  };
}

const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  immediate: 0,
  high: 1,
  medium: 2,
  moderate: 2,
  low: 3,
  planned: 3,
};

function normalizeSeverity(raw: string | null | undefined): SeverityLevel {
  const s = (raw ?? "").toLowerCase();
  if (s === "critical" || s === "immediate") return "critical";
  if (s === "high") return "high";
  if (s === "medium" || s === "moderate") return "medium";
  return "low";
}

function severitySortKey(raw: string | null | undefined): number {
  const s = (raw ?? "").toLowerCase();
  return SEVERITY_RANK[s] ?? 99;
}

const CENTER_STYLE: React.CSSProperties = {
  height: "100%",
  padding: 16,
  fontFamily: "var(--font-mono)",
  fontSize: 11,
};

/**
 * TopFindingsWidget -- compact grid of the top-5 most critical findings.
 *
 * Fetches directly from GET /vulnerability/findings (no `severity` filter so
 * we accept whatever criticality vocabulary the data carries -- "Critical",
 * "Immediate", "High", "Moderate", etc.) and re-sorts client-side using
 * `severitySortKey` so legacy values rank correctly. The dashboard
 * `module_data["vulnerability.top_findings"]` provider is not registered, so
 * relying on it produced an empty widget.
 *
 * Columns: CVE ID, Severity, System (host).
 */
export function TopFindingsWidget() {
  const { data, isLoading, isError, error } = useQuery<FindingsListResponse>({
    queryKey: ["vulnerability", "findings", "top-5"],
    queryFn: () =>
      authorizedRequestJson<FindingsListResponse>(
        "/vulnerability/findings?sort_by=severity&order=asc&page_size=25",
      ),
    staleTime: 30_000,
    refetchInterval: 60_000,
    retry: 1,
  });

  if (isLoading) {
    return (
      <div className="h-full w-full p-4 flex flex-col gap-2">
        {Array.from({ length: 4 }).map((_, i) => (
          <LoadingSkeleton key={i} size="sm" width="full" />
        ))}
      </div>
    );
  }

  if (isError) {
    return (
      <div
        className="flex items-center justify-center"
        style={{ ...CENTER_STYLE, color: "var(--status-warn)" }}
      >
        {error instanceof Error ? error.message : "Failed to load findings"}
      </div>
    );
  }

  const items = data?.data?.items ?? [];

  if (items.length === 0) {
    return (
      <div
        className="flex items-center justify-center"
        style={{ ...CENTER_STYLE, color: "var(--text-muted)" }}
      >
        No findings recorded
      </div>
    );
  }

  // Client-side severity sort: backend `_SEVERITY_ORDER` only ranks canonical
  // CRITICAL/HIGH/MEDIUM/LOW values, so legacy values like "Immediate" and
  // "Moderate" collapse into bucket 99 and lose their relative order.
  const findings = [...items]
    .sort((a, b) => severitySortKey(a.severity) - severitySortKey(b.severity))
    .slice(0, 5);

  return (
    <div className="h-full w-full flex flex-col" style={{ padding: 8 }}>
      <div className="flex-1 min-h-0 overflow-auto">
        <DataGrid<FindingRow>
          columns={[
            { label: "CVE", width: "1fr" },
            { label: "SEV", width: "80px" },
            { label: "SYSTEM", width: "1fr", align: "right" },
          ]}
          rows={findings}
          getKey={(r) => r.id}
          renderCells={(finding) => {
            const cveId = finding.cve_id ?? `Finding-${finding.id}`;
            const sev = normalizeSeverity(finding.severity);
            const system = finding.host ?? "--";
            return [
              <span
                key="cve"
                className="truncate"
                style={{ color: "var(--accent)" }}
              >
                {cveId}
              </span>,
              <MonoBadge key="sev" tone={sev}>
                {sev.toUpperCase()}
              </MonoBadge>,
              <span
                key="sys"
                className="truncate"
                style={{ color: "var(--text-muted)" }}
              >
                {system}
              </span>,
            ];
          }}
        />
      </div>
    </div>
  );
}
