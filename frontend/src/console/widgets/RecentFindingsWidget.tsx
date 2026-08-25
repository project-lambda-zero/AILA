/** RecentFindingsWidget -- merged recent findings across vulnerability + vr + malware.
 *
 * No cross-module endpoint exists. We fan out one useQuery per module and
 * merge client-side, tolerating individual failures. Sort by best-available
 * timestamp desc, take top 10. Each row is a button that deep-links via
 * `props.onOpenPage(module, "findings", ...)`. */

import type { JSX } from "react";
import { useQuery } from "@tanstack/react-query";

import { apiFetch } from "../../api/client";
import type { VulnFinding, VulnFindingsPage } from "../../api/vulnerability";
import { css } from "../css";
import { shortCaseId } from "../ids";
import type { WidgetProps } from "./types";

interface VrFindingLike {
  id: string | null;
  cvss_score: number | null;
  crash_type: string | null;
  reported_at: string | null;
  workflow_state?: string;
}

interface MalwareFindingLike {
  id: string;
  kind: string;
  confidence: string;
  created_at: string | null;
  updated_at: string | null;
  workflow_state?: string;
}

type SeverityBand = "critical" | "high" | "medium" | "low" | "unrated";

interface Row {
  module: string;
  id: string;
  shortId: string;
  severity: SeverityBand;
  ts: string | null;
}

function severityFromLabel(label: string | null | undefined): SeverityBand {
  const v = (label ?? "").toLowerCase();
  if (v === "critical") return "critical";
  if (v === "high") return "high";
  if (v === "medium") return "medium";
  if (v === "low") return "low";
  return "unrated";
}

function severityFromCvss(score: number | null): SeverityBand {
  if (score == null) return "unrated";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "unrated";
}

function severityFromConfidence(conf: string | null | undefined): SeverityBand {
  const v = (conf ?? "").toLowerCase();
  if (v === "exact" || v === "strong") return "high";
  if (v === "medium") return "medium";
  if (v === "caveated") return "low";
  return "unrated";
}

function toneFor(sev: SeverityBand): string {
  if (sev === "critical" || sev === "high") return "var(--status-warn)";
  if (sev === "medium") return "var(--status-info)";
  return "var(--text-muted)";
}

function fmtWhen(iso: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  return `${hh}:${mm}`;
}

const ROOT = css(
  "flex:1;min-height:0;display:flex;flex-direction:column;overflow:auto;" +
  "padding:10px 12px;background:var(--surface-card);" +
  "font-family:var(--font-mono);color:var(--text-primary);gap:4px;",
);

const LABEL = css(
  "font-size:9px;letter-spacing:0.12em;text-transform:uppercase;" +
  "color:var(--text-faint);margin-bottom:4px;",
);

const EMPTY = css("font-size:11px;color:var(--text-faint);padding:6px 0;");

const ROW_BTN = css(
  "display:flex;align-items:center;gap:8px;padding:4px 6px;background:transparent;" +
  "border:0;border-radius:2px;cursor:pointer;font-family:var(--font-mono);" +
  "font-size:11px;color:var(--text-primary);text-align:left;width:100%;",
);

export default function RecentFindingsWidget(props: WidgetProps): JSX.Element {
  const vulnQ = useQuery({
    queryKey: ["widget", "recent-findings", "vulnerability"],
    queryFn: () => apiFetch<VulnFindingsPage>("/vulnerability/findings?limit=25"),
    staleTime: 30000,
  });
  const vrQ = useQuery({
    queryKey: ["widget", "recent-findings", "vr"],
    queryFn: () => apiFetch<VrFindingLike[]>("/vr/findings?limit=25"),
    staleTime: 30000,
  });
  const malQ = useQuery({
    queryKey: ["widget", "recent-findings", "malware"],
    queryFn: () => apiFetch<MalwareFindingLike[]>("/malware/findings?limit=25"),
    staleTime: 30000,
  });

  const rows: Row[] = [];

  if (vulnQ.data?.items) {
    for (const f of vulnQ.data.items as VulnFinding[]) {
      const idStr = f.id == null ? "" : String(f.id);
      rows.push({
        module: "vulnerability",
        id: idStr,
        shortId: f.cve_id ?? (idStr ? `#${idStr}` : "?"),
        severity: severityFromLabel(f.severity),
        ts: f.created_at,
      });
    }
  }
  if (vrQ.data) {
    for (const f of vrQ.data) {
      const idStr = f.id ?? "";
      rows.push({
        module: "vr",
        id: idStr,
        shortId: idStr ? shortCaseId("vr", idStr) : "?",
        severity: severityFromCvss(f.cvss_score),
        ts: f.reported_at,
      });
    }
  }
  if (malQ.data) {
    for (const f of malQ.data) {
      const ts = f.updated_at ?? f.created_at;
      rows.push({
        module: "malware",
        id: f.id,
        shortId: shortCaseId("malware", f.id),
        severity: severityFromConfidence(f.confidence),
        ts,
      });
    }
  }

  rows.sort((a, b) => {
    if (!a.ts && !b.ts) return 0;
    if (!a.ts) return 1;
    if (!b.ts) return -1;
    return a.ts < b.ts ? 1 : a.ts > b.ts ? -1 : 0;
  });
  const top = rows.slice(0, 10);

  const failures: string[] = [];
  if (vulnQ.isError) failures.push("vulnerability");
  if (vrQ.isError) failures.push("vr");
  if (malQ.isError) failures.push("malware");

  const aggregateLoading = vulnQ.isLoading && vrQ.isLoading && malQ.isLoading;

  if (aggregateLoading) {
    return (
      <div style={ROOT}>
        <div style={LABEL}>recent findings</div>
        <div style={EMPTY}>loading...</div>
      </div>
    );
  }

  return (
    <div style={ROOT}>
      <div style={LABEL}>recent findings</div>
      {top.length === 0 ? (
        <div style={EMPTY}>no findings</div>
      ) : (
        top.map((row, idx) => (
          <button
            key={`${row.module}:${row.id}:${idx}`}
            type="button"
            style={ROW_BTN}
            onClick={() =>
              props.onOpenPage(row.module, "findings", `${row.module} \u00b7 findings`)
            }
          >
            <span
              style={{
                minWidth: 44,
                padding: "1px 4px",
                borderRadius: 2,
                fontSize: 9,
                letterSpacing: "0.08em",
                textTransform: "uppercase",
                color: toneFor(row.severity),
                border: `1px solid ${toneFor(row.severity)}`,
                textAlign: "center",
              }}
            >
              {row.severity}
            </span>
            <span
              style={{
                fontSize: 9,
                letterSpacing: "0.08em",
                textTransform: "uppercase",
                color: "var(--text-faint)",
                minWidth: 46,
              }}
            >
              {row.module}
            </span>
            <span style={{ color: "var(--text-primary)", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {row.shortId}
            </span>
            <span style={{ color: "var(--text-faint)", fontVariantNumeric: "tabular-nums" }}>
              {fmtWhen(row.ts)}
            </span>
          </button>
        ))
      )}
      {failures.length > 0 ? (
        <div style={{ ...EMPTY, color: "var(--text-faint)", marginTop: 4 }}>
          {`load failed: ${failures.join(", ")}`}
        </div>
      ) : null}
    </div>
  );
}
