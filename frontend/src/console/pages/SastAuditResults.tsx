import { useQuery } from "@tanstack/react-query";
import type { JSX } from "react";

import { apiFetch } from "../../api/client";
import { asRecord, readStr } from "../../api/parse";
import type { Investigation } from "../../api/types";
import { css } from "../css";
import { StatusBadge } from "./badges";

const tableCss = css("width:100%;border-collapse:collapse;font-size:11px;");
const cellCss = css("padding:7px;border-bottom:1px solid var(--border-soft);text-align:left;vertical-align:top;");
const mutedCss = css("color:var(--text-muted);font-size:11px;");
const linkCss = css("border:0;background:transparent;color:var(--accent);padding:0;cursor:pointer;text-align:left;font:inherit;");

interface SastResult {
  skillId: string;
  title: string;
  phase: string;
  investigationId: string;
  status: string;
  outcomeKind: string | null;
  confidence: string | null;
  summary: string | null;
}

interface SastAggregate {
  parentStatus: string;
  results: SastResult[];
  statusCounts: Record<string, number>;
}

function parseAggregate(value: unknown): SastAggregate {
  const row = asRecord(value);
  if (!row) return { parentStatus: "unknown", results: [], statusCounts: {} };
  const rawResults = Array.isArray(row.results) ? row.results : [];
  const results = rawResults.flatMap((item) => {
    const result = asRecord(item);
    if (!result) return [];
    const skillId = readStr(result, "skill_id");
    const investigationId = readStr(result, "investigation_id");
    if (!skillId || !investigationId) return [];
    return [{
      skillId,
      title: readStr(result, "title") ?? skillId,
      phase: readStr(result, "phase") ?? "detection",
      investigationId,
      status: readStr(result, "status") ?? "unknown",
      outcomeKind: readStr(result, "outcome_kind"),
      confidence: readStr(result, "confidence"),
      summary: readStr(result, "summary"),
    }];
  });
  const rawCounts = asRecord(row.status_counts) ?? {};
  const statusCounts = Object.fromEntries(Object.entries(rawCounts).map(([key, count]) => [key, typeof count === "number" ? count : 0]));
  return { parentStatus: readStr(row, "parent_status") ?? "unknown", results, statusCounts };
}

export default function SastAuditResults({ targetId, onOpenXray }: {
  targetId: string;
  onOpenXray: (investigation: Investigation) => void;
}): JSX.Element {
  const auditsQ = useQuery({
    queryKey: ["sast-audit", "parents", targetId],
    queryFn: async () => {
      const data = await apiFetch<unknown>(`/vr/investigations?target_id=${encodeURIComponent(targetId)}&kind=sast_audit&limit=20`);
      return (Array.isArray(data) ? data : []).map(asRecord).filter((row): row is Record<string, unknown> => row !== null);
    },
    refetchInterval: 15000,
  });
  const auditId = auditsQ.data?.map((row) => readStr(row, "id")).find((id) => id !== null) ?? null;
  const aggregateQ = useQuery({
    queryKey: ["sast-audit", "aggregate", auditId],
    queryFn: async () => parseAggregate(await apiFetch<unknown>(
      `/vr/targets/${encodeURIComponent(targetId)}/sast-audit-aggregate?audit_id=${encodeURIComponent(auditId ?? "")}`,
    )),
    enabled: auditId !== null,
    refetchInterval: 5000,
  });
  if (auditsQ.isPending) return <p style={mutedCss}>Loading prepared SAST audits...</p>;
  if (auditId === null) return <p style={mutedCss}>No SAST prepared audit has been dispatched for this source target.</p>;
  if (aggregateQ.isError) return <p style={mutedCss}>The SAST audit aggregate could not be loaded.</p>;
  const aggregate = aggregateQ.data;
  if (!aggregate) return <p style={mutedCss}>Loading all 16 skill investigations...</p>;
  return (
    <div style={css("display:flex;flex-direction:column;gap:10px;")}>
      <div style={{ ...mutedCss, display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <StatusBadge value={aggregate.parentStatus} />
        <span>{aggregate.results.length} skills · {aggregate.results.filter((result) => result.phase === "detection").length} detectors</span>
        {Object.entries(aggregate.statusCounts).map(([status, count]) => <span key={status}>{status}: {count}</span>)}
      </div>
      <div style={css("overflow-x:auto;")}>
        <table style={tableCss} aria-label="SAST prepared skill results">
          <thead><tr>{["Phase", "Skill", "State", "Outcome", "Evidence summary"].map((heading) => <th key={heading} style={cellCss}>{heading}</th>)}</tr></thead>
          <tbody>{aggregate.results.map((result) => <tr key={result.skillId}>
            <td style={cellCss}>{result.phase}</td>
            <td style={cellCss}>
              <button type="button" style={linkCss} onClick={() => onOpenXray({ id: result.investigationId, title: result.title, target_id: targetId, status: result.status, kind: "audit" })}>{result.title}</button>
              <code style={{ display: "block", color: "var(--text-faint)", marginTop: 3 }}>{result.skillId}</code>
            </td>
            <td style={cellCss}><StatusBadge value={result.status} /></td>
            <td style={cellCss}>{result.outcomeKind ?? "pending"}{result.confidence ? ` · ${result.confidence}` : ""}</td>
            <td style={{ ...cellCss, maxWidth: 420 }}>{result.summary ?? "No primary outcome yet."}</td>
          </tr>)}</tbody>
        </table>
      </div>
    </div>
  );
}
