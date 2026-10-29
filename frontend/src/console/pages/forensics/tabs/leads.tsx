import type { JSX } from "react";
import { useState } from "react";

import { parseLead, parseRows, useForensicsQuery } from "../../../../api/forensics";
import type { Lead } from "../../../../api/forensics";
import { css } from "../../../css";
import { Select } from "../formControls";
import { DataTable, KV, emptyNote } from "../panels";
import type { TableColumn } from "../panels";
import { FilterField, TableWithDetail, queryState } from "./shared";
import type { TabProps } from "./shared";

const LEAD_COLS: TableColumn<Lead>[] = [
  {
    field: "score",
    label: "score",
    width: 70,
    render: (r) => r.score.toFixed(1),
  },
  { field: "artifact_family", label: "family", width: 100 },
  { field: "artifact_type", label: "type", width: 140 },
  { field: "source_tool", label: "tool", width: 130 },
  { field: "reason", label: "reason" },
];

export function LeadsTab({ projectId }: TabProps): JSX.Element {
  const [limit, setLimit] = useState(200);
  const q = useForensicsQuery(projectId, ["leads", String(limit)], `/forensics/projects/${projectId}/leads?limit=${limit}`, (raw) => parseRows(raw, parseLead));
  const rows = q.data ?? [];
  const [sel, setSel] = useState<Lead | null>(null);
  const state = queryState(q, "no leads yet.", "/leads", rows.length === 0);
  return (
    <TableWithDetail
      title="leads"
      tag={`${rows.length} of ${limit}`}
      right={
        <>
          <FilterField label="limit">
            <Select
              value={String(limit)}
              onChange={(v) => setLimit(Number(v))}
              options={[
                { value: "50", label: "50" },
                { value: "200", label: "200" },
                { value: "500", label: "500" },
                { value: "1000", label: "1000" },
              ]}
            />
          </FilterField>
        </>
      }
      table={state ?? <DataTable rows={rows} columns={LEAD_COLS} selected={sel} onSelect={(r) => setSel((c) => (c === r ? null : r))} />}
      detail={sel}
      onClose={() => setSel(null)}
      detailRenderer={(row) => (
        <div style={css("padding:11px 13px;display:flex;flex-direction:column;gap:12px;")}>
          <KV
            entries={[
              ["score", row.score.toFixed(2)],
              ["reason", row.reason],
              ["family", row.artifact_family],
              ["type", row.artifact_type],
              ["tool", row.source_tool],
              ["question families", row.question_families],
              ["related artifact ids", row.related_artifact_ids],
            ]}
          />
          <div>
            <div style={css("font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);margin:8px 0 5px;")}>evidence</div>
            {row.evidence.length === 0 ? (
              <div style={emptyNote}>none.</div>
            ) : (
              <div style={css("display:flex;flex-direction:column;gap:6px;")}>
                {row.evidence.map((e, i) => (
                  <div
                    key={i}
                    style={css(
                      "border:1px solid var(--border-soft);border-radius:2px;background:var(--surface-sunk);padding:7px 9px;font-size:11px;color:var(--text-primary);",
                    )}
                  >
                    <div style={css("display:flex;gap:9px;font-size:11px;color:var(--text-muted);margin-bottom:4px;")}>
                      <span style={css("color:var(--accent);")}>{e.keyword}</span>
                      <span>{e.path}</span>
                    </div>
                    <div style={css("white-space:pre-wrap;word-break:break-word;font-family:var(--font-mono);font-size:11px;color:var(--text-primary);")}>{e.excerpt}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    />
  );
}
