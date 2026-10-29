import type { JSX } from "react";
import { useState } from "react";

import { carvedFilePath, parseArtifactPage, useForensicsQuery } from "../../../../api/forensics";
import type { Artifact } from "../../../../api/forensics";
import { css } from "../../../css";
import { Select, TextInput } from "../formControls";
import { CtlBtn, DataTable, DictPanel, KV } from "../panels";
import type { TableColumn } from "../panels";
import { DownloadBtn, FilterField, TableWithDetail, queryState } from "./shared";
import type { TabProps } from "./shared";

const ARTIFACT_FAMILIES = [
  "host",
  "user",
  "execution",
  "browser",
  "network",
  "memory",
  "malware",
  "log",
  "filesystem",
  "container",
  "cloud",
  "mobile",
  "firmware",
];

/** artifact_type the pcap collector emits for each Zeek-carved file. */
const CARVED_FILE_TYPE = "carved_file";

const ARTIFACT_COLS: TableColumn<Artifact>[] = [
  { field: "artifact_family", label: "family", width: 100 },
  { field: "artifact_type", label: "type" },
  { field: "source_tool", label: "tool", width: 140 },
  {
    field: "lead_score",
    label: "score",
    width: 80,
    render: (r) => (r.lead_score == null ? "\u2014" : r.lead_score.toFixed(2)),
  },
  { field: "source_investigation_id", label: "from inv", width: 120 },
];

export function ArtifactsTab({ projectId }: TabProps): JSX.Element {
  const [family, setFamily] = useState<string>("");
  const [type, setType] = useState<string>("");
  const [source, setSource] = useState<string>("");
  const [invId, setInvId] = useState<string>("");
  const [page, setPage] = useState(1);
  const pageSize = 50;
  const qs = new URLSearchParams();
  if (family) qs.set("artifact_family", family);
  if (type) qs.set("artifact_type", type);
  if (source) qs.set("source", source);
  if (invId) qs.set("investigation_id", invId);
  qs.set("page", String(page));
  qs.set("page_size", String(pageSize));
  const q = useForensicsQuery(projectId, ["artifacts", qs.toString()], `/forensics/projects/${projectId}/artifacts?${qs.toString()}`, parseArtifactPage);
  const rows = q.data?.items ?? [];
  const total = q.data?.total ?? null;
  const [sel, setSel] = useState<Artifact | null>(null);
  const state = queryState(q, "no artifacts match.", "/artifacts", rows.length === 0);
  const carvedOnly = type === CARVED_FILE_TYPE;
  return (
    <TableWithDetail
      title="artifacts"
      tag={`page ${page} \u00b7 ${rows.length} rows${total != null ? ` \u00b7 total ${total}` : ""}`}
      right={
        <>
          <CtlBtn label={"\u25c0"} title="prev page" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1} />
          <CtlBtn label={"\u25b6"} title="next page" onClick={() => setPage((p) => p + 1)} disabled={total != null ? page * pageSize >= total : rows.length < pageSize} />
        </>
      }
      filters={
        <>
          <FilterField label="family">
            <Select
              value={family}
              onChange={(v) => {
                setFamily(v);
                setPage(1);
              }}
              options={[{ value: "", label: "any" }, ...ARTIFACT_FAMILIES.map((f) => ({ value: f, label: f }))]}
            />
          </FilterField>
          <FilterField label="type">
            <TextInput value={type} onChange={setType} placeholder="e.g. autorun_entry" />
          </FilterField>
          <FilterField label="source">
            <Select
              value={source}
              onChange={(v) => setSource(v)}
              options={[
                { value: "", label: "any" },
                { value: "collectors", label: "collectors" },
                { value: "investigations", label: "investigations" },
              ]}
            />
          </FilterField>
          <FilterField label="investigation id">
            <TextInput value={invId} onChange={setInvId} placeholder={"\u2014"} />
          </FilterField>
          <CtlBtn
            label={carvedOnly ? "all types" : "carved files"}
            title="pcap files carved by Zeek; each row downloads the extracted bytes"
            tone={carvedOnly ? "muted" : "accent"}
            onClick={() => {
              setType(carvedOnly ? "" : CARVED_FILE_TYPE);
              setPage(1);
            }}
          />
        </>
      }
      table={
        state ?? (
          <DataTable
            rows={rows}
            columns={ARTIFACT_COLS}
            selected={sel}
            onSelect={(r) => setSel((c) => (c === r ? null : r))}
            rowActions={(r) =>
              r.carved ? (
                <DownloadBtn path={carvedFilePath(projectId, r.carved.sha256)} filename={r.carved.filename} label="download" />
              ) : null
            }
          />
        )
      }
      detail={sel}
      onClose={() => setSel(null)}
      detailRenderer={(row) => (
        <div style={css("padding:11px 13px;display:flex;flex-direction:column;gap:12px;")}>
          <KV
            entries={[
              ["id", row.id],
              ["family", row.artifact_family],
              ["type", row.artifact_type],
              ["tool", row.source_tool],
              ["lead score", row.lead_score],
              ["evidence id", row.source_evidence_id],
              ["from investigation", row.source_investigation_id],
            ]}
          />
          {row.carved ? (
            <div style={css("display:flex;align-items:center;gap:9px;padding:0 3px;font-size:11px;color:var(--text-muted);")}>
              <span style={css("font-family:var(--font-mono);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;")}>{row.carved.filename}</span>
              <span style={css("flex:1;")} />
              <DownloadBtn path={carvedFilePath(projectId, row.carved.sha256)} filename={row.carved.filename} label="download carved file" tone="accent" />
            </div>
          ) : null}
          <div style={css("padding:0 3px;")}>
            <div style={css("font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);margin-bottom:5px;")}>data</div>
            <DictPanel data={row.data} initialOpen />
          </div>
        </div>
      )}
    />
  );
}
