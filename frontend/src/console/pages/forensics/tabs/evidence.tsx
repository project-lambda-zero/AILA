import type { JSX } from "react";
import { useState } from "react";

import { parseEvidenceItem, parseRows, useForensicsQuery } from "../../../../api/forensics";
import type { EvidenceItem } from "../../../../api/forensics";
import { DataTable } from "../panels";
import type { TableColumn } from "../panels";
import { TableWithDetail, queryState } from "./shared";
import type { TabProps } from "./shared";

function humanBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MiB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GiB`;
}

const EVIDENCE_COLS: TableColumn<EvidenceItem>[] = [
  { field: "file_path", label: "path" },
  { field: "evidence_type", label: "type", width: 130 },
  { field: "file_hash_sha256", label: "sha256", width: 220 },
  {
    field: "size_bytes",
    label: "size",
    width: 110,
    render: (r) => (r.size_bytes == null ? "\u2014" : humanBytes(r.size_bytes)),
  },
];

export function EvidenceTab({ projectId }: TabProps): JSX.Element {
  const q = useForensicsQuery(projectId, ["evidence"], `/forensics/projects/${projectId}/evidence`, (raw) => parseRows(raw, parseEvidenceItem));
  const rows = q.data ?? [];
  const [sel, setSel] = useState<EvidenceItem | null>(null);
  const state = queryState(q, "no evidence files.", "/evidence", rows.length === 0);
  return (
    <TableWithDetail
      title="evidence"
      tag={`${rows.length} rows`}
      table={
        state ?? (
          <DataTable rows={rows} columns={EVIDENCE_COLS} selected={sel} onSelect={(r) => setSel((c) => (c === r ? null : r))} />
        )
      }
      detail={sel}
      onClose={() => setSel(null)}
    />
  );
}
