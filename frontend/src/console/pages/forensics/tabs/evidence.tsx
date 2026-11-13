import type { JSX } from "react";
import { useState } from "react";

import { parseEvidencePage, useForensicsQuery } from "../../../../api/forensics";
import type { EvidenceItem } from "../../../../api/forensics";
import { CtlBtn, DataTable } from "../panels";
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

/** Rows per request; the list route caps page_size at 500. */
const PAGE_SIZE = 100;

export function EvidenceTab({ projectId }: TabProps): JSX.Element {
  const [page, setPage] = useState(1);
  const qs = `page=${page}&page_size=${PAGE_SIZE}`;
  const q = useForensicsQuery(projectId, ["evidence", qs], `/forensics/projects/${projectId}/evidence?${qs}`, parseEvidencePage);
  const rows = q.data?.items ?? [];
  const total = q.data?.total ?? null;
  const [sel, setSel] = useState<EvidenceItem | null>(null);
  const state = queryState(q, "no evidence files.", "/evidence", rows.length === 0);
  return (
    <TableWithDetail
      title="evidence"
      tag={`page ${page} \u00b7 ${rows.length} rows${total != null ? ` \u00b7 total ${total}` : ""}`}
      right={
        <>
          <CtlBtn label={"\u25c0"} title="prev page" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1} />
          <CtlBtn label={"\u25b6"} title="next page" onClick={() => setPage((p) => p + 1)} disabled={total != null ? page * PAGE_SIZE >= total : rows.length < PAGE_SIZE} />
        </>
      }
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
