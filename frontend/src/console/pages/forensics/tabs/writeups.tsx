import type { JSX } from "react";
import { useState } from "react";

import { useMutation, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "../../../../api/client";
import { parseRows, parseWriteUp, useForensicsQuery } from "../../../../api/forensics";
import type { WriteUp } from "../../../../api/forensics";
import { apiErrDetail } from "../../../../api/parse";
import { css } from "../../../css";
import { toast } from "../../../toast";
import { CtlBtn, DataTable, KV } from "../panels";
import type { TableColumn } from "../panels";
import { DownloadBtn, TableWithDetail, detailCaption, queryState } from "./shared";
import type { TabProps } from "./shared";

const COLS: TableColumn<WriteUp>[] = [
  { field: "title", label: "title" },
  { field: "methodology", label: "methodology" },
  {
    field: "artifacts_referenced",
    label: "artifacts",
    width: 90,
    render: (r) => String(r.artifacts_referenced.length),
  },
  { field: "created_at", label: "created", width: 170 },
];

export function WriteupsTab({ projectId }: TabProps): JSX.Element {
  const qc = useQueryClient();
  const q = useForensicsQuery(projectId, ["writeups"], `/forensics/projects/${projectId}/writeups`, (raw) => parseRows(raw, parseWriteUp));
  const rows = q.data ?? [];
  const [sel, setSel] = useState<WriteUp | null>(null);
  const state = queryState(q, "no write-ups yet.", "/writeups", rows.length === 0);
  const del = useMutation({
    mutationFn: async (id: string): Promise<void> => {
      await apiFetch<unknown>(`/forensics/projects/${projectId}/writeups/${id}`, { method: "DELETE" });
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["forensics", projectId, "writeups"] });
      setSel(null);
    },
    onError: (e) => toast.fail("delete write-up", apiErrDetail(e)),
  });
  return (
    <TableWithDetail
      title="write-ups"
      tag={`${rows.length}`}
      right={
        <DownloadBtn
          path={`/forensics/projects/${projectId}/writeups.md`}
          filename={`writeups-${projectId.slice(0, 8)}.md`}
          label="download all .md"
        />
      }
      table={
        state ?? (
          <DataTable
            rows={rows}
            columns={COLS}
            selected={sel}
            onSelect={(r) => setSel((c) => (c === r ? null : r))}
            rowActions={(r) => (
              <div style={css("display:inline-flex;gap:5px;")}>
                <DownloadBtn path={`/forensics/projects/${projectId}/writeups/${r.id}.md`} filename={`${r.title || r.id}.md`} label="download" />
                <CtlBtn
                  label={del.isPending && del.variables === r.id ? "deleting\u2026" : "delete"}
                  tone="danger"
                  disabled={del.isPending}
                  onClick={() => window.confirm("Delete write-up?") && del.mutate(r.id)}
                />
              </div>
            )}
          />
        )
      }
      detail={sel}
      onClose={() => setSel(null)}
      detailRenderer={(row) => (
        <div style={css("padding:11px 13px;display:flex;flex-direction:column;gap:12px;")}>
          <KV entries={[["title", row.title], ["methodology", row.methodology], ["investigation", row.investigation_id], ["created", row.created_at], ["artifacts referenced", row.artifacts_referenced]]} />
          <div>
            <div style={detailCaption}>content</div>
            <pre style={css("margin:0;padding:10px;background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:2px;font-family:var(--font-mono);font-size:11px;color:var(--text-primary);white-space:pre-wrap;word-break:break-word;max-height:60vh;overflow:auto;")}>
              {row.content_markdown}
            </pre>
          </div>
        </div>
      )}
    />
  );
}
