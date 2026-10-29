import type { JSX } from "react";
import { useState } from "react";

import { useMutation, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "../../../../api/client";
import { parseRows, parseSolidEvidence, useForensicsQuery } from "../../../../api/forensics";
import type { SolidEvidence } from "../../../../api/forensics";
import { apiErrDetail } from "../../../../api/parse";
import { css } from "../../../css";
import { toast } from "../../../toast";
import { CtlBtn, DataTable, KV, VerdictBadge } from "../panels";
import type { TableColumn } from "../panels";
import { TableWithDetail, queryState } from "./shared";
import type { TabProps } from "./shared";

const COLS: TableColumn<SolidEvidence>[] = [
  { field: "question", label: "question" },
  { field: "answer", label: "answer" },
  { field: "verdict", label: "verdict", width: 100, render: (r) => <VerdictBadge verdict={r.verdict} /> },
  { field: "confidence", label: "confidence", width: 110 },
  { field: "primary_artifact", label: "artifact" },
  { field: "tagged_by", label: "by", width: 130 },
  { field: "tagged_at", label: "tagged", width: 170 },
];

export function SolidEvidenceTab({ projectId }: TabProps): JSX.Element {
  const qc = useQueryClient();
  const q = useForensicsQuery(projectId, ["solid-evidence"], `/forensics/projects/${projectId}/solid-evidence`, (raw) => parseRows(raw, parseSolidEvidence));
  const rows = q.data ?? [];
  const [sel, setSel] = useState<SolidEvidence | null>(null);
  const state = queryState(q, "no analyst-tagged evidence.", "/solid-evidence", rows.length === 0);
  const del = useMutation({
    mutationFn: async (id: string): Promise<void> => {
      await apiFetch<unknown>(`/forensics/projects/${projectId}/solid-evidence/${id}`, { method: "DELETE" });
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["forensics", projectId, "solid-evidence"] });
      setSel(null);
    },
    onError: (e) => toast.fail("delete solid evidence", apiErrDetail(e)),
  });
  return (
    <TableWithDetail
      title="solid evidence"
      tag={`${rows.length}`}
      table={
        state ?? (
          <DataTable
            rows={rows}
            columns={COLS}
            selected={sel}
            onSelect={(r) => setSel((c) => (c === r ? null : r))}
            rowActions={(r) => (
              <CtlBtn
                label={del.isPending && del.variables === r.id ? "deleting\u2026" : "delete"}
                tone="danger"
                disabled={del.isPending}
                onClick={() => window.confirm("Remove this solid-evidence row?") && del.mutate(r.id)}
              />
            )}
          />
        )
      }
      detail={sel}
      onClose={() => setSel(null)}
      detailRenderer={(row) => (
        <div style={css("padding:11px 13px;")}>
          <KV
            entries={[
              ["question", row.question],
              ["answer", row.answer],
              ["verdict", <VerdictBadge verdict={row.verdict} key="v" />],
              ["confidence", row.confidence],
              ["primary artifact", row.primary_artifact],
              ["from investigation", row.source_investigation_id],
              ["tagged by", row.tagged_by],
              ["tagged at", row.tagged_at],
              ["notes", row.notes || "\u2014"],
              ["corroboration", row.corroboration],
            ]}
          />
        </div>
      )}
    />
  );
}
