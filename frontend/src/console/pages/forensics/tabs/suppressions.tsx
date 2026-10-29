import type { JSX } from "react";

import { useMutation, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "../../../../api/client";
import { parseRows, parseSuppression, useForensicsQuery } from "../../../../api/forensics";
import type { Suppression } from "../../../../api/forensics";
import { apiErrDetail } from "../../../../api/parse";
import { toast } from "../../../toast";
import { CtlBtn, DataTable, Panel } from "../panels";
import type { TableColumn } from "../panels";
import { queryState } from "./shared";
import type { TabProps } from "./shared";

const COLS: TableColumn<Suppression>[] = [
  { field: "fingerprint", label: "fingerprint" },
  { field: "artifact_type", label: "type", width: 140 },
  { field: "path", label: "path" },
  { field: "name", label: "name" },
  { field: "reasons", label: "reasons", render: (r) => r.reasons.join(", ") },
  { field: "suppressed_by", label: "by", width: 130 },
  { field: "suppressed_at", label: "suppressed", width: 180 },
];

export function SuppressionsTab({ projectId }: TabProps): JSX.Element {
  const qc = useQueryClient();
  const q = useForensicsQuery(
    projectId,
    ["suppressions"],
    `/forensics/projects/${projectId}/findings/suppressions`,
    (raw) => parseRows(raw, parseSuppression),
  );
  const rows = q.data ?? [];
  const state = queryState(q, "no suppressions.", "/findings/suppressions", rows.length === 0);
  const del = useMutation({
    mutationFn: async (id: string): Promise<void> => {
      await apiFetch<unknown>(`/forensics/projects/${projectId}/findings/suppressions/${id}`, { method: "DELETE" });
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["forensics", projectId, "suppressions"] });
      void qc.invalidateQueries({ queryKey: ["forensics", projectId, "findings"] });
    },
    onError: (e) => toast.fail("delete suppression", apiErrDetail(e)),
  });
  return (
    <Panel title="suppressions" tag={`${rows.length}`}>
      {state ?? (
        <DataTable
          rows={rows}
          columns={COLS}
          rowActions={(r) => (
            <CtlBtn
              label={del.isPending && del.variables === r.id ? "deleting\u2026" : "delete"}
              tone="danger"
              disabled={del.isPending}
              onClick={() => window.confirm("Remove suppression? The row re-appears.") && del.mutate(r.id)}
            />
          )}
        />
      )}
    </Panel>
  );
}
