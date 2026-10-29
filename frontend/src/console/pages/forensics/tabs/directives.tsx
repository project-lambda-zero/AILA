import type { JSX } from "react";
import { useState } from "react";

import { useMutation, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "../../../../api/client";
import { parseDirective, parseRows, useForensicsQuery } from "../../../../api/forensics";
import type { Directive } from "../../../../api/forensics";
import { apiErrDetail } from "../../../../api/parse";
import { css } from "../../../css";
import { toast } from "../../../toast";
import { DirectiveCreateForm } from "../forms";
import { CtlBtn, DataTable, Panel, VerdictBadge } from "../panels";
import type { TableColumn } from "../panels";
import { DownloadBtn, queryState } from "./shared";
import type { TabProps } from "./shared";

const COLS: TableColumn<Directive>[] = [
  { field: "text", label: "directive" },
  {
    field: "investigation_id",
    label: "scope",
    width: 130,
    render: (r) => (r.investigation_id ? `inv ${r.investigation_id.slice(0, 8)}` : "project-wide"),
  },
  { field: "active", label: "active", width: 70, render: (r) => (r.active ? "yes" : "no") },
  { field: "verdict", label: "verdict", width: 110, render: (r) => <VerdictBadge verdict={r.verdict} /> },
  { field: "strategy_family", label: "strategy", width: 140 },
  { field: "created_by", label: "by", width: 130 },
  { field: "created_at", label: "created", width: 170 },
];

export function DirectivesTab({ projectId }: TabProps): JSX.Element {
  const qc = useQueryClient();
  const [includeInactive, setIncludeInactive] = useState(false);
  const q = useForensicsQuery(
    projectId,
    ["directives", String(includeInactive)],
    `/forensics/projects/${projectId}/directives?include_inactive=${includeInactive}`,
    (raw) => parseRows(raw, parseDirective),
  );
  const rows = q.data ?? [];
  const [openForm, setOpenForm] = useState(false);
  const state = queryState(q, "no directives.", "/directives", rows.length === 0);
  const del = useMutation({
    mutationFn: async (id: string): Promise<void> => {
      await apiFetch<unknown>(`/forensics/projects/${projectId}/directives/${id}`, { method: "DELETE" });
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["forensics", projectId, "directives"] }),
    onError: (e) => toast.fail("deactivate directive", apiErrDetail(e)),
  });
  return (
    <>
      <Panel
        title="directives"
        tag={`${rows.length}`}
        right={
          <>
            <label style={css("display:inline-flex;gap:6px;align-items:center;font-family:var(--font-mono);font-size:11px;color:var(--text-muted);")}>
              <input type="checkbox" checked={includeInactive} onChange={(e) => setIncludeInactive(e.target.checked)} />
              include inactive
            </label>
            <DownloadBtn
              path={`/forensics/projects/${projectId}/directives.md`}
              filename={`directives-${projectId.slice(0, 8)}.md`}
              label="download .md"
            />
            <CtlBtn label="+ new" tone="accent" onClick={() => setOpenForm(true)} />
          </>
        }
      >
        {state ?? (
          <DataTable
            rows={rows}
            columns={COLS}
            rowActions={(r) =>
              r.active ? (
                <CtlBtn
                  label={del.isPending && del.variables === r.id ? "deactivating\u2026" : "deactivate"}
                  tone="danger"
                  disabled={del.isPending}
                  onClick={() => window.confirm("Soft-delete this directive?") && del.mutate(r.id)}
                />
              ) : null
            }
          />
        )}
      </Panel>
      {openForm ? <DirectiveCreateForm projectId={projectId} onClose={() => setOpenForm(false)} /> : null}
    </>
  );
}
