import type { JSX } from "react";
import { useState } from "react";

import { parseInvestigationSummary, parseRows, useForensicsQuery } from "../../../../api/forensics";
import type { InvestigationSummary } from "../../../../api/forensics";
import { css } from "../../../css";
import { InvestigateForm } from "../forms";
import { CtlBtn, DataTable, H, Panel, StatusBadge } from "../panels";
import type { TableColumn } from "../panels";
import { queryState } from "./shared";
import type { TabProps } from "./shared";

const COLS: TableColumn<InvestigationSummary>[] = [
  { field: "question", label: "question" },
  { field: "status", label: "status", width: 130, render: (r) => <StatusBadge value={r.status} /> },
  {
    field: "attempts_used",
    label: "attempts",
    width: 90,
    render: (r) => `${r.attempts_used}${r.max_attempts != null ? "/" + r.max_attempts : ""}`,
  },
  { field: "confidence", label: "confidence", width: 110 },
  { field: "final_answer", label: "final answer" },
  {
    field: "needs_reap",
    label: "reap",
    width: 70,
    render: (r) =>
      r.needs_reap ? (
        <span style={css(`color:${H.warn};font-size:11px;letter-spacing:0.08em;text-transform:uppercase;`)}>needs reap</span>
      ) : (
        "\u2014"
      ),
  },
];

export function InvestigationsTab({ projectId, onOpenInvestigation }: TabProps): JSX.Element {
  const q = useForensicsQuery(
    projectId,
    ["investigations"],
    `/forensics/projects/${projectId}/investigations`,
    (raw) => parseRows(raw, parseInvestigationSummary),
    6000,
  );
  const rows = q.data ?? [];
  const [openForm, setOpenForm] = useState(false);
  const state = queryState(q, "no investigations yet.", "/investigations", rows.length === 0);
  return (
    <>
      <Panel
        title="investigations"
        tag={`${rows.length}`}
        right={<CtlBtn label="+ ask a question" tone="accent" onClick={() => setOpenForm(true)} />}
      >
        {state ?? (
          <DataTable rows={rows} columns={COLS} onSelect={(r) => onOpenInvestigation(r.id)} empty="no investigations yet." />
        )}
      </Panel>
      {openForm ? (
        <InvestigateForm projectId={projectId} onClose={() => setOpenForm(false)} onCreated={onOpenInvestigation} />
      ) : null}
    </>
  );
}
