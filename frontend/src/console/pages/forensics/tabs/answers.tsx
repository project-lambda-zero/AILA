import type { JSX } from "react";
import { useState } from "react";

import { parseAnswerCandidate, parseRows, useForensicsQuery } from "../../../../api/forensics";
import type { AnswerCandidate } from "../../../../api/forensics";
import { css } from "../../../css";
import { DataTable, KV } from "../panels";
import type { TableColumn } from "../panels";
import { TableWithDetail, queryState } from "./shared";
import type { TabProps } from "./shared";

const ANSWER_COLS: TableColumn<AnswerCandidate>[] = [
  { field: "question_text", label: "question" },
  { field: "answer_text", label: "answer" },
  { field: "confidence", label: "confidence", width: 110 },
  { field: "primary_artifact_id", label: "primary artifact" },
  { field: "created_at", label: "created", width: 170 },
];

export function AnswersTab({ projectId }: TabProps): JSX.Element {
  const q = useForensicsQuery(projectId, ["answers"], `/forensics/projects/${projectId}/answers`, (raw) => parseRows(raw, parseAnswerCandidate));
  const rows = q.data ?? [];
  const [sel, setSel] = useState<AnswerCandidate | null>(null);
  const state = queryState(q, "no answered questions yet.", "/answers", rows.length === 0);
  return (
    <TableWithDetail
      title="answers"
      tag={`${rows.length}`}
      table={state ?? <DataTable rows={rows} columns={ANSWER_COLS} selected={sel} onSelect={(r) => setSel((c) => (c === r ? null : r))} />}
      detail={sel}
      onClose={() => setSel(null)}
      detailRenderer={(row) => (
        <div style={css("padding:11px 13px;display:flex;flex-direction:column;gap:12px;")}>
          <KV
            entries={[
              ["question", row.question_text],
              ["answer", row.answer_text],
              ["confidence", row.confidence],
              ["primary artifact", row.primary_artifact_id],
              ["investigation", row.investigation_id],
              ["format hint", row.format_hint],
              ["created", row.created_at],
              ["corroboration", row.corroboration],
            ]}
          />
        </div>
      )}
    />
  );
}
