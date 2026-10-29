import type { JSX } from "react";
import { useState } from "react";

import { parseOccurrence, parseRows, useForensicsQuery } from "../../../../api/forensics";
import type { Occurrence } from "../../../../api/forensics";
import { css } from "../../../css";
import { Select } from "../formControls";
import { DataTable, DictPanel, KV } from "../panels";
import type { TableColumn } from "../panels";
import { CONF_OPTIONS, FilterField, TableWithDetail, detailCaption, queryState } from "./shared";
import type { TabProps } from "./shared";

const COLS: TableColumn<Occurrence>[] = [
  { field: "source", label: "source", width: 130 },
  { field: "event_type", label: "event", width: 130 },
  { field: "description", label: "description" },
  { field: "recorded_at", label: "recorded", width: 200 },
];

export function OccurrencesTab({ projectId }: TabProps): JSX.Element {
  const [minConf, setMinConf] = useState("medium");
  const q = useForensicsQuery(
    projectId,
    ["occurrences", minConf],
    `/forensics/projects/${projectId}/occurrences?min_confidence=${minConf}&limit=2000`,
    (raw) => parseRows(raw, parseOccurrence),
  );
  const rows = q.data ?? [];
  const [sel, setSel] = useState<Occurrence | null>(null);
  const state = queryState(q, "no confident findings without event-time.", "/occurrences", rows.length === 0);
  return (
    <TableWithDetail
      title="occurrences"
      tag={`${rows.length}`}
      right={
        <FilterField label="min confidence">
          <Select value={minConf} onChange={setMinConf} options={CONF_OPTIONS} />
        </FilterField>
      }
      table={state ?? <DataTable rows={rows} columns={COLS} selected={sel} onSelect={(r) => setSel((c) => (c === r ? null : r))} />}
      detail={sel}
      onClose={() => setSel(null)}
      detailRenderer={(row) => (
        <div style={css("padding:11px 13px;display:flex;flex-direction:column;gap:12px;")}>
          <KV
            entries={[
              ["source", row.source],
              ["event type", row.event_type],
              ["description", row.description],
              ["artifact id", row.artifact_id],
              ["from investigation", row.source_investigation_id],
              ["recorded at", row.recorded_at],
            ]}
          />
          <div>
            <div style={detailCaption}>data</div>
            <DictPanel data={row.data} initialOpen />
          </div>
        </div>
      )}
    />
  );
}
