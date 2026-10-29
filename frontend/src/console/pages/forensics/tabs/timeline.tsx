import type { JSX } from "react";
import { useState } from "react";

import { parseRows, parseTimelineEntry, useForensicsQuery } from "../../../../api/forensics";
import type { TimelineEntry } from "../../../../api/forensics";
import { css } from "../../../css";
import { Select } from "../formControls";
import { DataTable, DictPanel, KV } from "../panels";
import type { TableColumn } from "../panels";
import { CONF_OPTIONS, FilterField, TableWithDetail, detailCaption, queryState } from "./shared";
import type { TabProps } from "./shared";

const COLS: TableColumn<TimelineEntry>[] = [
  { field: "timestamp", label: "timestamp", width: 200 },
  { field: "source", label: "source", width: 130 },
  { field: "event_type", label: "event", width: 130 },
  { field: "description", label: "description" },
];

export function TimelineTab({ projectId }: TabProps): JSX.Element {
  const [minConf, setMinConf] = useState("medium");
  const q = useForensicsQuery(
    projectId,
    ["timeline", minConf],
    `/forensics/projects/${projectId}/timeline?min_confidence=${minConf}&limit=2000`,
    (raw) => parseRows(raw, parseTimelineEntry),
  );
  const rows = q.data ?? [];
  const [sel, setSel] = useState<TimelineEntry | null>(null);
  const state = queryState(q, "no time-anchored events at this confidence.", "/timeline", rows.length === 0);
  return (
    <TableWithDetail
      title="timeline"
      tag={`${rows.length} events`}
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
              ["timestamp", row.timestamp],
              ["origin", row.timestamp_origin],
              ["source", row.source],
              ["event type", row.event_type],
              ["description", row.description],
              ["artifact id", row.artifact_id],
              ["from investigation", row.source_investigation_id],
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
