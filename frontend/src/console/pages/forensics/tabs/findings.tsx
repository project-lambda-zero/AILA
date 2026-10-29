import type { JSX } from "react";
import { useState } from "react";

import { parseFinding, parseRows, useForensicsQuery } from "../../../../api/forensics";
import type { ForensicsFinding } from "../../../../api/forensics";
import { legalNextStates, useFindingWorkflowStates, useTransitionFinding } from "../../../../api/findingWorkflow";
import { css } from "../../../css";
import { WorkflowStateBadge } from "../../badges";
import { SuppressFindingForm } from "../forms";
import { CtlBtn, DataTable, DictPanel, H, KV } from "../panels";
import type { TableColumn } from "../panels";
import { TableWithDetail, detailCaption, queryState } from "./shared";
import type { TabProps } from "./shared";

/** Per-row workflow-transition control. Fetches the forensics-scoped state
 * machine once and only surfaces the buttons that map to a legal outbound
 * edge from the row's current `workflow_state`. Findings are derived rows
 * keyed by fingerprint, which is the `finding_id` the backend state machine
 * uses. Backend enforces operator+ role and re-validates the transition; a
 * 422 lands here as an inline error string rather than a modal. */
function ForensicsFindingTransition({ row }: { row: ForensicsFinding }): JSX.Element {
  const machineQ = useFindingWorkflowStates("forensics");
  const transitionM = useTransitionFinding();
  const current = row.workflow_state;
  const allowed = legalNextStates(machineQ.data, current);

  if (!row.fingerprint) {
    return (
      <div style={css("border:1px solid var(--border-soft);background:var(--surface-sunk);border-radius:3px;padding:10px 12px;font-size:11px;color:var(--text-muted);")}>
        no fingerprint on this row {"\u2014"} workflow transitions unavailable.
      </div>
    );
  }
  return (
    <div style={css("border:1px solid var(--border-soft);background:var(--surface-sunk);border-radius:3px;padding:11px 12px;display:flex;flex-direction:column;gap:8px;")}>
      <div style={css("display:flex;align-items:center;gap:9px;")}>
        <span style={css("font-size:11px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-faint);")}>
          workflow transition
        </span>
        <span style={css("flex:1;")} />
        <WorkflowStateBadge value={current} />
      </div>
      {machineQ.isLoading ? (
        <div style={css("font-size:11px;color:var(--text-faint);")}>loading state machine {"\u2026"}</div>
      ) : allowed.length === 0 ? (
        <div style={css("font-size:11px;color:var(--text-muted);")}>
          no valid transitions from {"\u201c" + current + "\u201d"}.
        </div>
      ) : (
        <div style={css("display:flex;flex-wrap:wrap;gap:6px;")}>
          {allowed.map((target) => (
            <button
              key={target}
              type="button"
              disabled={transitionM.isPending}
              onClick={() => {
                if (transitionM.isPending) return;
                transitionM.mutate({
                  finding_id: row.fingerprint,
                  module_id: "forensics",
                  target_state: target,
                });
              }}
              style={css(
                "padding:0 11px;height:28px;font-family:var(--font-mono);font-size:11px;letter-spacing:0.06em;text-transform:uppercase;color:var(--accent);border:1px solid " + H.acc + "59;background:" + H.acc + "1c;border-radius:3px;cursor:" + (transitionM.isPending ? "not-allowed" : "pointer") + ";",
              )}
            >
              {"\u2192 " + target}
            </button>
          ))}
        </div>
      )}
      {transitionM.isSuccess ? (
        <div style={css("font-size:11px;color:" + H.mint + ";")}>transition applied.</div>
      ) : null}
      {transitionM.isError ? (
        <div style={css("font-size:11px;color:var(--status-warn);")}>
          {"transition failed \u2014 " + (transitionM.error instanceof Error ? transitionM.error.message : "unknown")}
        </div>
      ) : null}
    </div>
  );
}

const COLS: TableColumn<ForensicsFinding>[] = [
  { field: "artifact_type", label: "type", width: 150 },
  { field: "executable", label: "executable" },
  { field: "path", label: "path" },
  { field: "name", label: "name" },
  { field: "user", label: "user", width: 120 },
  {
    field: "suspicious_reasons",
    label: "reasons",
    render: (r) => (r.suspicious_reasons.length ? r.suspicious_reasons.join(", ") : "\u2014"),
  },
  {
    field: "workflow_state",
    label: "state",
    width: 140,
    render: (r) => <WorkflowStateBadge value={r.workflow_state} />,
  },
  {
    field: "occurrences",
    label: "count",
    width: 70,
    render: (r) => String(r.occurrences),
  },
];

export function FindingsTab({ projectId }: TabProps): JSX.Element {
  const q = useForensicsQuery(projectId, ["findings"], `/forensics/projects/${projectId}/findings`, (raw) => parseRows(raw, parseFinding));
  const rows = q.data ?? [];
  const [sel, setSel] = useState<ForensicsFinding | null>(null);
  const [suppress, setSuppress] = useState<ForensicsFinding | null>(null);
  const state = queryState(q, "no suspicious findings.", "/findings", rows.length === 0);
  return (
    <>
      <TableWithDetail
        title="findings"
        tag={`${rows.length} rows`}
        table={
          state ?? (
            <DataTable
              rows={rows}
              columns={COLS}
              selected={sel}
              onSelect={(r) => setSel((c) => (c === r ? null : r))}
              rowActions={(r) => <CtlBtn label="suppress" tone="warn" onClick={() => setSuppress(r)} />}
            />
          )
        }
        detail={sel}
        onClose={() => setSel(null)}
        detailRenderer={(row) => (
          <div style={css("padding:11px 13px;display:flex;flex-direction:column;gap:12px;")}>
            <KV
              entries={[
                ["fingerprint", row.fingerprint || "\u2014"],
                ["artifact type", row.artifact_type || "\u2014"],
                ["artifact family", row.artifact_family],
                ["source tool", row.source_tool],
                ["executable", row.executable ?? "\u2014"],
                ["path", row.path ?? "\u2014"],
                ["name", row.name ?? "\u2014"],
                ["user", row.user ?? "\u2014"],
                ["reasons", row.suspicious_reasons],
                ["last run", row.last_run],
                ["run count", row.run_count],
                ["occurrences", row.occurrences],
              ]}
            />
            <ForensicsFindingTransition row={row} />
            <div>
              <div style={detailCaption}>raw record</div>
              <DictPanel data={row.raw_record} />
            </div>
          </div>
        )}
      />
      {suppress ? <SuppressFindingForm projectId={projectId} row={suppress} onClose={() => setSuppress(null)} /> : null}
    </>
  );
}
