import type { JSX } from "react";

import type { Branch, DispatchState, LedgerRow, McpCall } from "../../../../api/types";
import { css } from "../../../css";
import { DispatchHubState, type NodeState } from "../dispatch";
import { grid2, type PaneView } from "../layout";
import { Panel } from "../Panel";
import { personaTone } from "../persona";
import { H, emptyNote, kLabel, kVal, kv } from "../theme";
import { buildMcpDisplay, type ToolCallRow } from "./derive";
import { OraclePanel, type DetailItem } from "./OraclePanel";

// 4 ORACLE: ORACLE requests + DISPATCH HUB gate + MCP CALLS + DETAIL.
export function OracleView({
  pv,
  invId,
  requestRows,
  decisionRows,
  branchMap,
  dispatchState,
  nodeState,
  mcpData,
  toolCalls,
  detail,
  setDetail,
}: {
  pv: PaneView;
  invId: string | null;
  requestRows: readonly LedgerRow[];
  decisionRows: readonly LedgerRow[];
  branchMap: ReadonlyMap<string, Branch>;
  dispatchState: DispatchState | undefined;
  nodeState: (id: string) => NodeState;
  mcpData: readonly McpCall[];
  toolCalls: readonly ToolCallRow[];
  detail: DetailItem | null;
  setDetail: (item: DetailItem) => void;
}): JSX.Element {
  const mcpDisplay = buildMcpDisplay(mcpData, toolCalls, branchMap);
  return (
    <div style={grid2}>
      <OraclePanel pane={pv("oracle")} invId={invId} requestRows={requestRows} decisionRows={decisionRows} branchMap={branchMap} onDetail={setDetail} />
      <Panel {...pv("dispatch")} title="dispatch hub" tag="D" signature="gate + hub state">
        <DispatchHubState dispatchState={dispatchState} nodeState={nodeState} />
      </Panel>
      <Panel {...pv("mcp")} title="mcp calls" tag="M" signature="provider · persona" right={<span style={css("font-size:11px;color:var(--text-faint);")}>{mcpDisplay.length}</span>}>
        {mcpDisplay.length === 0 ? (
          <div style={emptyNote}>no mcp calls yet.</div>
        ) : (
          mcpDisplay.map((c) => {
            const stCol = c.status === "ok" ? H.mint : c.status === "pending" ? H.amber : H.acc;
            return (
              <div key={c.id} onClick={() => setDetail({ title: c.label, rows: c.rows, body: c.body })} style={css("display:flex;align-items:center;gap:8px;padding:6px 11px;border-bottom:1px solid var(--border-faint);cursor:pointer;")}>
                <span style={css(`flex:0 0 auto;font-size:11px;letter-spacing:0.08em;text-transform:uppercase;padding:1px 5px;border-radius:2px;color:${stCol};border:1px solid ${stCol}66;`)}>{c.status}</span>
                <span style={css("flex:1;min-width:0;font-size:11px;color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;")}>{c.label}</span>
                {c.latency !== null ? <span style={css("flex:0 0 auto;font-size:11px;color:var(--text-faint);")}>{c.latency}ms</span> : null}
                {c.server ? <span style={css("flex:0 0 auto;font-size:11px;letter-spacing:0.04em;color:var(--text-faint);")}>{c.server}</span> : null}
                {c.persona ? <span style={css(`flex:0 0 auto;font-size:11px;color:${personaTone(c.persona)};`)}>{c.persona}</span> : null}
              </div>
            );
          })
        )}
      </Panel>
      <Panel {...pv("detail")} title="detail" tag="D" signature="click any row">
        {detail ? (
          <div style={kv}>
            <span style={kLabel}>item</span><span style={kVal}>{detail.title}</span>
            {(detail.rows ?? []).map(([k, v]) => (
              <span key={k} style={{ display: "contents" }}><span style={kLabel}>{k}</span><span style={kVal}>{v}</span></span>
            ))}
            {detail.body ? (<><span style={kLabel}>detail</span><span style={kVal}>{detail.body}</span></>) : null}
          </div>
        ) : (
          <div style={css("padding:13px;font-size:11px;color:var(--text-muted);line-height:1.5;")}>
            Nothing selected.
            <div style={css("margin-top:8px;font-size:11px;color:var(--text-faint);")}>Click any ledger row, hypothesis or MCP call. The record opens here — a pane, never a modal.</div>
          </div>
        )}
      </Panel>
    </div>
  );
}
