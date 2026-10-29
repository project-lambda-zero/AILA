import type { Dispatch, JSX, ReactNode, SetStateAction } from "react";

import type { Branch, Hypothesis, Investigation, Message } from "../../../../api/types";
import { css } from "../../../css";
import { OverviewDrawers } from "../chrome";
import { ActivityFeed, HypothesisDrawerList } from "../hypotheses";
import type { OverviewDrawer } from "../layout";
import { usd } from "../parsers";
import type { Persona } from "../persona";
import { kLabel, kVal, kv } from "../theme";
import type { XRayShell } from "../useXRayShell";
import { TurnsPanel, type TurnsPanelProps } from "./TurnsPanel";

// 1 OVERVIEW: the wide TURNS panel plus the brief / records / engine /
// activity drawer columns.
export function OverviewView({
  turns,
  shell,
  openDrawer,
  setOpenDrawer,
  inv,
  caseId,
  target,
  hypList,
  liveHyps,
  branchList,
  turnCount,
  promoted,
  recentMsgs,
  resolvePersona,
  onOpenHypothesis,
}: {
  turns: TurnsPanelProps;
  shell: XRayShell;
  openDrawer: string | null;
  setOpenDrawer: Dispatch<SetStateAction<string | null>>;
  inv: Investigation | undefined;
  caseId: string;
  target: string;
  hypList: readonly Hypothesis[];
  liveHyps: number;
  branchList: readonly Branch[];
  turnCount: number;
  promoted: number;
  recentMsgs: readonly Message[];
  resolvePersona: (m: Message) => Persona;
  onOpenHypothesis: (h: Hypothesis) => void;
}): JSX.Element {
  const d = inv;
  const activeBr = branchList.filter((b) => b.status === "active").length;
  const rejectedHyps = hypList.filter((h) => (h.state ?? "").toLowerCase() === "rejected").length;
  // Body of each collapsible overview drawer column.
  const drawerBody = (id: OverviewDrawer): ReactNode => {
    if (id === "brief") {
      return (
        <div style={css("padding:11px 13px;display:flex;flex-direction:column;gap:10px;")}>
          <div>
            <div style={css("font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:var(--accent);")}>prompt</div>
            <div style={css("margin-top:4px;font-family:var(--font-sans,system-ui);font-size:11.5px;line-height:1.45;color:var(--text-primary);text-wrap:pretty;")}>{target}</div>
          </div>
          <div style={kv}>
            <span style={kLabel}>case</span><span style={kVal}>{caseId}</span>
            <span style={kLabel}>kind</span><span style={kVal}>{d?.kind ?? "\u2014"}</span>
            <span style={kLabel}>strategy</span><span style={kVal}>{d?.strategy_family ?? "\u2014"}</span>
            <span style={kLabel}>status</span><span style={kVal}>{d?.status ?? "\u2014"}</span>
            <span style={kLabel}>budget</span><span style={kVal}>{usd(d?.cost_budget_usd)}</span>
            {d?.primary_outcome_verdict_head ? (<><span style={kLabel}>verdict</span><span style={kVal}>{d.primary_outcome_verdict_head.replace(/^#+\s*/, "")}</span></>) : null}
          </div>
        </div>
      );
    }
    if (id === "records") return <HypothesisDrawerList hypList={hypList} onOpen={onOpenHypothesis} />;
    if (id === "engine") {
      return (
        <div style={kv}>
          <span style={kLabel}>loops</span><span style={kVal}>{branchList.length} &#183; {activeBr} active</span>
          <span style={kLabel}>turns</span><span style={kVal}>{turnCount}</span>
          <span style={kLabel}>hypotheses</span><span style={kVal}>{liveHyps} live &#183; {rejectedHyps} rej &#183; {hypList.length} total</span>
          <span style={kLabel}>promoted</span><span style={kVal}>{promoted}</span>
          <span style={kLabel}>budget</span><span style={kVal}>{usd(d?.cost_actual_usd)} / {usd(d?.cost_budget_usd)}</span>
          {d?.primary_outcome_kind ? (<><span style={kLabel}>outcome</span><span style={kVal}>{d.primary_outcome_kind}{d.primary_outcome_confidence ? ` \u00b7 ${d.primary_outcome_confidence}` : ""}</span></>) : null}
          {d?.verifier_verdict ? (<><span style={kLabel}>verifier</span><span style={kVal}>{d.verifier_verdict}{d.verifier_confidence ? ` \u00b7 ${d.verifier_confidence}` : ""}</span></>) : null}
          <span style={kLabel}>auto-pilot</span><span style={kVal}>{d?.auto_pilot ? "on" : "off"}</span>
        </div>
      );
    }
    return <ActivityFeed recentMsgs={recentMsgs} resolvePersona={resolvePersona} />;
  };
  return (
    <div style={css("flex:1;min-height:0;display:flex;gap:4px;padding:4px;")}>
      <div style={css("flex:1 1 0;min-width:0;display:flex;flex-direction:column;")}>
        <TurnsPanel {...turns} />
      </div>
      <OverviewDrawers shell={shell} openDrawer={openDrawer} setOpenDrawer={setOpenDrawer} renderBody={drawerBody} />
    </div>
  );
}
