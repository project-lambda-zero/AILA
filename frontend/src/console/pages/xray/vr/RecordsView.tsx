import type { Dispatch, JSX, SetStateAction } from "react";

import type { Branch, Hypothesis, LedgerRow } from "../../../../api/types";
import { css } from "../../../css";
import { HypothesisDetailPanel, HypothesisListPanel } from "../hypotheses";
import { grid2, type PaneView } from "../layout";
import { Panel } from "../Panel";
import { clockTime, ledgerText } from "../parsers";
import { personaTone } from "../persona";
import { H, emptyNote, kLabel, kVal, kv } from "../theme";

// 2 RECORDS: LEDGER + LEDGER ENTRY + HYPOTHESES + HYPOTHESIS.
export function RecordsView({
  pv,
  branchMap,
  narrativeLedger,
  auditLedger,
  visibleLedger,
  showAudit,
  setShowAudit,
  ledgerSel,
  setLedgerSel,
  hypList,
  liveHyps,
  hypSel,
  setHypSel,
}: {
  pv: PaneView;
  branchMap: ReadonlyMap<string, Branch>;
  narrativeLedger: readonly LedgerRow[];
  auditLedger: readonly LedgerRow[];
  visibleLedger: readonly LedgerRow[];
  showAudit: boolean;
  setShowAudit: Dispatch<SetStateAction<boolean>>;
  ledgerSel: LedgerRow | null;
  setLedgerSel: (row: LedgerRow) => void;
  hypList: readonly Hypothesis[];
  liveHyps: number;
  hypSel: Hypothesis | null;
  setHypSel: (h: Hypothesis) => void;
}): JSX.Element {
  return (
    <div style={grid2}>
      <Panel {...pv("ledger")} title="ledger" tag="L" signature="append-only" right={
        <span style={css("display:flex;align-items:center;gap:8px;font-size:11px;color:var(--text-faint);")}>
          <span>{narrativeLedger.length} entries</span>
          {auditLedger.length > 0 ? (
            <span
              onClick={(ev) => { ev.stopPropagation(); setShowAudit((v) => !v); }}
              style={css(`min-height:28px;cursor:pointer;padding:1px 6px;border-radius:2px;letter-spacing:0.06em;text-transform:uppercase;border:1px solid ${showAudit ? H.amber + "88" : "var(--border-faint)"};color:${showAudit ? H.amber : "var(--text-faint)"};`)}
              title={showAudit ? "hide recovery / audit events" : "show recovery / audit events"}
            >{auditLedger.length} audit</span>
          ) : null}
        </span>
      }>
        {visibleLedger.length === 0 ? (
          <div style={emptyNote}>
            {auditLedger.length > 0
              ? `no narrative ledger entries yet - ${auditLedger.length} recovery/audit events hidden (use the "audit" toggle above).`
              : "no ledger entries yet - append-only."}
          </div>
        ) : (
          visibleLedger.map((e) => {
            const who = (branchMap.get(e.author_branch_id ?? "")?.persona_voice ?? "").toUpperCase();
            const isAudit = e.kind === "recovery";
            return (
              <div
                key={e.id}
                onClick={() => setLedgerSel(e)}
                style={css(`display:flex;align-items:center;gap:9px;padding:7px 11px;border-bottom:1px solid var(--border-faint);cursor:pointer;${isAudit ? "opacity:0.55;" : ""}${ledgerSel?.id === e.id ? "background:color-mix(in srgb,var(--accent) 8%,transparent);" : ""}`)}
              >
                <span style={css("flex:0 0 auto;min-width:52px;font-size:11px;font-variant-numeric:tabular-nums;color:var(--text-faint);")}>{clockTime(e.created_at) || "\u2014"}</span>
                <span style={css(`flex:0 0 auto;font-size:11px;letter-spacing:0.08em;text-transform:uppercase;min-width:64px;color:${e.kind === "request" ? H.lav : e.kind === "decision" ? H.mint : e.kind === "objective" ? H.amber : isAudit ? "var(--text-faint)" : H.cream};`)}>{e.intent ? e.intent.replace(/_/g, " ") : e.kind}</span>
                <span style={css(`flex:0 0 auto;min-width:50px;font-size:11px;font-weight:700;letter-spacing:0.06em;color:${who ? personaTone(who) : "var(--text-faint)"};`)}>{who || "\u2014"}</span>
                <span style={css("flex:1;min-width:0;font-size:11px;color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;")}>{ledgerText(e.text)}</span>
                {e.status ? <span style={css("flex:0 0 auto;font-size:11px;letter-spacing:0.06em;text-transform:uppercase;color:var(--text-faint);")}>{e.status}</span> : null}
              </div>
            );
          })
        )}
      </Panel>
      <Panel {...pv("ldetail")} title="ledger entry" tag="E" signature="in plain terms">
        {ledgerSel ? (
          <div style={kv}>
            <span style={kLabel}>kind</span><span style={kVal}>{ledgerSel.kind}</span>
            {ledgerSel.created_at ? (<><span style={kLabel}>when</span><span style={kVal}>{clockTime(ledgerSel.created_at) || ledgerSel.created_at}</span></>) : null}
            {ledgerSel.intent ? (<><span style={kLabel}>intent</span><span style={kVal}>{ledgerSel.intent.replace(/_/g, " ")}</span></>) : null}
            <span style={kLabel}>by</span><span style={css(`color:${personaTone((branchMap.get(ledgerSel.author_branch_id ?? "")?.persona_voice ?? "").toUpperCase())};font-weight:700;letter-spacing:0.06em;`)}>{(branchMap.get(ledgerSel.author_branch_id ?? "")?.persona_voice ?? "unknown").toUpperCase()}</span>
            {ledgerSel.owner_branch_id ? (<><span style={kLabel}>owner</span><span style={kVal}>{(branchMap.get(ledgerSel.owner_branch_id)?.persona_voice ?? ledgerSel.owner_branch_id).toUpperCase()}</span></>) : null}
            {ledgerSel.objective_key ? (<><span style={kLabel}>objective</span><span style={kVal}>{ledgerSel.objective_key}</span></>) : null}
            {ledgerSel.target_capability ? (<><span style={kLabel}>capability</span><span style={kVal}>{ledgerSel.target_capability}</span></>) : null}
            {ledgerSel.status ? (<><span style={kLabel}>status</span><span style={kVal}>{ledgerSel.status}</span></>) : null}
            <span style={kLabel}>text</span><span style={kVal}>{ledgerText(ledgerSel.text)}</span>
          </div>
        ) : (
          <div style={css("padding:13px;")}>
            <div style={css("font-size:11px;color:var(--text-muted);")}>Select an entry on the left.</div>
            <div style={css("margin-top:11px;")}>
              <div style={kv}>
                <span style={kLabel}>entries</span><span style={kVal}>{narrativeLedger.length} narrative, {auditLedger.length} audit</span>
                <span style={kLabel}>kinds</span><span style={kVal}>discovery, request, decision, objective, note, recovery</span>
              </div>
            </div>
          </div>
        )}
      </Panel>
      <HypothesisListPanel pane={pv("hypotheses")} hypList={hypList} liveHyps={liveHyps} selected={hypSel} onSelect={setHypSel} />
      <HypothesisDetailPanel pane={pv("hdetail")} hyp={hypSel} branchMap={branchMap} />
    </div>
  );
}
