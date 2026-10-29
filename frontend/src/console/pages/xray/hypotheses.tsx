import type { JSX } from "react";

import type { Branch, Hypothesis, Message } from "../../../api/types";
import { css } from "../../css";
import type { PaneProps } from "./layout";
import { Panel } from "./Panel";
import { turnProse, turnType } from "./parsers";
import type { Persona } from "./persona";
import { emptyNote, hypTone, kLabel, kVal, kv } from "./theme";

// HYPOTHESES pane: the investigation's hypotheses, click to inspect.
export function HypothesisListPanel({
  pane,
  hypList,
  liveHyps,
  selected,
  onSelect,
}: {
  pane: PaneProps;
  hypList: readonly Hypothesis[];
  liveHyps: number;
  selected: Hypothesis | null;
  onSelect: (h: Hypothesis) => void;
}): JSX.Element {
  return (
    <Panel {...pane} title="hypotheses" tag="H" signature="held privately" right={<span style={css("font-size:11px;color:var(--text-faint);")}>{liveHyps} live</span>}>
      {hypList.length === 0 ? (
        <div style={emptyNote}>no hypotheses filed yet.</div>
      ) : (
        hypList.map((h) => (
          <div
            key={h.id}
            onClick={() => onSelect(h)}
            style={css(`display:flex;align-items:center;gap:9px;padding:8px 11px;border-bottom:1px solid var(--border-faint);cursor:pointer;${selected?.id === h.id ? "background:color-mix(in srgb,var(--accent) 8%,transparent);" : ""}`)}
          >
            <span style={css("flex:1;min-width:0;font-size:11px;color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;")}>{h.claim}</span>
            <span style={css(`flex:0 0 auto;font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:${hypTone(h.state)};`)}>{h.state}</span>
          </div>
        ))
      )}
    </Panel>
  );
}

// HYPOTHESIS pane: the selected hypothesis in plain terms.
export function HypothesisDetailPanel({
  pane,
  hyp,
  branchMap,
}: {
  pane: PaneProps;
  hyp: Hypothesis | null;
  branchMap: ReadonlyMap<string, Branch>;
}): JSX.Element {
  return (
    <Panel {...pane} title="hypothesis" tag="Y" signature="in plain terms">
      {hyp ? (
        <div style={kv}>
          <span style={kLabel}>state</span><span style={css(`color:${hypTone(hyp.state)};text-transform:uppercase;letter-spacing:0.08em;`)}>{hyp.state}</span>
          <span style={kLabel}>claim</span><span style={kVal}>{hyp.claim}</span>
          {hyp.why_plausible ? (<><span style={kLabel}>why plausible</span><span style={kVal}>{hyp.why_plausible}</span></>) : null}
          {hyp.kill_criterion ? (<><span style={kLabel}>kill criterion</span><span style={kVal}>{hyp.kill_criterion}</span></>) : null}
          {hyp.rejection_reason ? (<><span style={kLabel}>why rejected</span><span style={kVal}>{hyp.rejection_reason}</span></>) : null}
          {hyp.resolution_note ? (<><span style={kLabel}>resolution</span><span style={kVal}>{hyp.resolution_note}</span></>) : null}
          {(() => {
            const ids = [...(hyp.live_in_branches ?? []), ...(hyp.rejected_in_branches ?? []), ...(hyp.resolved_in_branches ?? [])];
            const who = [...new Set(ids)].map((x) => (branchMap.get(x)?.persona_voice ?? x).toUpperCase()).join(", ");
            return who ? (<><span style={kLabel}>held by</span><span style={kVal}>{who}</span></>) : null;
          })()}
        </div>
      ) : (
        <div style={css("padding:13px;")}>
          <div style={css("font-size:11px;color:var(--text-muted);")}>Select a hypothesis on the left.</div>
          <div style={kv}>
            <span style={kLabel}>states</span><span style={kVal}>live, rejected, resolved</span>
            <span style={kLabel}>held by</span><span style={kVal}>each branch privately</span>
          </div>
        </div>
      )}
    </Panel>
  );
}

// Overview "records" drawer: compact hypothesis list; a click selects the
// hypothesis and jumps to the records layout.
export function HypothesisDrawerList({ hypList, onOpen }: { hypList: readonly Hypothesis[]; onOpen: (h: Hypothesis) => void }): JSX.Element {
  return hypList.length === 0 ? (
    <div style={emptyNote}>no hypotheses filed.</div>
  ) : (
    <>
      {hypList.map((h) => (
        <div key={h.id} onClick={() => onOpen(h)} style={css("display:flex;align-items:center;gap:8px;padding:6px 11px;border-bottom:1px solid var(--border-faint);cursor:pointer;")}>
          <span style={css("flex:0 0 auto;font-size:11px;color:var(--text-faint);")}>{h.id}</span>
          <span style={css("flex:1;min-width:0;font-size:11px;color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;")}>{h.claim}</span>
          <span style={css(`flex:0 0 auto;font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:${hypTone(h.state)};`)}>{h.state}</span>
        </div>
      ))}
    </>
  );
}

// Overview "activity" drawer: the 50 newest messages, one line each.
export function ActivityFeed({ recentMsgs, resolvePersona }: { recentMsgs: readonly Message[]; resolvePersona: (m: Message) => Persona }): JSX.Element {
  return recentMsgs.length === 0 ? (
    <div style={emptyNote}>no activity yet.</div>
  ) : (
    <>
      {recentMsgs.slice(0, 50).map((m) => {
        const pr = resolvePersona(m);
        return (
          <div key={m.id} style={css("display:flex;align-items:center;gap:7px;padding:5px 11px;border-bottom:1px solid var(--border-faint);")}>
            <span style={css(`width:6px;height:6px;flex:0 0 auto;border-radius:1px;background:${pr.tone};`)} />
            <span style={css(`flex:0 0 auto;font-size:11px;font-weight:700;color:${pr.tone};`)}>{pr.name}</span>
            <span style={css("flex:1;min-width:0;font-size:11px;color:var(--text-muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;")}>{turnProse(m)}</span>
            <span style={css("flex:0 0 auto;font-size:11px;letter-spacing:0.06em;text-transform:uppercase;color:var(--text-faint);")}>{turnType(m.payload_kind || "text")}</span>
          </div>
        );
      })}
    </>
  );
}
