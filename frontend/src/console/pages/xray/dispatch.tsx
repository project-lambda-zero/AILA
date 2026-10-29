import type { JSX } from "react";

import type { DispatchState } from "../../../api/types";
import { css } from "../../css";
import { H, emptyNote, kLabel, kVal, kv } from "./theme";

export type NodeState = "active" | "done" | "eligible";

// Structural hub nodes are not gated dispatch phases.
const STRUCTURAL = { setup: true, oracle: true, emit: true, investigation_ledger: true } as const satisfies Record<string, true>;

// Phase-node state from real dispatch-hub state (visited / current phases,
// aggregated across the investigation's branch cursors) -- never a fabricated
// heuristic. Structural nodes infer their state from real signals: setup /
// oracle / ledger have run once any branch exists; emit only completes when
// the investigation does.
export function nodeStateOf(
  id: string,
  { invRunning, visited, current, branchCount }: { invRunning: boolean; visited: ReadonlySet<string>; current: ReadonlySet<string>; branchCount: number },
): NodeState {
  // Only a running investigation has a live "active" phase; a finished run's
  // current_state is just the last phase it reached -> render as done.
  if (invRunning && current.has(id)) return "active";
  if (visited.has(id) || current.has(id)) return "done";
  if (Object.hasOwn(STRUCTURAL, id)) {
    if (id === "emit") return invRunning ? "eligible" : "done";
    return branchCount > 0 ? "done" : "eligible";
  }
  return "eligible";
}

// Colour key under a phase graph.
export function PhaseLegend(): JSX.Element {
  return (
    <div style={css("flex:0 0 auto;display:flex;gap:16px;padding:8px 12px;border-top:1px solid var(--border-soft);font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);")}>
      {([["active", H.mint], ["done", H.cream], ["eligible", "#3a3a3a"], ["gated", H.amber], ["blocked", H.acc]] as const).map(([lbl, c]) => (
        <span key={lbl} style={css("display:flex;align-items:center;gap:5px;")}>
          <span style={css(`width:7px;height:7px;background:${c};border-radius:1px;`)} />{lbl}
        </span>
      ))}
    </div>
  );
}

// Body of the DISPATCH HUB panel: active phase, per-phase gate evaluation and
// the hub-state readout.
export function DispatchHubState({
  dispatchState,
  nodeState,
}: {
  dispatchState: DispatchState | undefined;
  nodeState: (id: string) => NodeState;
}): JSX.Element {
  const activePhase = dispatchState?.current?.[0] ?? dispatchState?.last ?? null;
  return (
    <>
      <div style={kv}>
        <span style={kLabel}>active phase</span><span style={kVal}>{activePhase ?? "\u2014"}</span>
      </div>
      <div style={css("padding:0 13px 8px;font-size:11px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-muted);")}>gate evaluation</div>
      {dispatchState && dispatchState.phases.length > 0 ? (
        dispatchState.phases.map((p) => {
          const st = nodeState(p.id);
          const col = st === "active" ? H.mint : st === "done" ? H.cream : "#3a3a3a";
          return (
            <div key={p.id} style={css("display:flex;align-items:center;gap:9px;padding:4px 13px;font-size:11px;")}>
              <span style={css(`width:6px;height:6px;flex:0 0 auto;border-radius:1px;background:${col};`)} />
              <span style={css("color:var(--text-primary);")}>{p.id}</span>
              {p.capability ? <span style={css("font-size:11px;color:var(--text-faint);")}>{p.capability}</span> : null}
              <span style={css("flex:1;")} />
              {p.trust ? <span style={css("font-size:11px;letter-spacing:0.06em;text-transform:uppercase;color:var(--text-faint);")}>{p.trust}</span> : null}
              <span style={css(`color:${st === "eligible" ? "var(--text-faint)" : col};font-size:11px;letter-spacing:0.08em;text-transform:uppercase;`)}>{st === "done" ? "visited" : st}</span>
            </div>
          );
        })
      ) : (
        <div style={emptyNote}>dispatch state unavailable.</div>
      )}
      {dispatchState ? (
        <>
          <div style={css("padding:8px 13px 6px;margin-top:4px;border-top:1px solid var(--border-faint);font-size:11px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-muted);")}>hub state</div>
          <div style={kv}>
            <span style={kLabel}>visited</span><span style={kVal}>{dispatchState.visited.length ? dispatchState.visited.join(", ") : "\u2014"}</span>
            <span style={kLabel}>last</span><span style={kVal}>{dispatchState.last ?? "\u2014"}</span>
            {dispatchState.reason ? (<><span style={kLabel}>reason</span><span style={kVal}>{dispatchState.reason}</span></>) : null}
            <span style={kLabel}>phase trust</span><span style={kVal}>{dispatchState.phase_trust ?? "\u2014"}</span>
            <span style={kLabel}>replan relax</span><span style={kVal}>{dispatchState.replan_relax ? "true" : "false"}</span>
            <span style={kLabel}>budget</span><span style={kVal}>{dispatchState.budget_exhausted ? "exhausted" : "ok"}</span>
          </div>
        </>
      ) : null}
    </>
  );
}
