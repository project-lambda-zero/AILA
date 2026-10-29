import type { JSX } from "react";

import { useBranchOp } from "../../../../api/hooks";
import type { Branch } from "../../../../api/types";
import { css } from "../../../css";
import { PhaseLegend, type NodeState } from "../dispatch";
import type { PaneView } from "../layout";
import { Panel } from "../Panel";
import { VR_PERSONA_RULES, personaTone, type PersonaRules } from "../persona";
import { H } from "../theme";
import { BranchActions, StrategySpawnForm } from "./BranchOps";
import { HUB, PHASES } from "./constants";

const PERSONA_RULES: PersonaRules = VR_PERSONA_RULES;

// GRAPHS branch lanes: one card per branch with persona, role, turns, status
// and the operator branch controls, followed by the strategy-spawn form.
export function BranchLanes({ invId, branchList }: { invId: string | null; branchList: readonly Branch[] }): JSX.Element {
  const op = useBranchOp(invId);
  return (
    <div style={css("flex:0 0 auto;display:flex;flex-direction:column;gap:6px;max-height:50%;overflow:auto;")}>
      <div style={css("font-size:11px;letter-spacing:0.16em;text-transform:uppercase;color:var(--text-muted);")}>branch lanes ({branchList.length})</div>
      {branchList.length === 0 ? (
        <div style={css("font-size:11px;color:var(--text-faint);padding:4px 0;")}>no branches spawned yet.</div>
      ) : (
        branchList.map((b) => {
          const name = (b.persona_voice ?? "branch").toUpperCase();
          const role = PERSONA_RULES.roles[(b.persona_voice ?? "").toLowerCase()] ?? (b.strategy_family ?? "").split(".").pop() ?? "";
          return (
            <div key={b.id} style={css("display:flex;flex-direction:column;gap:7px;padding:7px 11px;border:1px solid var(--border-soft);border-radius:3px;background:var(--surface-card);")}>
              <div style={css("display:flex;align-items:center;gap:10px;")}>
                <span style={css(`width:8px;height:8px;flex:0 0 auto;border-radius:1px;background:${b.promoted ? H.mint : personaTone(name)};`)} />
                <span style={css(`font-size:11px;font-weight:700;letter-spacing:0.08em;color:${personaTone(name)};`)}>{name}</span>
                <span style={css("font-size:11px;color:var(--text-faint);")}>{role}</span>
                <span style={css("flex:1;")} />
                <span style={css("font-size:11px;color:var(--text-muted);")}>{b.turn_count ?? 0} turns</span>
                <span style={css("font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-faint);")}>{b.status}{b.promoted ? " · promoted" : ""}</span>
              </div>
              <BranchActions branch={b} branchList={branchList} op={op} />
            </div>
          );
        })
      )}
      <StrategySpawnForm invId={invId} branchList={branchList} />
    </div>
  );
}

// 3 GRAPHS: DISPATCH HUB node graph + branch lanes.
export function GraphsView({
  pv,
  invId,
  nodeState,
  branchList,
}: {
  pv: PaneView;
  invId: string | null;
  nodeState: (id: string) => NodeState;
  branchList: readonly Branch[];
}): JSX.Element {
  return (
    <div style={css("flex:1;min-height:0;display:flex;flex-direction:column;padding:12px;gap:10px;")}>
      <Panel {...pv("phasegraph")} title="dispatch hub · vr.investigate.hub" tag="3" signature="phase graph">
        <div style={css("display:flex;flex-direction:column;height:100%;min-height:0;overflow:hidden;")}>
          <svg viewBox="0 0 1160 420" preserveAspectRatio="xMidYMid meet" style={{ width: "100%", height: "100%", flex: 1, minHeight: 0, background: "#0a0a0a" }}>
            {/* Category Column Headers */}
            <text x={100} y={20} fill="#555" fontSize={8.5} fontFamily="var(--font-mono, monospace)" letterSpacing="0.1em" textAnchor="middle">ORCHESTRATION</text>
            <text x={470} y={20} fill="#555" fontSize={8.5} fontFamily="var(--font-mono, monospace)" letterSpacing="0.1em" textAnchor="middle">RECON &amp; DISCOVERY</text>
            <text x={660} y={20} fill="#555" fontSize={8.5} fontFamily="var(--font-mono, monospace)" letterSpacing="0.1em" textAnchor="middle">SOURCE &amp; SEMANTIC</text>
            <text x={850} y={20} fill="#555" fontSize={8.5} fontFamily="var(--font-mono, monospace)" letterSpacing="0.1em" textAnchor="middle">BINARY &amp; MEMORY</text>
            <text x={1040} y={20} fill="#555" fontSize={8.5} fontFamily="var(--font-mono, monospace)" letterSpacing="0.1em" textAnchor="middle">SYNTHESIS &amp; POC</text>

            {/* Column Separator Guides */}
            <line x1={180} y1={25} x2={180} y2={405} stroke="#181818" strokeDasharray="2 4" />
            <line x1={360} y1={25} x2={360} y2={405} stroke="#181818" strokeDasharray="2 4" />
            <line x1={560} y1={25} x2={560} y2={405} stroke="#181818" strokeDasharray="2 4" />
            <line x1={750} y1={25} x2={750} y2={405} stroke="#181818" strokeDasharray="2 4" />
            <line x1={940} y1={25} x2={940} y2={405} stroke="#181818" strokeDasharray="2 4" />

            {/* Hub to Node Edges */}
            {PHASES.map((p) => {
              const st = nodeState(p.id);
              const col = st === "active" ? H.mint : st === "done" ? H.cream : "#252525";
              const targetX = p.x < HUB.x ? p.x + 140 : p.x;
              const targetY = p.y + 11;
              return (
                <line
                  key={`l-${p.id}`}
                  x1={HUB.x}
                  y1={HUB.y}
                  x2={targetX}
                  y2={targetY}
                  stroke={col}
                  strokeWidth={st === "active" ? 2 : 1}
                  strokeDasharray={st === "eligible" ? "3 3" : "0"}
                  opacity={st === "eligible" ? 0.4 : 0.85}
                />
              );
            })}

            {/* Central Dispatch Hub */}
            <g>
              <rect x={HUB.x - 65} y={HUB.y - 17} width={130} height={34} rx={4} fill="#141414" stroke={H.acc} strokeWidth={1.8} />
              <text x={HUB.x} y={HUB.y + 4} fill={H.acc} fontSize={10} fontFamily="var(--font-mono, monospace)" fontWeight="700" textAnchor="middle">vr.investigate.hub</text>
            </g>

            {/* Phase Nodes */}
            {PHASES.map((p) => {
              const st = nodeState(p.id);
              const col = st === "active" ? H.mint : st === "done" ? H.cream : "#333";
              const fill = st === "active" ? "#102218" : st === "done" ? "#181812" : "#0f0f0f";
              const txt = st === "eligible" ? "var(--text-faint)" : col;
              return (
                <g key={p.id}>
                  <rect
                    x={p.x}
                    y={p.y}
                    width={140}
                    height={22}
                    rx={3}
                    fill={fill}
                    stroke={col}
                    strokeWidth={st === "active" ? 1.8 : 1}
                    strokeDasharray={st === "eligible" ? "3 3" : "0"}
                  />
                  <text
                    x={p.x + 70}
                    y={p.y + 14}
                    fill={txt}
                    fontSize={8.5}
                    fontFamily="var(--font-mono, monospace)"
                    textAnchor="middle"
                  >
                    {p.label}
                  </text>
                </g>
              );
            })}
          </svg>
          <PhaseLegend />
        </div>
      </Panel>
      <BranchLanes invId={invId} branchList={branchList} />
    </div>
  );
}
