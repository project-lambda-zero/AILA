import type { Dispatch, JSX, SetStateAction } from "react";

import type { Investigation, Message } from "../../../../api/types";
import { css } from "../../../css";
import { CtlButton } from "../chrome";
import type { PaneProps } from "../layout";
import { Panel } from "../Panel";
import type { Persona } from "../persona";
import { TurnList } from "../TurnRow";
import { H, kLabel, kVal, kv } from "../theme";

// The VR investigation control mutation (POST /vr/investigations/{id}/{action}).
export interface VrControl {
  mutate: (action: string) => void;
  isPending: boolean;
  isError: boolean;
  isSuccess: boolean;
  error: Error | null;
  variables: string | undefined;
  data: Investigation | undefined;
}

export interface TurnsPanelProps {
  pane: PaneProps;
  inv: Investigation | undefined;
  invId: string | null;
  caseId: string;
  target: string;
  control: VrControl;
  onNarrative: () => void;
  narrativePending: boolean;
  onFavorite: () => void;
  invRunning: boolean;
  isPaused: boolean;
  messageCount: number;
  onExport: () => void;
  onReset: () => void;
  onReenqueue: () => void;
  turnGroups: readonly Message[][];
  openTurn: string | null;
  setOpenTurn: Dispatch<SetStateAction<string | null>>;
  resolvePersona: (m: Message) => Persona;
  branchCount: number;
  hypCount: number;
}

// TURNS pane: the multi-agent transcript plus the operator control row, each
// control backed by a real VR endpoint.
export function TurnsPanel({
  pane,
  inv,
  invId,
  caseId,
  target,
  control,
  onNarrative,
  narrativePending,
  onFavorite,
  invRunning,
  isPaused,
  messageCount,
  onExport,
  onReset,
  onReenqueue,
  turnGroups,
  openTurn,
  setOpenTurn,
  resolvePersona,
  branchCount,
  hypCount,
}: TurnsPanelProps): JSX.Element {
  const d = inv;
  // Truthful resume feedback: the resume endpoint reports what it actually
  // did -- restored a checkpoint ("resumed"), no checkpoint so it re-enqueued
  // fresh ("reenqueued"), or nothing could be enqueued ("noop_failed"). Keyed
  // to the most recent control action so a pause/verify/reset does not carry
  // stale resume text.
  const resumeFeedback = ((): { tone: string; text: string } | null => {
    if (control.variables !== "resume" || !control.data?.resume_action) return null;
    if (control.data.resume_action === "resumed") return { tone: H.mint, text: "resumed from checkpoint" };
    if (control.data.resume_action === "reenqueued") return { tone: H.amber, text: "no checkpoint \u2014 re-enqueued fresh" };
    return { tone: H.acc, text: "resume failed \u2014 nothing enqueued" };
  })();
  const canReenqueue = Boolean(invId) && !control.isPending;
  return (
    <Panel
      {...pane}
      title="turns"
      tag="T"
      actions={
        <div style={css("flex:0 0 auto;display:flex;align-items:center;gap:5px;")}>
          <CtlButton label={isPaused ? "resume" : "pause"} onClick={() => control.mutate(isPaused ? "resume" : "pause")} enabled={(invRunning || isPaused) && !control.isPending} />
          {resumeFeedback ? <span style={css(`font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:${resumeFeedback.tone};border:1px solid ${resumeFeedback.tone}66;padding:1px 6px;border-radius:2px;`)}>{resumeFeedback.text}</span> : null}
          <CtlButton label="narrative" onClick={onNarrative} enabled={(d?.outcome_count ?? 0) > 0 && !narrativePending} />
          <CtlButton label="re-verify" onClick={() => control.mutate("verify")} enabled={(d?.outcome_count ?? 0) > 0 && !control.isPending} />
          <CtlButton label="export" onClick={onExport} enabled={messageCount > 0} />
          <CtlButton label="reset" onClick={onReset} enabled={Boolean(invId) && !control.isPending} />
          <button
            type="button"
            onClick={canReenqueue ? onReenqueue : undefined}
            disabled={!canReenqueue}
            title="Clear all cursors, cancel queued/running tasks, dispatch a fresh run (no checkpoint resume)"
            style={css(`flex:0 0 auto;font-family:var(--font-mono);font-size:11px;letter-spacing:0.1em;text-transform:uppercase;padding:2px 7px;border:1px solid ${H.acc}88;border-radius:2px;background:transparent;color:${H.acc};cursor:${canReenqueue ? "pointer" : "default"};${canReenqueue ? "" : "opacity:0.4;"}`)}
          >
            re-enqueue
          </button>
          {control.isPending ? (
            <span style={css(`font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-faint);border:1px solid var(--border-soft);padding:1px 6px;border-radius:2px;`)}>
              working{"\u2026"}
            </span>
          ) : null}
          {control.isError ? (
            <span style={css(`font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:${H.acc};border:1px solid ${H.acc}66;padding:1px 6px;border-radius:2px;`)}>
              {control.error instanceof Error ? control.error.message : "action failed"}
            </span>
          ) : null}
          {control.isSuccess ? (
            <span style={css(`font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:${H.mint};border:1px solid ${H.mint}66;padding:1px 6px;border-radius:2px;`)}>
              action applied
            </span>
          ) : null}
        </div>
      }
      right={
        <>
          <span style={css("font-size:11px;color:var(--text-faint);")}>{turnGroups.length} turns</span>
          <button type="button" onClick={onFavorite} title="toggle favorite" style={css(`flex:0 0 auto;background:transparent;border:0;padding:0;cursor:pointer;font-size:11px;color:${d?.is_favorite ? H.amber : "var(--text-faint)"};`)}>{d?.is_favorite ? "\u2605" : "\u2606"}</button>
          <span style={css(`font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:${H.mint};border:1px solid ${H.mint}66;padding:1px 6px;border-radius:2px;`)}>live tail</span>
        </>
      }
    >
      {turnGroups.length === 0 ? (
        <div style={css("padding:16px 18px;display:flex;flex-direction:column;gap:14px;")}>
          <div style={css("font-size:11px;line-height:1.6;color:var(--text-muted);")}>
            No turn-by-turn transcript was recorded for this investigation. Its summary and any ratified outcome are below; the records and finding layouts show what was captured.
          </div>
          <div style={kv}>
            <span style={kLabel}>case</span><span style={kVal}>{caseId}</span>
            <span style={kLabel}>target</span><span style={kVal}>{target}</span>
            <span style={kLabel}>kind</span><span style={kVal}>{d?.kind ?? "\u2014"}</span>
            <span style={kLabel}>status</span><span style={kVal}>{d?.status ?? "\u2014"}</span>
            <span style={kLabel}>strategy</span><span style={kVal}>{d?.strategy_family ?? "\u2014"}</span>
            <span style={kLabel}>branches</span><span style={kVal}>{branchCount}</span>
            <span style={kLabel}>hypotheses</span><span style={kVal}>{hypCount}</span>
            <span style={kLabel}>outcomes</span><span style={kVal}>{d?.outcome_count ?? 0}</span>
          </div>
          {d?.primary_outcome_verdict_head ? (
            <div style={css("border-top:1px solid var(--border-faint);padding-top:12px;display:flex;flex-direction:column;gap:8px;")}>
              <div style={css("display:flex;align-items:center;gap:8px;")}>
                <span style={css(`font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:${H.acc};border:1px solid ${H.acc}66;padding:1px 6px;border-radius:2px;`)}>{(d.primary_outcome_kind ?? "outcome").replace(/_/g, " ")}</span>
                {d.primary_outcome_confidence ? <span style={css(`font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:${H.amber};`)}>{d.primary_outcome_confidence}</span> : null}
              </div>
              <div style={css("font-family:var(--font-sans,system-ui);font-size:13px;line-height:1.5;color:var(--text-primary);")}>{d.primary_outcome_verdict_head.replace(/^#+\s*/, "")}</div>
            </div>
          ) : null}
        </div>
      ) : (
        <TurnList groups={turnGroups} openTurn={openTurn} setOpenTurn={setOpenTurn} resolvePersona={resolvePersona} showClock />
      )}
    </Panel>
  );
}
