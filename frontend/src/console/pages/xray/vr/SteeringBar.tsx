import { useState, type ChangeEvent, type JSX, type KeyboardEvent } from "react";

import { css } from "../../../css";
import { H } from "../theme";

const STEER_INTENTS = ["steering", "correction", "dismissal", "question", "outcome_selection", "branch_command"] as const;

// The operator message mutation (POST /vr/investigations/{id}/messages).
export interface SteerPost {
  mutate: (arg: { text: string; intent: string }, options: { onSuccess: () => void }) => void;
  isPending: boolean;
}

// Steering composer: context the engine sees verbatim on its next turn.
export function SteeringBar({ invId, post }: { invId: string | null; post: SteerPost }): JSX.Element {
  const [steer, setSteer] = useState("");
  const [steerIntent, setSteerIntent] = useState("steering");
  const doSteer = (): void => {
    const text = steer.trim();
    if (!text || !invId || post.isPending) return;
    post.mutate({ text, intent: steerIntent }, { onSuccess: () => setSteer("") });
  };
  const onSteerKey = (e: KeyboardEvent<HTMLInputElement>): void => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      doSteer();
    }
  };
  return (
    <div style={css("flex:0 0 auto;display:flex;align-items:center;gap:9px;padding:8px 14px;border-top:1px solid var(--border-soft);background:color-mix(in srgb,var(--surface-sunk) 60%,transparent);")}>
      <span style={css(`font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:${H.acc};font-weight:700;`)}>steering</span>
      <input value={steer} onChange={(e: ChangeEvent<HTMLInputElement>) => setSteer(e.target.value)} onKeyDown={onSteerKey} placeholder="context the engine sees verbatim next turn" disabled={!invId} style={css("flex:1;min-width:0;background:transparent;border:0;outline:none;color:var(--text-primary);font-family:var(--font-mono);font-size:12px;")} />
      <select value={steerIntent} onChange={(e: ChangeEvent<HTMLSelectElement>) => setSteerIntent(e.target.value)} disabled={!invId} title="operator intent" style={css("flex:0 0 auto;height:28px;background:var(--surface-chrome);border:1px solid var(--border-soft);border-radius:2px;color:var(--text-muted);font-family:var(--font-mono);font-size:11px;padding:0 6px;cursor:pointer;")}>
        {STEER_INTENTS.map((o) => (
          <option key={o} value={o}>{o}</option>
        ))}
      </select>
      <button type="button" onClick={doSteer} disabled={!invId || steer.trim().length === 0 || post.isPending} style={css(`flex:0 0 auto;padding:0 14px;height:28px;font-family:var(--font-mono);font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-on-accent);background:var(--accent);border:1px solid var(--accent);border-radius:2px;cursor:pointer;${!invId || steer.trim().length === 0 || post.isPending ? "opacity:0.45;cursor:not-allowed;" : ""}`)}>send</button>
    </div>
  );
}
