import { useState, type JSX } from "react";

import type { Branch } from "../../../api/types";
import { css } from "../../css";
import { ActButton, PERSONA_VOICES, actionRow, branchLabel, fieldStyle } from "./actions";

// POST body shared by the VR /strategy-branches and malware /branches/spawn
// routes (both StrategyBranchSpawn contracts).
export interface SpawnBranchFields {
  strategy_family: string;
  persona_voice: string | null;
  rationale: string;
  parent_branch_id: string | null;
}

// Spawn a new strategy-tagged branch, fresh or inheriting an active parent.
// `onSpawn` runs the module's mutation and calls `done` on success.
export function SpawnBranchForm({
  listId,
  branchList,
  disabled,
  pending,
  onSpawn,
}: {
  listId: string;
  branchList: readonly Branch[];
  disabled: boolean;
  pending: boolean;
  onSpawn: (req: SpawnBranchFields, done: () => void) => void;
}): JSX.Element {
  const [family, setFamily] = useState("");
  const [voice, setVoice] = useState("");
  const [parent, setParent] = useState("");
  const [rationale, setRationale] = useState("");
  const families = [...new Set(branchList.map((b) => b.strategy_family).filter((f): f is string => Boolean(f)))];
  const parents = branchList.filter((b) => b.status.toLowerCase() === "active");

  const submit = (): void =>
    onSpawn(
      { strategy_family: family.trim(), persona_voice: voice || null, rationale: rationale.trim(), parent_branch_id: parent || null },
      () => {
        setFamily("");
        setRationale("");
      },
    );

  return (
    <div style={css("display:flex;flex-direction:column;gap:6px;padding:9px 11px;border:1px dashed var(--border-soft);border-radius:3px;")}>
      <div style={css("font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-muted);")}>spawn strategy branch</div>
      <div style={actionRow}>
        <input value={family} onChange={(e) => setFamily(e.target.value)} list={listId} maxLength={128} placeholder="strategy family" aria-label="strategy family" style={{ ...fieldStyle, flex: "1 1 200px" }} />
        <datalist id={listId}>
          {families.map((f) => <option key={f} value={f} />)}
        </datalist>
        <select value={voice} onChange={(e) => setVoice(e.target.value)} aria-label="spawn persona" style={fieldStyle}>
          <option value="">no persona</option>
          {PERSONA_VOICES.map((v) => <option key={v} value={v}>{v}</option>)}
        </select>
        <select value={parent} onChange={(e) => setParent(e.target.value)} aria-label="parent branch" style={fieldStyle}>
          <option value="">fresh start</option>
          {parents.map((b) => <option key={b.id} value={b.id}>inherit {branchLabel(b)}</option>)}
        </select>
      </div>
      <div style={actionRow}>
        <input value={rationale} onChange={(e) => setRationale(e.target.value)} maxLength={2048} placeholder="rationale (optional)" aria-label="spawn rationale" style={{ ...fieldStyle, flex: "1 1 240px" }} />
        <ActButton label="spawn" pendingLabel="spawning…" tone="accent" disabled={disabled || !family.trim()} pending={pending} onClick={submit} />
      </div>
    </div>
  );
}
