import type { UseMutationResult } from "@tanstack/react-query";
import { useState, type JSX } from "react";

import { useSpawnStrategyBranch, type BranchOpRequest } from "../../../../api/hooks";
import type { Branch } from "../../../../api/types";
import { css } from "../../../css";
import { toast } from "../../../toast";
import { ActButton, ConfirmButton, PERSONA_VOICES, actionRow, branchLabel, fieldStyle, formLabel } from "../actions";
import { SpawnBranchForm } from "../SpawnBranchForm";

type BranchOp = BranchOpRequest["op"];

export type BranchOpMutation = UseMutationResult<unknown, Error, BranchOpRequest>;

const OP_DONE = {
  fork: "branch forked",
  merge: "branches merged",
  promote: "branch promoted; active siblings abandoned",
  abandon: "branch abandoned",
  pause: "branch paused",
  resume: "branch resumed",
} as const satisfies Record<BranchOp, string>;

// Per-branch operator controls. Server-side preconditions: fork, merge,
// promote and pause need an ACTIVE branch; resume needs a PAUSED one.
export function BranchActions({
  branch,
  branchList,
  op,
}: {
  branch: Branch;
  branchList: readonly Branch[];
  op: BranchOpMutation;
}): JSX.Element | null {
  const [form, setForm] = useState<"fork" | "merge" | null>(null);
  const [reason, setReason] = useState("");
  const [voice, setVoice] = useState("");
  const [atTurn, setAtTurn] = useState("");
  const [other, setOther] = useState("");
  const status = branch.status.toLowerCase();
  const active = status === "active";
  const paused = status === "paused";

  if (!active && !paused) return null;

  const busy = op.isPending && op.variables?.branchId === branch.id;
  const pendingOp = busy ? op.variables?.op : undefined;
  const mergeTargets = branchList.filter((b) => b.id !== branch.id && b.status.toLowerCase() === "active");

  const run = (req: BranchOpRequest): void => {
    op.mutate(req, {
      onSuccess: () => {
        toast.success(OP_DONE[req.op]);
        setForm(null);
        setReason("");
      },
      onError: (err) => toast.fail(`${req.op} branch`, err),
    });
  };

  const simple = (name: "promote" | "abandon" | "pause" | "resume"): void => run({ op: name, branchId: branch.id, reason: reason.trim() });
  const parsedTurn = atTurn.trim() === "" ? null : Number.parseInt(atTurn, 10);
  const turnValid = parsedTurn === null || (Number.isInteger(parsedTurn) && parsedTurn >= 0);

  return (
    <div style={css("display:flex;flex-direction:column;gap:6px;")}>
      <div style={actionRow}>
        {active ? (
          <>
            <ActButton label="fork" tone={form === "fork" ? "accent" : "neutral"} disabled={op.isPending} onClick={() => setForm(form === "fork" ? null : "fork")} />
            <ActButton label="merge" tone={form === "merge" ? "accent" : "neutral"} disabled={op.isPending || mergeTargets.length === 0} title={mergeTargets.length === 0 ? "needs another active branch" : undefined} onClick={() => setForm(form === "merge" ? null : "merge")} />
            <ConfirmButton label="promote" confirmLabel="confirm promote" tone="ok" disabled={op.isPending} pending={pendingOp === "promote"} onConfirm={() => simple("promote")} />
            <ActButton label="pause" disabled={op.isPending} pending={pendingOp === "pause"} onClick={() => simple("pause")} />
          </>
        ) : (
          <ActButton label="resume" tone="ok" disabled={op.isPending} pending={pendingOp === "resume"} onClick={() => simple("resume")} />
        )}
        <ConfirmButton label="abandon" confirmLabel="confirm abandon" disabled={op.isPending} pending={pendingOp === "abandon"} onConfirm={() => simple("abandon")} />
        <input value={reason} onChange={(e) => setReason(e.target.value)} maxLength={1024} placeholder="reason (optional)" aria-label="operation reason" style={{ ...fieldStyle, flex: "1 1 160px" }} />
      </div>
      {form === "fork" ? (
        <div style={actionRow}>
          <span style={formLabel}>fork as</span>
          <select value={voice} onChange={(e) => setVoice(e.target.value)} aria-label="fork persona" style={fieldStyle}>
            <option value="">inherit voice</option>
            {PERSONA_VOICES.map((v) => <option key={v} value={v}>{v}</option>)}
          </select>
          <span style={formLabel}>at turn</span>
          <input value={atTurn} onChange={(e) => setAtTurn(e.target.value)} inputMode="numeric" placeholder="latest" aria-label="fork at turn" style={{ ...fieldStyle, width: 80 }} />
          <ActButton
            label="fork branch"
            tone="accent"
            disabled={!turnValid}
            pending={pendingOp === "fork"}
            onClick={() => run({ op: "fork", branchId: branch.id, reason: reason.trim(), persona_voice: voice || null, at_turn: parsedTurn })}
          />
        </div>
      ) : null}
      {form === "merge" ? (
        <div style={actionRow}>
          <span style={formLabel}>merge with</span>
          <select value={other} onChange={(e) => setOther(e.target.value)} aria-label="merge target branch" style={fieldStyle}>
            <option value="">choose branch</option>
            {mergeTargets.map((b) => <option key={b.id} value={b.id}>{branchLabel(b)}</option>)}
          </select>
          <ConfirmButton
            label="merge branches"
            confirmLabel="confirm merge"
            disabled={!other}
            pending={pendingOp === "merge"}
            onConfirm={() => run({ op: "merge", branchId: branch.id, reason: reason.trim(), other_branch_id: other })}
          />
        </div>
      ) : null}
    </div>
  );
}

// Spawn a new strategy-tagged branch, fresh or inheriting a parent's case state.
export function StrategySpawnForm({ invId, branchList }: { invId: string | null; branchList: readonly Branch[] }): JSX.Element {
  const spawn = useSpawnStrategyBranch(invId);

  return (
    <SpawnBranchForm
      listId="vr-strategy-families"
      branchList={branchList}
      disabled={!invId}
      pending={spawn.isPending}
      onSpawn={(req, done) =>
        spawn.mutate(req, {
          onSuccess: (res) => {
            toast.success(`spawned ${res.strategy_family} branch ${res.new_branch_id.slice(0, 8)}`);
            done();
          },
          onError: (err) => toast.fail("spawn strategy branch", err),
        })
      }
    />
  );
}
