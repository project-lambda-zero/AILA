import type { UseMutationResult } from "@tanstack/react-query";
import { useState, type JSX } from "react";

import { useLedgerDecision, type LedgerDecisionRequest, type LedgerDecisionResult } from "../../../../api/hooks";
import type { Branch, LedgerRow } from "../../../../api/types";
import { css } from "../../../css";
import { toast } from "../../../toast";
import { ActButton, actionRow, branchLabel, fieldStyle, formLabel, stopClick } from "../actions";
import type { PaneProps } from "../layout";
import { Panel } from "../Panel";
import { ledgerText } from "../parsers";
import { personaTone } from "../persona";
import { H, emptyNote } from "../theme";

// A record opened in the ORACLE layout's DETAIL pane.
export interface DetailItem {
  title: string;
  rows?: [string, string][];
  body?: string;
}

interface RequestVotes {
  approvers: string[];
  rejecters: string[];
}

// Fold decision rows into the distinct approving / rejecting branches per
// request id. Any approval ratifies (the oracle's default quorum of one).
function votesByRequest(decisionRows: readonly LedgerRow[]): Map<number, RequestVotes> {
  const out = new Map<number, RequestVotes>();

  for (const d of decisionRows) {
    if (d.decision_target === null || d.decision_approved === null) continue;
    const entry = out.get(d.decision_target) ?? { approvers: [], rejecters: [] };
    const list = d.decision_approved ? entry.approvers : entry.rejecters;
    const voter = d.author_branch_id ?? "";

    if (!list.includes(voter)) list.push(voter);
    out.set(d.decision_target, entry);
  }

  return out;
}

type DecisionMutation = UseMutationResult<LedgerDecisionResult, Error, LedgerDecisionRequest>;

// Operator vote cast as one of the investigation's branches; the request
// author is excluded because a branch cannot ratify its own request.
function DecisionForm({ request, branches, decide }: { request: LedgerRow; branches: readonly Branch[]; decide: DecisionMutation }): JSX.Element {
  const voters = branches.filter((b) => b.id !== request.author_branch_id);
  const [approver, setApprover] = useState("");
  const [reason, setReason] = useState("");
  const busy = decide.isPending && decide.variables?.requestId === request.id;
  const pendingApprove = busy ? decide.variables?.approve : undefined;

  const vote = (approve: boolean): void => {
    decide.mutate(
      { requestId: request.id, approver_branch_id: approver, approve, reason: reason.trim() },
      {
        onSuccess: (res) => {
          if (!approve) toast.success(`req #${request.id} rejected`);
          else if (res.ratified) toast.success(`req #${request.id} ratified; the hub applies it on its next visit`);
          else toast.info(`req #${request.id} approval recorded; quorum not reached`);
          setReason("");
        },
        onError: (err) => toast.fail(`decide req #${request.id}`, err),
      },
    );
  };

  return (
    <div onClick={stopClick} style={{ ...actionRow, marginTop: 6 }}>
      <span style={formLabel}>vote as</span>
      <select value={approver} onChange={(e) => setApprover(e.target.value)} aria-label="approver branch" style={fieldStyle}>
        <option value="">choose branch</option>
        {voters.map((b) => <option key={b.id} value={b.id}>{branchLabel(b)}</option>)}
      </select>
      <input value={reason} onChange={(e) => setReason(e.target.value)} maxLength={1024} placeholder="reason" aria-label="decision reason" style={{ ...fieldStyle, flex: "1 1 120px" }} />
      <ActButton label="ratify" tone="ok" disabled={!approver || decide.isPending} pending={pendingApprove === true} onClick={() => vote(true)} />
      <ActButton label="reject" tone="warn" disabled={!approver || decide.isPending} pending={pendingApprove === false} onClick={() => vote(false)} />
    </div>
  );
}

// ORACLE pane: the ledger's governance requests (kind=request rows) with
// their recorded votes and an operator ratify / reject control.
export function OraclePanel({
  pane,
  invId,
  requestRows,
  decisionRows,
  branchMap,
  onDetail,
}: {
  pane: PaneProps;
  invId: string | null;
  requestRows: readonly LedgerRow[];
  decisionRows: readonly LedgerRow[];
  branchMap: ReadonlyMap<string, Branch>;
  onDetail: (item: DetailItem) => void;
}): JSX.Element {
  const decide = useLedgerDecision(invId);
  const votes = votesByRequest(decisionRows);
  const branches = [...branchMap.values()];
  const voterName = (id: string): string => (branchMap.get(id)?.persona_voice ?? id.slice(0, 8)).toUpperCase();

  return (
    <Panel {...pane} title="oracle" tag="R" signature="ledger coordinator" right={<span style={css("font-size:11px;color:var(--text-faint);")}>{requestRows.length}</span>}>
      {requestRows.length === 0 ? (
        <div style={emptyNote}>no governance requests filed.</div>
      ) : (
        requestRows.map((r) => {
          const author = (branchMap.get(r.author_branch_id ?? "")?.persona_voice ?? "").toUpperCase();
          const intent = (r.intent ?? "request").replace(/_/g, " ").toUpperCase();
          const v = votes.get(r.id) ?? { approvers: [], rejecters: [] };
          const ratified = v.approvers.length > 0 || ["ratified", "applied"].includes((r.status ?? "").toLowerCase());
          const stateLabel = ratified ? "ratified" : v.rejecters.length > 0 ? "rejected" : (r.status ?? "open");

          return (
            <div key={r.id} onClick={() => onDetail({ title: `req #${r.id} · ${intent}`, body: ledgerText(r.text) })} style={css("padding:8px 11px;border-bottom:1px solid var(--border-faint);cursor:pointer;")}>
              <div style={css("display:flex;align-items:center;gap:8px;flex-wrap:wrap;")}>
                <span style={css("font-size:11px;color:var(--text-faint);")}>req #{r.id}</span>
                <span style={css(`font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:${H.lav};border:1px solid ${H.lav}66;padding:1px 6px;border-radius:2px;`)}>{intent}</span>
                <span style={css("flex:1;")} />
                <span style={css(`font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:${ratified ? H.mint : H.amber};`)}>{stateLabel}</span>
              </div>
              <div style={css("margin-top:4px;display:grid;grid-template-columns:auto 1fr;gap:2px 10px;font-size:11px;")}>
                {author ? (<><span style={css("color:var(--text-faint);")}>author</span><span style={css(`color:${personaTone(author)};`)}>{author}</span></>) : null}
                {r.target_capability ? (<><span style={css("color:var(--text-faint);")}>capability</span><span style={css("color:var(--text-primary);")}>{r.target_capability}</span></>) : null}
                {r.objective_key ? (<><span style={css("color:var(--text-faint);")}>objective</span><span style={css("color:var(--text-primary);")}>{r.objective_key}</span></>) : null}
                {v.approvers.length > 0 ? (<><span style={css("color:var(--text-faint);")}>approved by</span><span style={css(`color:${H.mint};`)}>{v.approvers.map(voterName).join(", ")}</span></>) : null}
                {v.rejecters.length > 0 ? (<><span style={css("color:var(--text-faint);")}>rejected by</span><span style={css(`color:${H.amber};`)}>{v.rejecters.map(voterName).join(", ")}</span></>) : null}
              </div>
              <div style={css("margin-top:4px;font-size:11px;color:var(--text-muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;")}>{ledgerText(r.text)}</div>
              {ratified ? null : <DecisionForm request={r} branches={branches} decide={decide} />}
            </div>
          );
        })
      )}
    </Panel>
  );
}
