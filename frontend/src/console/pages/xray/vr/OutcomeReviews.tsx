import { useState, type JSX } from "react";

import { useCreateVrOutcomeReview, useVrOutcomeReviews, useVrOutcomes } from "../../../../api/hooks";
import type { Branch, VrOutcome } from "../../../../api/types";
import { css } from "../../../css";
import { toast } from "../../../toast";
import { clockTime } from "../parsers";
import { ReviewThread, type ReviewVote } from "../reviews";
import { H } from "../theme";

const VR_VOTES: readonly ReviewVote[] = ["approve", "reject", "request_edit", "abstain", "not_ready"];

type OutcomeState = "draft" | "approved" | "dispatched" | "rejected";

const STATE_TONE = {
  draft: H.amber,
  approved: H.mint,
  dispatched: H.mint,
  rejected: H.acc,
} as const satisfies Record<OutcomeState, string>;

function isOutcomeState(s: string): s is OutcomeState {
  return Object.hasOwn(STATE_TONE, s);
}

function OutcomeThread({ invId, outcome, branches }: { invId: string | null; outcome: VrOutcome; branches: readonly Branch[] }): JSX.Element {
  const reviews = useVrOutcomeReviews(invId, outcome.id);
  const create = useCreateVrOutcomeReview(invId);

  return (
    <ReviewThread
      reviews={reviews.data ?? []}
      loading={reviews.isLoading}
      branches={branches}
      votes={VR_VOTES}
      pending={create.isPending}
      onSubmit={(req, done) =>
        create.mutate(
          { outcomeId: outcome.id, ...req },
          {
            onSuccess: () => {
              toast.success(`${req.vote.replace(/_/g, " ")} vote recorded`);
              done();
            },
            onError: (err) => toast.fail("cast review vote", err),
          },
        )
      }
    />
  );
}

// Every outcome of the investigation with its quorum tally; expanding one
// shows the sibling reviews and the operator vote form.
export function OutcomeReviews({ invId, branches }: { invId: string | null; branches: readonly Branch[] }): JSX.Element {
  const outcomes = useVrOutcomes(invId);
  const [openId, setOpenId] = useState<string | null>(null);
  const list = outcomes.data ?? [];

  return (
    <div style={css("display:flex;flex-direction:column;gap:6px;border-top:1px solid var(--border-faint);padding-top:9px;")}>
      <div style={css("font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-muted);")}>outcomes · sibling review ({list.length})</div>
      {outcomes.isLoading ? <div style={css("font-size:11px;color:var(--text-faint);")}>loading outcomes…</div> : null}
      {outcomes.isError ? <div style={css(`font-size:11px;color:${H.acc};`)}>outcomes unavailable</div> : null}
      {list.map((o) => {
        const open = openId === o.id;
        const tone = isOutcomeState(o.state) ? STATE_TONE[o.state] : H.lav;

        return (
          <div key={o.id} style={css("border:1px solid var(--border-soft);border-radius:3px;")}>
            <button
              type="button"
              onClick={() => setOpenId(open ? null : o.id)}
              aria-expanded={open}
              style={css("width:100%;min-height:28px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:5px 9px;background:transparent;border:0;cursor:pointer;font-family:var(--font-mono);font-size:11px;color:var(--text-primary);text-align:left;")}
            >
              <span style={css(`letter-spacing:0.08em;text-transform:uppercase;color:${H.acc};`)}>{o.outcome_kind.replace(/_/g, " ")}</span>
              <span style={css(`letter-spacing:0.08em;text-transform:uppercase;color:${tone};`)}>{o.state}</span>
              <span style={css("color:var(--text-faint);")}>{o.confidence}</span>
              <span style={css("flex:1;")} />
              <span style={css("color:var(--text-muted);")}>{`✓${o.approve_count} ✗${o.reject_count} ~${o.request_edit_count} ·${o.abstain_count}${o.quorum_k ? ` / k=${o.quorum_k}` : ""}`}</span>
              <span style={css("color:var(--text-faint);")}>{clockTime(o.created_at)}</span>
            </button>
            {open ? (
              <div style={css("padding:6px 9px 9px;border-top:1px solid var(--border-faint);")}>
                <OutcomeThread invId={invId} outcome={o} branches={branches} />
              </div>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}
