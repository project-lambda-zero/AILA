import { useState, type JSX } from "react";

import type { Branch, OutcomeReview } from "../../../api/types";
import { css } from "../../css";
import { ActButton, actionRow, branchLabel, fieldStyle, formLabel, stopClick } from "./actions";
import { clockTime } from "./parsers";
import { personaTone } from "./persona";
import { H } from "./theme";

export type ReviewVote = "approve" | "reject" | "request_edit" | "abstain" | "not_ready";

const VOTE_TONE = {
  approve: H.mint,
  reject: H.acc,
  request_edit: H.amber,
  abstain: H.lav,
  not_ready: H.cream,
} as const satisfies Record<ReviewVote, string>;

function isReviewVote(v: string): v is ReviewVote {
  return Object.hasOwn(VOTE_TONE, v);
}

export interface ReviewSubmit {
  reviewer_branch_id: string;
  vote: ReviewVote;
  comment: string;
}

// Sibling reviews on one outcome plus an operator vote cast on behalf of a
// chosen branch (the backend records it as that branch's review, replacing
// any prior vote from the same branch).
export function ReviewThread({
  reviews,
  loading,
  branches,
  votes,
  pending,
  onSubmit,
}: {
  reviews: readonly OutcomeReview[];
  loading: boolean;
  branches: readonly Branch[];
  votes: readonly ReviewVote[];
  pending: boolean;
  onSubmit: (req: ReviewSubmit, done: () => void) => void;
}): JSX.Element {
  const [reviewer, setReviewer] = useState("");
  const [vote, setVote] = useState<ReviewVote>(votes[0] ?? "approve");
  const [comment, setComment] = useState("");

  return (
    <div onClick={stopClick} style={css("display:flex;flex-direction:column;gap:6px;")}>
      {loading ? (
        <div style={css("font-size:11px;color:var(--text-faint);")}>loading reviews…</div>
      ) : reviews.length === 0 ? (
        <div style={css("font-size:11px;color:var(--text-faint);")}>no reviews cast yet.</div>
      ) : (
        reviews.map((r) => {
          const persona = r.reviewer_persona.toUpperCase();
          const tone = isReviewVote(r.vote) ? VOTE_TONE[r.vote] : "var(--text-muted)";

          return (
            <div key={r.id} style={css("display:flex;flex-direction:column;gap:2px;padding:5px 8px;border-left:2px solid var(--border-soft);")}>
              <div style={css("display:flex;align-items:center;gap:8px;font-size:11px;")}>
                <span style={css(`font-weight:700;letter-spacing:0.06em;color:${personaTone(persona)};`)}>{persona}</span>
                <span style={css(`letter-spacing:0.08em;text-transform:uppercase;color:${tone};`)}>{r.vote.replace(/_/g, " ")}</span>
                <span style={css("flex:1;")} />
                {r.created_at ? <span style={css("color:var(--text-faint);")}>{clockTime(r.created_at)}</span> : null}
              </div>
              {r.comment ? <div style={css("font-size:11px;line-height:1.5;color:var(--text-muted);white-space:pre-wrap;")}>{r.comment}</div> : null}
            </div>
          );
        })
      )}
      <div style={actionRow}>
        <span style={formLabel}>vote as</span>
        <select value={reviewer} onChange={(e) => setReviewer(e.target.value)} aria-label="reviewer branch" style={fieldStyle}>
          <option value="">choose branch</option>
          {branches.map((b) => <option key={b.id} value={b.id}>{branchLabel(b)}</option>)}
        </select>
        <select value={vote} onChange={(e) => { const next = e.target.value;

 if (isReviewVote(next)) setVote(next); }} aria-label="review vote" style={fieldStyle}>
          {votes.map((v) => <option key={v} value={v}>{v.replace(/_/g, " ")}</option>)}
        </select>
      </div>
      <div style={actionRow}>
        <input value={comment} onChange={(e) => setComment(e.target.value)} maxLength={4096} placeholder={vote === "not_ready" ? "stated blocker" : "comment"} aria-label="review comment" style={{ ...fieldStyle, flex: "1 1 200px" }} />
        <ActButton
          label="cast vote"
          pendingLabel="casting…"
          tone="accent"
          disabled={!reviewer}
          pending={pending}
          onClick={() => onSubmit({ reviewer_branch_id: reviewer, vote, comment: comment.trim() }, () => setComment(""))}
        />
      </div>
    </div>
  );
}
