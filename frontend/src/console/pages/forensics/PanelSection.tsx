/** Read-only panel deliberation inside an investigation drill-down. */
import type { JSX } from "react";

import type { ForensicsPanelView } from "../../../api/forensics";
import { css } from "../../css";
import { DictPanel, H, Panel, StatusBadge, emptyNote } from "./panels";

const label = css("font-family:var(--font-mono);font-size:10px;text-transform:uppercase;letter-spacing:0.1em;color:var(--text-faint);");
const bodyText = css("font-family:var(--font-mono);font-size:11px;line-height:1.55;color:var(--text-primary);white-space:pre-wrap;overflow-wrap:anywhere;");
const card = css("padding:10px 12px;border:1px solid var(--border-soft);border-radius:2px;display:flex;flex-direction:column;gap:7px;");

export function PanelSection({ view }: { view: ForensicsPanelView }): JSX.Element {
  return (
    <Panel title="panel deliberation" tag={`${view.branches.length} branches · ${view.outcomes.length} outcomes`}>
      <div style={css("padding:10px 12px;display:flex;flex-direction:column;gap:12px;")}>
        <div style={css("display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;")}>
          {view.branches.map((branch) => (
            <div key={branch.id} style={card} data-testid={`panel-branch-${branch.persona_voice}`}>
              <div style={css("display:flex;align-items:center;gap:8px;")}>
                <strong style={bodyText}>{branch.persona_voice}</strong>
                <span style={css("flex:1;")} />
                <StatusBadge value={branch.status} />
              </div>
              <div style={label}>{branch.turn_count} turns · {branch.id.slice(0, 8)}</div>
              {branch.closed_reason ? <div style={label}>closed: {branch.closed_reason}</div> : null}
            </div>
          ))}
        </div>

        <section style={css("display:flex;flex-direction:column;gap:8px;")}>
          <div style={label}>answers and sibling review</div>
          {view.outcomes.length === 0 ? <div style={emptyNote}>no answer submitted yet.</div> : null}
          {view.outcomes.map((outcome) => (
            <article key={outcome.id} style={card} data-testid="panel-outcome">
              <div style={css("display:flex;align-items:center;gap:8px;")}>
                <strong style={bodyText}>{outcome.proposer_persona}</strong>
                <StatusBadge value={outcome.state} />
                <span style={label}>{outcome.confidence}</span>
                <span style={css("flex:1;")} />
                <span style={label}>{outcome.id.slice(0, 8)}</span>
              </div>
              <div style={bodyText}>{outcome.answer}</div>
              {Object.keys(outcome.provenance).length > 0 ? (
                <div><div style={label}>provenance</div><DictPanel data={outcome.provenance} initialOpen /></div>
              ) : null}
              {outcome.contributions.length > 0 ? (
                <div style={label}>
                  {outcome.contributions.map((contribution, index) => (
                    <div key={`${String(contribution.branch_id ?? "contribution")}-${index}`}>
                      contribution: {String(contribution.persona ?? "unknown")} · {String(contribution.confidence ?? "unknown")}
                    </div>
                  ))}
                </div>
              ) : null}
              {outcome.reviews.length > 0 ? (
                <div style={css("display:flex;flex-direction:column;gap:4px;")}>
                  {outcome.reviews.map((review) => (
                    <div key={review.reviewer_branch_id} style={bodyText}>
                      <span style={{ color: review.vote === "approve" ? H.mint : review.vote === "reject" ? H.danger : H.amber }}>
                        {review.reviewer_persona}: {review.vote}
                      </span>
                      {review.comment ? ` -- ${review.comment}` : ""}
                    </div>
                  ))}
                </div>
              ) : <div style={label}>awaiting sibling votes</div>}
            </article>
          ))}
        </section>

        <section style={css("display:flex;flex-direction:column;gap:8px;")}>
          <div style={label}>recent branch messages</div>
          {view.messages.length === 0 ? <div style={emptyNote}>no panel messages yet.</div> : null}
          {view.messages.map((message) => (
            <article key={message.id} style={card}>
              <div style={label}>
                {message.persona_voice} · turn {message.at_turn ?? "?"} · {message.payload_kind}
                {message.action ? ` · ${message.action}` : ""}
                {message.exit_code !== null ? ` · exit ${message.exit_code}` : ""}
              </div>
              {message.text ? <div style={bodyText}>{message.text}</div> : null}
              {message.command ? <pre style={bodyText}>{message.command}</pre> : null}
              {message.stdout ? <pre style={bodyText}>{message.stdout}</pre> : null}
              {message.stderr ? <pre style={{ ...bodyText, color: H.danger }}>{message.stderr}</pre> : null}
            </article>
          ))}
        </section>
      </div>
    </Panel>
  );
}
