import type { JSX } from "react";

import { readStr } from "../../../../api/parse";
import type { Branch, Hypothesis, Investigation, Message } from "../../../../api/types";
import { css } from "../../../css";
import { grid2, type PaneView } from "../layout";
import { Panel } from "../Panel";
import { turnProse } from "../parsers";
import { H, emptyNote } from "../theme";
import { PocPanelBody } from "./DraftPoc";
import { OutcomeReviews } from "./OutcomeReviews";

// 5 FINDING: FINDING (+ outcome reviews) + REACHABILITY + PROOF OF CONCEPT + CRASH.
export function FindingView({
  pv,
  invId,
  inv,
  branchList,
  caseId,
  outcomeMsg,
  topHyp,
  taintMsgs,
  pocMsg,
  crashMsg,
}: {
  pv: PaneView;
  invId: string | null;
  inv: Investigation | undefined;
  branchList: readonly Branch[];
  caseId: string;
  outcomeMsg: Message | undefined;
  topHyp: Hypothesis | undefined;
  taintMsgs: readonly Message[];
  pocMsg: Message | undefined;
  crashMsg: Message | undefined;
}): JSX.Element {
  const d = inv;
  // No severity field exists on the summary contract; deriving one from
  // investigation status would fabricate evidence. Show "unknown" unless
  // the primary outcome carries a confidence label.
  const sev = "unknown";
  const answer = outcomeMsg ? readStr(outcomeMsg.payload ?? {}, "answer") : null;
  const reasoning = outcomeMsg ? readStr(outcomeMsg.payload ?? {}, "reasoning") : null;
  // verdict_head often carries only a markdown section label ("### Scope"),
  // not a usable headline. Lead with the finding's first sentence instead and
  // keep the remainder as the body.
  const cleanVh = (d?.primary_outcome_verdict_head ?? "").replace(/^#+\s*/, "").trim();
  const vhUsable = cleanVh.length > 24 && !/^(scope|analysis|summary|finding|conclusion|background|verdict)$/i.test(cleanVh);
  let headline = "";
  let bodyText = answer ?? "";
  if (vhUsable) {
    headline = cleanVh;
  } else if (answer) {
    const sentence = answer.match(/^(.{24,200}?[.!?])(\s|$)/);
    headline = sentence ? sentence[1] : answer.slice(0, 160);
    bodyText = sentence ? answer.slice(sentence[1].length).trim() : "";
  } else {
    headline = topHyp?.claim ?? "";
  }
  const hasFinding = Boolean(answer || cleanVh || topHyp);
  return (
    <div style={grid2}>
      <Panel {...pv("finding")} title="finding" tag="F" signature="the artifact">
        {hasFinding ? (
          <div style={css("padding:13px;display:flex;flex-direction:column;gap:9px;")}>
            <div style={css("display:flex;align-items:center;gap:8px;flex-wrap:wrap;")}>
              <span style={css(`font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:${H.acc};border:1px solid ${H.acc}66;padding:1px 6px;border-radius:2px;`)}>{(d?.primary_outcome_kind ?? "direct_finding").replace(/_/g, " ")}</span>
              {d?.primary_outcome_confidence ? (
                <span style={css(`font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:${H.amber};`)}>{d.primary_outcome_confidence}</span>
              ) : (
                <span style={css(`font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:${H.lav};`)}>{sev}</span>
              )}
              {d?.primary_outcome_polarity ? (
                <span style={css("font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-faint);")}>{d.primary_outcome_polarity}</span>
              ) : null}
              <span style={css("flex:1;")} />
              <span style={css("font-size:11px;color:var(--text-faint);")}>{caseId}-F1</span>
            </div>
            <div style={css("font-family:var(--font-sans,system-ui);font-size:13px;line-height:1.5;color:var(--text-primary);")}>{headline || "\u2014"}</div>
            {bodyText ? (
              <div style={css("font-size:11.5px;line-height:1.55;color:var(--text-muted);")}>{bodyText}</div>
            ) : topHyp?.why_plausible ? (
              <div style={css("font-size:11.5px;line-height:1.5;color:var(--text-muted);")}>{topHyp.why_plausible}</div>
            ) : null}
            {reasoning ? (
              <div style={css("font-size:11px;line-height:1.5;color:var(--text-faint);border-top:1px solid var(--border-faint);padding-top:8px;")}>{reasoning}</div>
            ) : null}
            <div style={css("margin-top:4px;font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);")}>{(d?.status ?? "").toLowerCase() === "completed" ? `${d?.outcome_count ?? 1} outcome ratified` : "draft \u00b7 awaiting quorum"}</div>
          </div>
        ) : (
          <div style={emptyNote}>no finding drafted yet.</div>
        )}
        <div style={css("padding:0 13px 13px;")}>
          <OutcomeReviews invId={invId} branches={branchList} />
        </div>
      </Panel>
      <Panel {...pv("reach")} title="reachability" tag="E" signature="source to sink">
        {taintMsgs.length === 0 ? (
          <div style={emptyNote}>no reachability chain recorded.</div>
        ) : (
          taintMsgs.map((m) => {
            const p = m.payload ?? {};
            return (
              <div key={m.id} style={css("display:flex;align-items:center;gap:9px;padding:8px 11px;border-bottom:1px solid var(--border-faint);")}>
                <span style={css(`width:7px;height:7px;border-radius:50%;background:${H.amber};`)} />
                <span style={css("font-size:11px;color:var(--text-primary);")}>{readStr(p, "source") ?? "?"}</span>
                <span style={css("color:var(--text-faint);")}>{"\u2192"}</span>
                <span style={css("font-size:11px;color:var(--text-primary);")}>{readStr(p, "target") ?? "?"}</span>
              </div>
            );
          })
        )}
      </Panel>
      <Panel {...pv("poc")} title="proof of concept" tag="P" signature="reproduces the bug">
        <PocPanelBody inv={inv} pocMsg={pocMsg} />
      </Panel>
      <Panel {...pv("crash")} title="crash" tag="C" signature="sanitizer output">
        {crashMsg ? (
          <pre style={css("margin:0;padding:12px;font-family:var(--font-mono);font-size:11px;line-height:1.5;color:var(--text-primary);white-space:pre-wrap;word-break:break-word;")}>
            {turnProse(crashMsg)}
          </pre>
        ) : (
          <div style={emptyNote}>no crash artifact captured.</div>
        )}
      </Panel>
    </div>
  );
}
