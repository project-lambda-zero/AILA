import { useMemo, type JSX } from "react";

import { useSessionMessages, type DanteAction, type SessionMessage } from "../../api/sessions";
import { useChatSession } from "../chatSessionStore";
import { css } from "../css";
import type { WidgetProps } from "./types";

/**
 * DanteActionsWidget -- read-only view of pending dante proposals on the live
 * chat session. ChatConsole owns confirm/dismiss; this widget only surfaces
 * what has NOT yet been acted on so the operator can see backlog at a glance
 * without keeping the chat panel open. Every rendered row is a real proposal
 * off the persisted session transcript.
 */

const CAP = 12;

interface Pending {
  messageId: string;
  action: DanteAction;
  createdAt?: string;
}

function collectPending(messages: SessionMessage[], actedIds: string[]): Pending[] {
  const actedSet = new Set(actedIds);
  const out: Pending[] = [];
  for (const m of messages) {
    if (m.role !== "assistant") continue;
    if (actedSet.has(m.message_id)) continue;
    const actions = m.actions;
    if (!actions || actions.length === 0) continue;
    for (const a of actions) {
      out.push({ messageId: m.message_id, action: a, createdAt: m.created_at });
    }
  }
  // Newest first: session order is ascending by created_at; reverse so the
  // freshest proposal sits at the top of the widget body.
  out.reverse();
  return out.slice(0, CAP);
}

export default function DanteActionsWidget(_props: WidgetProps): JSX.Element {
  const sessionId = useChatSession((s) => s.sessionId);
  const actedIds = useChatSession((s) => s.actedMessageIds);
  const q = useSessionMessages(sessionId);

  const pending = useMemo(
    () => collectPending(q.data?.items ?? [], actedIds),
    [q.data?.items, actedIds],
  );

  const rootStyle = css(
    "flex:1;min-height:0;display:flex;flex-direction:column;overflow:auto;padding:10px 12px;background:var(--surface-card);font-family:var(--font-mono);color:var(--text-primary);",
  );
  const labelStyle = css(
    "flex:0 0 auto;font-size:9px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-muted);padding-bottom:8px;border-bottom:1px solid var(--border-faint);margin-bottom:8px;",
  );
  const messageStyle = css(
    "font-size:11px;color:var(--text-muted);letter-spacing:0.02em;padding:6px 2px;",
  );
  const listStyle = css("display:flex;flex-direction:column;gap:6px;flex:1;min-height:0;");
  const rowStyle = css(
    "display:flex;flex-direction:column;gap:3px;padding:7px 8px;border:1px solid var(--border-soft);border-radius:2px;background:var(--surface-sunk);",
  );
  const rowHeadStyle = css("display:flex;align-items:center;gap:8px;");
  const labelTextStyle = css(
    "flex:1;min-width:0;font-size:11px;color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;",
  );
  const summaryStyle = css(
    "font-size:10px;color:var(--text-muted);letter-spacing:0.02em;line-height:1.35;",
  );
  const footerStyle = css(
    "flex:0 0 auto;font-size:9px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);padding-top:8px;margin-top:8px;border-top:1px solid var(--border-faint);",
  );

  const TONE_BY_KIND: Record<DanteAction["kind"], string> = {
    open_wizard: "var(--status-info)",
    enqueue_scan: "var(--accent)",
    create_tag: "var(--status-ok)",
    delete_tag: "var(--status-warn)",
    steer_investigation: "var(--accent)",
  };
  const LABEL_BY_KIND: Record<DanteAction["kind"], string> = {
    open_wizard: "wizard",
    enqueue_scan: "scan",
    create_tag: "tag+",
    delete_tag: "tag-",
    steer_investigation: "steer",
  };
  function pillStyle(kind: DanteAction["kind"]) {
    const tone = TONE_BY_KIND[kind];
    return css(
      `flex:0 0 auto;font-size:9px;letter-spacing:0.1em;text-transform:uppercase;padding:2px 6px;border:1px solid ${tone};color:${tone};border-radius:2px;`,
    );
  }

  let body: JSX.Element;
  if (!sessionId) {
    body = <div style={messageStyle}>no active chat session</div>;
  } else if (q.isLoading) {
    body = <div style={messageStyle}>loading...</div>;
  } else if (q.isError) {
    body = <div style={messageStyle}>failed to load session messages</div>;
  } else if (pending.length === 0) {
    body = <div style={messageStyle}>no pending proposals</div>;
  } else {
    body = (
      <div style={listStyle}>
        {pending.map((p, idx) => (
          <div key={`${p.messageId}:${idx}`} style={rowStyle}>
            <div style={rowHeadStyle}>
              <span style={pillStyle(p.action.kind)}>{LABEL_BY_KIND[p.action.kind]}</span>
              <span style={labelTextStyle}>{p.action.label}</span>
            </div>
            {p.action.summary ? <div style={summaryStyle}>{p.action.summary}</div> : null}
          </div>
        ))}
      </div>
    );
  }

  return (
    <div style={rootStyle}>
      <div style={labelStyle}>pending proposals</div>
      {body}
      <div style={footerStyle}>confirm in chat</div>
    </div>
  );
}
