import {
  useEffect,
  useRef,
  useState,
  type ChangeEvent,
  type CSSProperties,
  type JSX,
  type KeyboardEvent,
} from "react";

import {
  useCreateSession,
  usePostSessionMessage,
  useSessionMessages,
  useSessions,
  type DanteAction,
  type SessionMessage,
} from "../api/sessions";
import { useCreateVocabEntry, useDeleteVocabEntry } from "../api/systems";
import { useSubmitVulnScan } from "../api/vulnerability";
import type { ChatConsoleProps } from "./contract";
import { useChatSession } from "./chatSessionStore";
import { css } from "./css";
import { shortCaseId } from "./ids";
import { primaryWizardIdForModule, wizardsForModule } from "./wizards";

/*
 * ChatConsole -- center panel of the console scene, ported verbatim from
 * `AILA Console.dc.html` (see renderVals: thread / suggestions / panelStyle
 * / panelBarStyle / threadStyle / composerWrapStyle / composerStyle /
 * promptStyle / sendStyle / modeBtnStyle / chip). Advanced + bound
 * investigation streams real messages from useMessages; basic (or unbound)
 * mode shows the mock's boot copy only -- no fabricated data rows.
 */

// Mock's T palette. Standalone lookups map to CSS vars so a theme swap
// carries; alpha-suffixed uses need literal hex because `var(--x)66` is
// invalid CSS (the color-mix trick blows up the copied strings).
const T = {
  pri: "var(--text-primary)",
  mut: "var(--text-muted)",
  fnt: "var(--text-faint)",
  acc: "var(--accent)",
  ok: "var(--status-ok)",
  info: "var(--status-info)",
  warn: "var(--status-warn)",
  sig: "var(--status-signal)",
  onAcc: "var(--text-on-accent)",
} as const;

const H = {
  pri: "#ffd7af",
  mut: "#af8c6c",
  fnt: "#6b563f",
  acc: "#ff5f87",
  ok: "#97dbbe",
  info: "#af87d7",
  warn: "#ffb85f",
  sig: "#f0a8c7",
} as const;

/* ------------------------------ tiny helpers ------------------------------ */

type ChipTone = "info" | "ok" | "warn" | "acc" | "sig" | "mut";

// Mock's chip() -- exact inline style, tone drives border/color/bg via a
// literal hex plus alpha-suffix (see comment on H above).
function chipStyle(tone: ChipTone): CSSProperties {
  const c = H[tone];
  return css(
    `display:inline-flex;align-items:center;padding:2px 7px;font-size:9px;letter-spacing:0.06em;text-transform:uppercase;white-space:nowrap;border:1px solid ${c}66;color:${c};background:${c}14;border-radius:2px;`,
  );
}

/* -------------------------------- constants ------------------------------- */

// Prompt chips map to real dante capabilities: the interview/advise voice
// and the four proposal kinds (open_wizard / enqueue_scan / create_tag /
// delete_tag). No decorative options; anything a chip suggests dante can
// actually do.
const ADV_SUGGESTIONS: readonly string[] = [
  "what can you do?",
  "open a vr investigation on this target",
  "scan this system for kev cves",
];

// "+ new investigation" is rendered separately as an accent action (it opens
// the intake wizard, not a prompt). These are the plain prompt chips.
const BASIC_SUGGESTIONS: readonly string[] = [
  "what can you do?",
  "open a vr investigation",
  "scan a system for kev cves",
  "add a tag to the vocabulary",
];

/* --------------------------- message row rendering ------------------------ */

interface RowProps {
  who: "you" | "dante";
  meta: string;
  body: string;
  chips: Array<{ label: string; tone: ChipTone }>;
  card: { id: string; conf: string; body: string } | null;
  actions?: DanteAction[];
  messageId?: string;
}

interface RowRenderCtx {
  acted: Set<string>;
  onAction: (a: DanteAction, messageId?: string) => void;
  onDismiss: (messageId?: string) => void;
}

function renderRow(key: string, r: RowProps, ctx?: RowRenderCtx): JSX.Element {
  const you = r.who === "you";

  const rowStyle = css(
    `display:flex;flex-direction:column;align-items:${you ? "flex-end" : "flex-start"};animation:acin .32s cubic-bezier(0.22,1,0.36,1) both;`,
  );
  const metaStyle = css(
    `display:flex;align-items:center;gap:8px;margin-bottom:4px;${you ? "flex-direction:row-reverse;" : ""}`,
  );
  const tagStyle = css(
    `font-size:9px;letter-spacing:0.14em;text-transform:uppercase;font-weight:700;color:${you ? T.mut : T.acc};`,
  );
  const bubbleStyle = css(
    `max-width:min(680px,86%);padding:10px 13px;font-family:var(--font-sans,system-ui);font-size:13px;line-height:1.5;text-wrap:pretty;border:1px solid ${you ? "var(--border-soft)" : `${H.acc}4d`};background:${you ? "var(--surface-card)" : "color-mix(in srgb,var(--accent) 7%,var(--surface-card))"};color:${you ? T.mut : T.pri};border-radius:3px;${you ? "" : "box-shadow:0 0 22px rgba(255,95,135,0.07);"}`,
  );
  const metaStampStyle = css(
    "color:var(--text-faint);font-size:9px;letter-spacing:0.08em;",
  );
  const cardStyle = css(
    `max-width:min(680px,86%);margin-top:8px;padding:9px 11px;border:1px solid ${H.info}59;background:var(--surface-sunk);border-left:2px solid ${T.info};border-radius:2px;`,
  );
  const cardBadgeStyle = css(
    `display:inline-flex;align-items:center;padding:1px 6px;font-size:9px;letter-spacing:0.1em;text-transform:uppercase;border:1px solid ${T.info};color:${T.info};background:${H.info}1a;border-radius:2px;`,
  );
  const cardIdStyle = css(
    "font-size:9.5px;color:var(--text-faint);letter-spacing:0.06em;",
  );
  const cardConfStyle = css(
    `font-size:9.5px;color:${T.mut};letter-spacing:0.04em;`,
  );
  const cardBodyStyle = css(
    "margin-top:6px;font-family:var(--font-sans,system-ui);font-size:12px;line-height:1.4;color:var(--text-primary);text-wrap:pretty;",
  );
  const chipsRowStyle = css(
    `display:flex;flex-wrap:wrap;gap:5px;margin-top:7px;${you ? "justify-content:flex-end;" : ""}`,
  );

  const actionsRowStyle = css(
    "display:flex;flex-wrap:wrap;gap:6px;margin-top:8px;align-items:center;",
  );
  const proposalSummaryStyle = css(
    `flex:1 1 100%;font-size:11px;line-height:1.4;color:${T.mut};margin-bottom:2px;`,
  );
  const actionBtnBase =
    `padding:5px 11px;font-family:var(--font-mono);font-size:10px;letter-spacing:0.06em;text-transform:uppercase;border-radius:2px;cursor:pointer;white-space:nowrap;`;
  const confirmBtnStyle = css(
    `${actionBtnBase}color:var(--text-on-accent);background:var(--accent);border:1px solid var(--accent);box-shadow:0 0 12px rgba(255,95,135,0.28);`,
  );
  const dismissBtnStyle = css(
    `${actionBtnBase}color:${T.mut};background:var(--surface-card);border:1px solid var(--border-soft);`,
  );
  const inertBtnStyle = css(
    `${actionBtnBase}color:${T.fnt};background:var(--surface-sunk);border:1px solid var(--border-soft);cursor:default;opacity:0.55;`,
  );
  const wizardBtnStyle = css(
    `${actionBtnBase}color:var(--accent);background:color-mix(in srgb,var(--accent) 12%,transparent);border:1px solid ${H.acc}66;`,
  );

  const actions = r.actions ?? [];
  const rowIsDante = r.who === "dante";
  const isActed = Boolean(r.messageId && ctx?.acted.has(r.messageId));

  return (
    <div key={key} style={rowStyle}>
      <div style={metaStyle}>
        <span style={tagStyle}>{r.who}</span>
        <span style={metaStampStyle}>{r.meta}</span>
      </div>
      <div style={bubbleStyle}>{r.body}</div>
      {r.card ? (
        <div style={cardStyle}>
          <div style={css("display:flex;align-items:center;gap:8px;")}>
            <span style={cardBadgeStyle}>hypothesis</span>
            <span style={cardIdStyle}>{r.card.id}</span>
            <span style={css("flex:1;")} />
            <span style={cardConfStyle}>{r.card.conf}</span>
          </div>
          <div style={cardBodyStyle}>{r.card.body}</div>
        </div>
      ) : null}
      {r.chips.length > 0 ? (
        <div style={chipsRowStyle}>
          {r.chips.map((c, i) => (
            <span key={`${c.label}-${i}`} style={chipStyle(c.tone)}>
              {c.label}
            </span>
          ))}
        </div>
      ) : null}
      {rowIsDante && actions.length > 0 && ctx ? (
        <div style={actionsRowStyle}>
          {actions.map((a, i) => {
            const aKey = `${r.messageId ?? key}-a${i}`;
            if (a.kind === "open_wizard") {
              const label = a.label || `open ${a.module_id ?? "module"} wizard`;
              return (
                <button
                  key={aKey}
                  type="button"
                  onClick={() => ctx.onAction(a, r.messageId)}
                  style={wizardBtnStyle}
                >
                  {label}
                </button>
              );
            }
            // Mutation kinds render a summary + confirm/dismiss pair. Once
            // acted, the buttons flip inert (Set<messageId> in the root
            // tracks this) so a proposal can be run at most once.
            return (
              <div key={aKey} style={actionsRowStyle}>
                {a.summary ? <div style={proposalSummaryStyle}>{a.summary}</div> : null}
                <button
                  type="button"
                  disabled={isActed}
                  onClick={() => ctx.onAction(a, r.messageId)}
                  style={isActed ? inertBtnStyle : confirmBtnStyle}
                >
                  {isActed ? "done" : (a.label || "confirm")}
                </button>
                <button
                  type="button"
                  disabled={isActed}
                  onClick={() => ctx.onDismiss(r.messageId)}
                  style={isActed ? inertBtnStyle : dismissBtnStyle}
                >
                  dismiss
                </button>
              </div>
            );
          })}
        </div>
      ) : null}
    </div>
  );
}

// Bind one live Message to a RowProps -- no fabrication: every value
function bindSessionMessage(m: SessionMessage): RowProps {
  const you = m.role === "user";
  const chips: Array<{ label: string; tone: ChipTone }> = [];
  if (m.role === "assistant") chips.push({ label: "dante", tone: "acc" });

  const meta = m.created_at ? new Date(m.created_at).toLocaleTimeString() : "";
  return {
    who: you ? "you" : "dante",
    meta,
    body: m.content,
    chips,
    card: null,
    actions: m.actions ?? [],
    messageId: m.message_id,
  };
}

/* ---------------------------------- root ---------------------------------- */

export default function ChatConsole(props: ChatConsoleProps): JSX.Element {
  const { mode, moduleId, investigationId, onToggleMode, onOpenIntake, onOpenWizard, onOpenXray, dockOpen } =
    props;
  const adv = mode === "advanced";

  const [draft, setDraft] = useState<string>("");
  // Chat's `+ open wizard \u25be` picker toggle. Closed by default; closes on
  // selection or when the operator clicks the button again.
  const [pickerOpen, setPickerOpen] = useState<boolean>(false);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  // Message ids for which the operator has already confirmed or dismissed a
  // dante proposal. Prevents double-firing a mutation from the same row.
  const [acted, setActed] = useState<Set<string>>(() => new Set<string>());
  const threadRef = useRef<HTMLDivElement | null>(null);
  const seenLen = useRef<number | null>(null);

  const sessionsQ = useSessions();
  const createSession = useCreateSession();

  useEffect(() => {
    if (!activeSessionId && sessionsQ.data?.items?.[0]) {
      setActiveSessionId(sessionsQ.data.items[0].session_id);
    }
  }, [activeSessionId, sessionsQ.data?.items]);

  const chatSessionId = activeSessionId;
  const sessionMessagesQ = useSessionMessages(chatSessionId);
  const postSessionMessage = usePostSessionMessage(chatSessionId);
  const sessionMessages: SessionMessage[] = sessionMessagesQ.data?.items ?? [];

  // Mutation hooks dante's proposals invoke on operator confirm. Bound here
  // (Rules of Hooks) and dispatched by kind inside onAction.
  const submitVulnScan = useSubmitVulnScan();
  const createVocab = useCreateVocabEntry();
  const deleteVocab = useDeleteVocabEntry();

  // Reset the scroll baseline when the session changes.
  useEffect(() => {
    seenLen.current = null;
  }, [activeSessionId, mode]);

  const totalMessageCount = sessionMessages.length;

  // The design opens with the greeting at the top of the thread. On first load
  // of a session we stay at the top; once new turns actually arrive we follow them
  // down to the bottom.
  useEffect(() => {
    const el = threadRef.current;
    if (!el) return;
    if (seenLen.current === null) {
      seenLen.current = totalMessageCount;
      el.scrollTop = 0;
      return;
    }
    if (totalMessageCount > seenLen.current) el.scrollTop = el.scrollHeight;
    seenLen.current = totalMessageCount;
  }, [totalMessageCount]);

  const bindLabel = investigationId ? shortCaseId(moduleId, investigationId) : moduleId;

  const promptGlyph = adv ? `${moduleId}:` : ">";
  const placeholder = adv
    ? `ask about ${bindLabel} \u2014 dissent, evidence, next action\u2026`
    : "describe a target or ask platform assistant\u2026";
  const modeLabel = adv ? "advanced \u25be" : "basic \u25be";
  const suggestions = adv ? ADV_SUGGESTIONS : BASIC_SUGGESTIONS;

  const trimmed = draft.trim();
  const isSending = postSessionMessage.isPending || createSession.isPending;

  const canSend = trimmed.length > 0 && !isSending;

  const doSend = (): void => {
    if (!canSend) return;
    const content = trimmed;
    if (!activeSessionId) {
      // Create the session, then post THIS message to it. Without the nested
      // post the operator's first message is dropped (session made, draft
      // cleared, nothing sent).
      createSession.mutate(
        { title: content.slice(0, 40) },
        {
          onSuccess: (newSess) => {
            setActiveSessionId(newSess.session_id);
            setDraft("");
            postSessionMessage.mutate({ content, sessionId: newSess.session_id });
          },
        },
      );
      return;
    }
    postSessionMessage.mutate(
      { content },
      {
        onSuccess: () => setDraft(""),
      },
    );
  };

  const markActed = (messageId?: string): void => {
    if (!messageId) return;
    setActed((prev) => {
      if (prev.has(messageId)) return prev;
      const next = new Set(prev);
      next.add(messageId);
      return next;
    });
  };

  // Dispatch a dante proposal against the existing hook that owns the
  // matching real mutation. open_wizard is a pure UI gesture (no mutation,
  // no acted flag needed). enqueue_scan / create_tag / delete_tag each map
  // to the same hook the operator would trigger by hand elsewhere in the UI.
  const onAction = (a: DanteAction, messageId?: string): void => {
    if (a.kind === "open_wizard") {
      // Resolve via the registry so dante can never propose a wizard that has
      // no working surface. Falls through silently when the module has no
      // registered primary wizard.
      const wid = primaryWizardIdForModule(a.module_id ?? moduleId);
      if (wid) onOpenWizard(wid, { targetId: a.target_id ?? undefined });
      return;
    }
    if (a.kind === "enqueue_scan") {
      const query = (a.query ?? "").trim();
      if (!query) return;
      submitVulnScan.mutate(
        { query_text: query, targets: a.system_ids ?? [] },
        { onSettled: () => markActed(messageId) },
      );
      markActed(messageId);
      return;
    }
    if (a.kind === "create_tag") {
      const key = (a.key ?? "").trim();
      if (!key) return;
      createVocab.mutate(
        { tag_key: key, description: a.summary ?? "" },
        { onSettled: () => markActed(messageId) },
      );
      markActed(messageId);
      return;
    }
    if (a.kind === "delete_tag") {
      const key = (a.key ?? "").trim();
      if (!key) return;
      deleteVocab.mutate(key, { onSettled: () => markActed(messageId) });
      markActed(messageId);
      return;
    }
  };

  const rowCtx: RowRenderCtx = { acted, onAction, onDismiss: markActed };

  // Publish the resolved chat session id + acted-message-id set to the shared
  // store so the dante-actions widget can render pending proposals from the
  // same session without duplicating this component's logic. Additive mirror
  // only -- ChatConsole is the sole writer.
  const publishSessionId = useChatSession((s) => s.setSessionId);
  const publishActedIds = useChatSession((s) => s.setActedMessageIds);
  useEffect(() => {
    publishSessionId(chatSessionId ?? null);
  }, [chatSessionId, publishSessionId]);
  useEffect(() => {
    publishActedIds(Array.from(acted));
  }, [acted, publishActedIds]);

  const onKey = (e: KeyboardEvent<HTMLInputElement>): void => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      doSend();
    }
  };

  /* ------------------------------- styles -------------------------------- */

  const panelStyle = css(
    "flex:1;min-height:0;width:100%;max-width:820px;margin:20px auto 0;display:flex;flex-direction:column;overflow:hidden;border:1px solid var(--border);border-radius:4px;background:color-mix(in srgb,var(--surface-card) 84%,transparent);box-shadow:0 0 46px rgba(255,95,135,0.09),inset 1px 1px 0 rgba(255,255,255,0.03),inset -1px -1px 0 rgba(0,0,0,0.5);backdrop-filter:blur(3px);",
  );
  const panelBarStyle = css(
    "flex:0 0 26px;height:26px;display:flex;align-items:center;gap:9px;padding:0 10px;background:var(--surface-chrome);border-bottom:1px solid var(--border);font-size:10px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-muted);",
  );
  const panelBarDot = css(
    "width:7px;height:7px;flex:0 0 auto;background:var(--accent);box-shadow:0 0 7px var(--accent);",
  );
  const panelBarLabel = css(
    "color:var(--text-primary);letter-spacing:0.14em;",
  );
  const panelBarHatch = css(
    "height:2px;flex:1;background-image:repeating-linear-gradient(135deg,var(--border) 0 1px,transparent 1px 3px);",
  );

  const threadStyle = css(
    "flex:1;min-height:0;width:100%;overflow:auto;padding:18px 18px 12px;display:flex;flex-direction:column;gap:16px;margin-top:0;",
  );
  const emptyStyle = css(
    `color:${T.mut};font-family:var(--font-mono);font-size:11px;letter-spacing:0.04em;`,
  );

  const composerWrapStyle = css(
    "flex:0 0 auto;width:100%;padding:10px 14px 12px;border-top:1px solid var(--border-soft);background:color-mix(in srgb,var(--surface-sunk) 60%,transparent);" +
      (dockOpen ? "padding-bottom:52px;" : ""),
  );
  const suggestionsRow = css(
    "display:flex;flex-wrap:wrap;gap:6px;margin-bottom:9px;",
  );
  const suggestionBtn = css(
    `padding:5px 10px;font-family:var(--font-mono);font-size:10px;letter-spacing:0.04em;color:${T.mut};background:var(--surface-card);border:1px solid var(--border-soft);border-radius:2px;cursor:pointer;white-space:nowrap;`,
  );
  const newInvBtn = css(
    `padding:5px 10px;font-family:var(--font-mono);font-size:10px;letter-spacing:0.04em;color:var(--accent);background:color-mix(in srgb,var(--accent) 12%,transparent);border:1px solid ${H.acc}66;border-radius:2px;cursor:pointer;white-space:nowrap;`,
  );
  const xrayBtnStyle = css(
    `flex:0 0 auto;font-size:9px;letter-spacing:0.12em;text-transform:uppercase;color:var(--accent);background:transparent;border:0;cursor:pointer;padding:0 4px;`,
  );
  const composerStyle = css(
    `display:flex;align-items:center;gap:9px;padding:6px 8px 6px 12px;background:var(--surface-card);border:1px solid ${H.acc}59;border-radius:3px;box-shadow:0 0 30px rgba(255,95,135,0.12),var(--bevel-raised,inset 1px 1px 0 rgba(255,255,255,0.03));`,
  );
  const promptStyle = css(
    "flex:0 0 auto;color:var(--accent);font-size:13px;font-weight:700;",
  );
  const inputStyle = css(
    "flex:1;min-width:0;background:transparent;border:0;outline:none;color:var(--text-primary);font-family:var(--font-mono);font-size:13px;letter-spacing:0.01em;",
  );
  const modeBtnStyle = css(
    `flex:0 0 auto;padding:0 10px;height:30px;font-family:var(--font-mono);font-size:9.5px;letter-spacing:0.1em;text-transform:uppercase;color:${adv ? T.acc : T.mut};background:transparent;border:1px solid ${adv ? `${H.acc}66` : "var(--border-soft)"};border-radius:2px;cursor:pointer;`,
  );
  const sendBase =
    "flex:0 0 auto;display:inline-flex;align-items:center;gap:6px;padding:0 14px;height:30px;font-family:var(--font-mono);font-size:10px;text-transform:uppercase;color:var(--text-on-accent);background:var(--accent);border:1px solid var(--accent);border-radius:2px;cursor:pointer;box-shadow:0 0 16px rgba(255,95,135,0.3);";
  const sendStyle = css(
    canSend ? sendBase : `${sendBase}opacity:0.45;cursor:not-allowed;`,
  );
  const sendLabelStyle = css("letter-spacing:0.1em;");
  const sendArrowStyle = css("font-size:11px;");

  /* ------------------------------- thread -------------------------------- */

  let threadContent: JSX.Element | JSX.Element[];
  if (sessionMessagesQ.isLoading && !sessionMessagesQ.data) {
    threadContent = <div key="_load" style={emptyStyle}>connecting to assistant session...</div>;
  } else if (sessionMessages.length === 0) {
    threadContent = [];
  } else {
    threadContent = sessionMessages.map((m) => renderRow(m.message_id, bindSessionMessage(m), rowCtx));
  }

  /* -------------------------------- render ------------------------------- */

  return (
    <div style={panelStyle}>
      <div style={panelBarStyle}>
        <span style={panelBarDot} />
        <span style={panelBarLabel}>dante</span>
        <span aria-hidden="true" style={panelBarHatch} />
        {adv && investigationId && onOpenXray ? (
          <button type="button" onClick={onOpenXray} style={xrayBtnStyle}>
            x-ray {"\u25b8"}
          </button>
        ) : null}
      </div>

      <div ref={threadRef} style={threadStyle}>
        {threadContent}
      </div>

      <div style={composerWrapStyle}>
        <div style={suggestionsRow}>
          {!adv ? (
            <button key="_new" type="button" onClick={() => onOpenIntake()} style={newInvBtn}>
              {"\uff0b new investigation"}
            </button>
          ) : null}
          {wizardsForModule(moduleId).length > 0 ? (
            <span key="_wizpick" style={{ position: "relative", display: "inline-flex" }}>
              <button
                type="button"
                aria-haspopup="menu"
                aria-expanded={pickerOpen}
                onClick={() => setPickerOpen((v) => !v)}
                style={newInvBtn}
              >
                {"\uff0b open wizard \u25be"}
              </button>
              {pickerOpen ? (
                <div
                  role="menu"
                  style={css(
                    "position:absolute;left:0;top:calc(100% + 4px);z-index:6;min-width:260px;padding:5px;background:var(--surface-chrome);border:1px solid var(--border);border-radius:3px;box-shadow:0 10px 30px rgba(0,0,0,0.55);display:flex;flex-direction:column;gap:2px;",
                  )}
                >
                  {wizardsForModule(moduleId).map((w) => (
                    <button
                      key={w.id}
                      type="button"
                      role="menuitem"
                      onClick={() => {
                        setPickerOpen(false);
                        onOpenWizard(w.id);
                      }}
                      style={css(
                        "display:flex;flex-direction:column;align-items:flex-start;gap:2px;padding:7px 9px;background:transparent;border:0;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;letter-spacing:0.02em;cursor:pointer;text-align:left;border-radius:2px;",
                      )}
                    >
                      <span style={{ color: "var(--accent)", letterSpacing: "0.06em" }}>{w.label}</span>
                      <span style={{ color: "var(--text-muted)", fontSize: 10, letterSpacing: "0.02em" }}>{w.purpose}</span>
                    </button>
                  ))}
                </div>
              ) : null}
            </span>
          ) : null}
          {suggestions.map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => setDraft(s)}
              style={suggestionBtn}
            >
              {s}
            </button>
          ))}
        </div>
        <div style={composerStyle}>
          <span style={promptStyle}>{promptGlyph}</span>
          <input
            value={draft}
            onChange={(e: ChangeEvent<HTMLInputElement>) =>
              setDraft(e.target.value)
            }
            onKeyDown={onKey}
            placeholder={placeholder}
            style={inputStyle}
          />
          <button type="button" onClick={onToggleMode} style={modeBtnStyle}>
            {modeLabel}
          </button>
          <button
            type="button"
            onClick={doSend}
            disabled={!canSend}
            style={sendStyle}
          >
            <span style={sendLabelStyle}>send</span>
            <span style={sendArrowStyle}>{"\u25b8"}</span>
          </button>
        </div>
      </div>
    </div>
  );
}
