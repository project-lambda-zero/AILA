import {
  useEffect,
  useRef,
  useState,
  type ChangeEvent,
  type CSSProperties,
  type JSX,
  type KeyboardEvent,
} from "react";

import { useMessages, usePostMessage } from "../api/hooks";
import type { Message } from "../api/types";
import type { ChatConsoleProps } from "./contract";
import { css } from "./css";
import { shortCaseId } from "./ids";

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

// Read an unknown-typed payload field as string without an inline cast --
// the linter blocks `(payload as {x:string}).x`; this is the shared narrow.
function readStr(o: Record<string, unknown>, k: string): string | null {
  const v = o[k];
  return typeof v === "string" ? v : null;
}

// HH:MM:SS from an ISO string, empty if unparseable. Zero-padded.
function formatClock(iso?: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}

// Compact JSON preview for non-text payloads: single-line, capped so the
// bubble doesn't unroll a full tool_call body.
function previewPayload(payload: Record<string, unknown>): string {
  try {
    const s = JSON.stringify(payload);
    if (!s) return "";
    return s.length > 220 ? s.slice(0, 220) + "..." : s;
  } catch {
    return "";
  }
}

// Read an unknown-typed field as a finite number, else null. Mirrors readStr.
function readNum(o: Record<string, unknown>, k: string): number | null {
  const v = o[k];
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

// Narrow an unknown (a JSON.parse result, a nested field) to an indexable
// record so readStr/readNum can read it. Not a cast-access: no field is read
// off the assertion here, callers go through the typed helpers.
function asRecord(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : null;
}

// A tool_call payload carries `command` as a JSON string of the form
// {"tool": "audit_mcp.semantic_search", "args": {...}}. Pull the tool name and
// one short argument hint (query / path / target) so the row reads like the
// mock's chips instead of unrolling the raw command body.
function parseToolCommand(payload: Record<string, unknown>): {
  tool: string | null;
  hint: string | null;
} {
  const raw = readStr(payload, "command");
  if (!raw) return { tool: null, hint: null };
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { tool: null, hint: null };
  }
  const rec = asRecord(parsed);
  if (!rec) return { tool: null, hint: null };
  const args = asRecord(rec["args"]);
  const hint = args
    ? readStr(args, "query") ??
      readStr(args, "file_path") ??
      readStr(args, "apk_path") ??
      readStr(args, "name") ??
      readStr(args, "target")
    : null;
  return { tool: readStr(rec, "tool"), hint };
}

// Collapse a path/query hint to a short chip label: basename for paths,
// truncated otherwise. Ellipsis lives in a string literal (safe outside JSX).
function shortHint(s: string): string {
  const segs = s.split(/[\\/]/);
  const base = segs[segs.length - 1] || s;
  return base.length > 42 ? base.slice(0, 42) + "\u2026" : base;
}

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

const ADV_SUGGESTIONS: readonly string[] = [
  "summarize the dissent",
  "what is still unconfirmed?",
  "draft the disclosure",
];

// "+ new investigation" is rendered separately as an accent action (it opens
// the intake wizard, not a prompt). These are the plain prompt chips.
const BASIC_SUGGESTIONS: readonly string[] = [
  "what can you do?",
  "explain the modules",
  "check platform health",
  "search findings",
];

// Assistant copy for the boot bubble (basic mode / unbound). This is
// static assistant COPY, not fabricated investigation data.
const BOOT_COPY =
  "aila online. point me at a target \u2014 a repo, a binary, a CVE, an apk \u2014 and I open an investigation. every step stays in the record.";

/* --------------------------- message row rendering ------------------------ */

interface RowProps {
  who: "you" | "dante";
  meta: string;
  body: string;
  chips: Array<{ label: string; tone: ChipTone }>;
  card: { id: string; conf: string; body: string } | null;
}

function renderRow(key: string, r: RowProps): JSX.Element {
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
    </div>
  );
}

// Bind one live Message to a RowProps -- no fabrication: every value
// comes off the payload we actually received.
function bindMessage(m: Message): RowProps {
  const you = m.sender_kind === "operator";
  const payload: Record<string, unknown> = m.payload ?? {};
  const kind = m.payload_kind || "text";

  let meta = formatClock(m.created_at);
  if (!meta && typeof m.at_turn === "number") meta = `t${m.at_turn}`;

  const chips: Array<{ label: string; tone: ChipTone }> = [];
  let body = "";
  let card: RowProps["card"] = null;

  if (kind === "tool_call") {
    const { tool, hint } = parseToolCommand(payload);
    body = readStr(payload, "reasoning") ?? (tool ? `calling ${tool}` : "tool call");
    if (tool) chips.push({ label: tool, tone: "warn" });
    if (hint) chips.push({ label: shortHint(hint), tone: "info" });
  } else if (kind === "text") {
    const text = readStr(payload, "text");
    if (text) {
      body = text;
    } else {
      // Engine tool results arrive as text-kind carrying a `tool` field.
      const tool = readStr(payload, "tool");
      if (tool) {
        const mc = readNum(payload, "match_count");
        const q = readStr(payload, "query");
        body =
          tool +
          (mc !== null ? ` -- ${mc} match${mc === 1 ? "" : "es"}` : "") +
          (q ? `: ${q}` : "");
        chips.push({ label: tool, tone: "warn" });
      } else {
        body = previewPayload(payload);
      }
    }
  } else if (kind === "decompiled_function") {
    const fn = readStr(payload, "function_name") ?? "function";
    const addr = readStr(payload, "address");
    const lc = readNum(payload, "line_count");
    body =
      `decompiled ${fn}` +
      (addr ? ` @ ${addr}` : "") +
      (lc !== null ? ` (${lc} lines)` : "");
    chips.push({ label: "decompiled", tone: "info" });
  } else if (kind === "xref_view") {
    const total = readNum(payload, "total");
    const note = readStr(payload, "bridge_note");
    const tgt = readStr(payload, "target");
    body = note ?? `xrefs of ${tgt ?? "target"}: ${total !== null ? total : "?"}`;
    chips.push({ label: "xref", tone: "info" });
  } else if (kind === "outcome_pending" || kind === "outcome_review") {
    body =
      readStr(payload, "answer") ??
      readStr(payload, "reasoning") ??
      readStr(payload, "comment") ??
      kind.replace(/_/g, " ");
    const vote = readStr(payload, "vote");
    if (vote) chips.push({ label: vote, tone: "acc" });
    const conf = readNum(payload, "confidence");
    if (conf !== null) chips.push({ label: `confidence ${conf.toFixed(2)}`, tone: "info" });
  } else if (kind === "taint_flow") {
    const src = readStr(payload, "source") ?? "?";
    const tgt = readStr(payload, "target") ?? "?";
    const total = readNum(payload, "total");
    body = `taint ${src} -> ${tgt}: ${total !== null ? total : "?"} path${total === 1 ? "" : "s"}`;
    chips.push({ label: "taint_flow", tone: "sig" });
  } else if (kind === "hypothesis_update") {
    const claim = readStr(payload, "claim") ?? readStr(payload, "text") ?? "";
    const hid = readStr(payload, "hypothesis_id") ?? readStr(payload, "id") ?? "";
    const state = readStr(payload, "state") ?? "";
    const conf = readNum(payload, "confidence");
    const confLabel =
      conf !== null ? `confidence ${conf.toFixed(2)}` : state ? `state ${state}` : "";
    const summary = readStr(payload, "summary");
    body = summary ?? (hid ? `hypothesis ${hid} ${state}`.trim() : "hypothesis update");
    card = { id: hid, conf: confLabel, body: claim || summary || "" };
  } else {
    body = readStr(payload, "text") ?? `${kind}: ${previewPayload(payload)}`;
  }

  const evCount = m.evidence_refs?.length ?? 0;
  if (evCount > 0) chips.push({ label: `evidence x${evCount}`, tone: "ok" });
  if (typeof m.at_turn === "number") chips.push({ label: `t${m.at_turn}`, tone: "info" });

  return { who: you ? "you" : "dante", meta, body, chips, card };
}

/* ---------------------------------- root ---------------------------------- */

export default function ChatConsole(props: ChatConsoleProps): JSX.Element {
  const { mode, moduleId, investigationId, onToggleMode, onOpenIntake, onOpenXray, dockOpen } =
    props;
  const adv = mode === "advanced";

  const [draft, setDraft] = useState<string>("");
  const threadRef = useRef<HTMLDivElement | null>(null);
  const seenLen = useRef<number | null>(null);

  const messagesQuery = useMessages(investigationId);
  const postMessage = usePostMessage(investigationId);
  const messages: Message[] = messagesQuery.data ?? [];

  // Reset the scroll baseline when the bound case changes.
  useEffect(() => {
    seenLen.current = null;
  }, [investigationId]);

  // The design opens with the greeting at the top of the thread. On first load
  // of a case we stay at the top; once new turns actually arrive we follow them
  // down to the bottom.
  useEffect(() => {
    const el = threadRef.current;
    if (!el) return;
    if (seenLen.current === null) {
      seenLen.current = messages.length;
      el.scrollTop = 0;
      return;
    }
    if (messages.length > seenLen.current) el.scrollTop = el.scrollHeight;
    seenLen.current = messages.length;
  }, [messages.length]);

  const bindLabel = investigationId ? shortCaseId(moduleId, investigationId) : moduleId;
  const panelSig = adv ? `bound \u00b7 ${bindLabel} case_state` : "";

  const promptGlyph = adv ? `${moduleId}:` : ">";
  const placeholder = adv
    ? `ask about ${bindLabel} \u2014 dissent, evidence, next action\u2026`
    : "describe a target or paste a repo / CVE / binary\u2026";
  const modeLabel = adv ? "advanced \u25be" : "basic \u25be";
  const suggestions = adv ? ADV_SUGGESTIONS : BASIC_SUGGESTIONS;

  const trimmed = draft.trim();
  const canSend =
    trimmed.length > 0 &&
    !(adv && !investigationId) &&
    !postMessage.isPending;

  const doSend = (): void => {
    if (!canSend) return;
    if (adv && investigationId) {
      postMessage.mutate(trimmed, {
        onSuccess: () => setDraft(""),
      });
      return;
    }
    // Basic mode has no real backend endpoint; clear the draft honestly
    // rather than fake a reply.
    setDraft("");
  };

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
  const panelBarSig = css(
    "color:var(--text-faint);text-transform:none;letter-spacing:0.05em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;",
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

  // The console opens with the assistant greeting -- the same static copy the
  // design page leads with -- and the live turns follow it. This is UI chrome,
  // not investigation data, so it is honest to show above any bound thread.
  const bootRow = renderRow("boot", {
    who: "dante",
    meta: "boot",
    body: BOOT_COPY,
    chips: [],
    card: null,
  });

  let threadContent: JSX.Element | JSX.Element[];
  if (adv && investigationId) {
    if (messagesQuery.isLoading) {
      threadContent = [bootRow, <div key="_load" style={emptyStyle}>loading conversation...</div>];
    } else if (messagesQuery.isError) {
      threadContent = [
        bootRow,
        <div key="_err" style={emptyStyle}>could not load messages for this investigation.</div>,
      ];
    } else if (messages.length === 0) {
      threadContent = [
        bootRow,
        <div key="_empty" style={emptyStyle}>no turns yet -- send a message below</div>,
      ];
    } else {
      threadContent = [bootRow, ...messages.map((m) => renderRow(m.id, bindMessage(m)))];
    }
  } else {
    threadContent = bootRow;
  }

  /* -------------------------------- render ------------------------------- */

  return (
    <div style={panelStyle}>
      <div style={panelBarStyle}>
        <span style={panelBarDot} />
        <span style={panelBarLabel}>console</span>
        <span aria-hidden="true" style={panelBarHatch} />
        <span style={panelBarSig}>{panelSig}</span>
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
            <button key="_new" type="button" onClick={onOpenIntake} style={newInvBtn}>
              {"\uff0b new investigation"}
            </button>
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
