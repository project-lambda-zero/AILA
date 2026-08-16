/**
 * Readable renderers for the admin LLM interaction log.
 *
 * Backend ships `prompt_preview` and `response_preview` as opaque 200-char
 * strings (see aila.platform.llm.cost._make_preview). Usually those are
 * plain LLM text; sometimes they are a JSON chat-messages array (the
 * caller serialized the whole request) or a JSON object (the model
 * returned structured content). This module turns either shape into a
 * clean single-line preview for list cells, plus a role-segmented
 * transcript component reusable in a detail panel.
 *
 * Nothing here fabricates content -- if the value is empty or
 * unparseable, callers get null / an em-dash / a mono fallback so the
 * "raw JSON" complaint never leaks back through.
 */
import type { CSSProperties, JSX } from "react";

import { css } from "../css";

/** Ellipsize target for one-line previews. 140 chars fits a DataPage cell
 * without wrapping while still carrying enough context to skim. */
const MAX_LINE = 140;

export interface ChatMessage {
  role: string;
  content: string;
}

/** Roles we render with a stronger label colour; anything else falls back
 * to the neutral bubble styling. Static string-keyed table. */
const KNOWN_ROLES: Record<string, true> = {
  system: true,
  user: true,
  assistant: true,
  tool: true,
  function: true,
  developer: true,
};

/** Parse a value into a chat-messages array when it looks like one.
 * Accepts either a parsed array or a JSON string. Returns null when the
 * value is not recognisably a chat transcript so callers can fall back to
 * plain-text rendering instead of forcing a wrong shape. */
export function parseChatMessages(value: unknown): ChatMessage[] | null {
  const parsed = typeof value === "string" ? tryJson(value) : value;
  if (!Array.isArray(parsed) || parsed.length === 0) return null;

  const messages: ChatMessage[] = [];
  for (const raw of parsed) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
    if (!("role" in raw) || typeof raw.role !== "string") return null;
    const role = raw.role;
    const content: unknown = "content" in raw ? raw.content : "";

    let text: string;
    if (typeof content === "string") {
      text = content;
    } else if (Array.isArray(content)) {
      // OpenAI multi-part content list -- keep the text parts only, drop
      // image/audio parts (they carry no readable preview here).
      const parts: string[] = [];
      for (const p of content) {
        if (p && typeof p === "object" && "text" in p && typeof p.text === "string") {
          parts.push(p.text);
        }
      }
      text = parts.join(" ");
    } else if (content === null || content === undefined) {
      text = "";
    } else {
      // Structured tool payload: shortest honest single-line label is the
      // compact JSON of the object.
      try {
        text = JSON.stringify(content);
      } catch {
        text = String(content);
      }
    }
    messages.push({ role, content: text });
  }
  return messages;
}

function tryJson(text: string): unknown {
  const head = text.trimStart();
  if (!head) return null;
  const first = head.charAt(0);
  if (first !== "{" && first !== "[" && first !== '"') return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/** Undo the common JSON string escapes so a salvaged fragment reads
 * naturally. Bails on malformed sequences instead of throwing. */
function unescapeJsonString(text: string): string {
  return text
    .replace(/\\n/g, " ")
    .replace(/\\t/g, " ")
    .replace(/\\r/g, " ")
    .replace(/\\"/g, '"')
    .replace(/\\\\/g, "\\");
}

/** Collapse whitespace + ellipsize. Small helper because it's applied to
 * every preview branch (chat pick, JSON extract, plain text). */
function ellipsize(text: string, max = MAX_LINE): string {
  const collapsed = text.replace(/\s+/g, " ").trim();
  const cap = max > 1 ? max : 1;
  return collapsed.length > cap ? collapsed.slice(0, cap - 1) + "\u2026" : collapsed;
}

/** Pick the most informative message from a parsed transcript. For a
 * request-side preview we prefer the last non-empty user turn (the
 * operator's actual ask); for a response-side preview we prefer the last
 * assistant turn. Falls back to any non-empty message when the preferred
 * role isn't present. */
function pickPreviewMessage(
  messages: ChatMessage[],
  kind: "prompt" | "response",
): ChatMessage | null {
  const preferred = kind === "prompt" ? "user" : "assistant";
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    if (messages[i].role === preferred && messages[i].content.trim() !== "") return messages[i];
  }
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    if (messages[i].content.trim() !== "") return messages[i];
  }
  return null;
}

/** Build a single-line preview: `role: text` when the value is a chat
 * transcript, a natural-key extract when it's a JSON object, or plain
 * ellipsized text otherwise. Returns null for empty / null / undefined so
 * the caller can render an em-dash instead of an empty cell. */
export function llmPreviewLine(
  value: unknown,
  kind: "prompt" | "response",
): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value === "string" && value.trim() === "") return null;

  const messages = parseChatMessages(value);
  if (messages) {
    const pick = pickPreviewMessage(messages, kind);
    if (!pick) return null;
    const room = MAX_LINE - pick.role.length - 2;
    return `${pick.role}: ${ellipsize(pick.content, room > 20 ? room : 20)}`;
  }

  if (typeof value === "string") {
    const parsed = tryJson(value);
    if (parsed !== null && parsed !== undefined) {
      const line = flattenJsonToLine(parsed);
      if (line) return ellipsize(line);
    }
    // Backend caps previews at 200 chars, which frequently cuts a JSON
    // response mid-string so `tryJson` returns null. Salvage the model's
    // text so the operator sees words instead of a `{"summary":"...`
    // fragment. Regex captures may be unterminated -- that's expected on
    // the mid-string cut, and we strip trailing quote/brace noise.
    const head = value.trimStart();
    if (head && (head.charAt(0) === "{" || head.charAt(0) === "[")) {
      const keyed = value.match(
        /"(?:content|text|message|summary|answer|output)"\s*:\s*"((?:[^"\\]|\\.)*)/,
      );
      if (keyed && keyed[1].trim().length >= 2) {
        return ellipsize(unescapeJsonString(keyed[1].replace(/"$/, "")));
      }
      const anyValue = [...value.matchAll(/"\s*:\s*"((?:[^"\\]|\\.)*)/g)].pop();
      if (anyValue && anyValue[1].trim().length >= 2) {
        return ellipsize(unescapeJsonString(anyValue[1].replace(/"$/, "")));
      }
    }
    return ellipsize(value);
  }

  const line = flattenJsonToLine(value);
  return line ? ellipsize(line) : null;
}

/** Type guard: parsed-JSON plain object (not array, not null). Lets us
 * iterate arbitrary parsed JSON without inline casts. */
function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Turn a JSON value into a single-line description without brace / quote
 * noise. Prefers a well-known content key when the value is an object so
 * a `{"summary": "..."}` response reads as its summary text. */
function flattenJsonToLine(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) {
    if (value.length === 0) return null;
    const parts: string[] = [];
    for (const v of value) {
      const s = flattenJsonToLine(v);
      if (s !== null && s !== "") parts.push(s);
      if (parts.join(", ").length > MAX_LINE) break;
    }
    return parts.length ? parts.join(", ") : null;
  }
  if (isPlainObject(value)) {
    for (const k of ["content", "text", "message", "summary", "answer", "output"]) {
      const v = value[k];
      if (typeof v === "string" && v.trim() !== "") return v;
    }
    const pairs: string[] = [];
    for (const [k, v] of Object.entries(value)) {
      const s = flattenJsonToLine(v);
      if (s === null || s === "") continue;
      pairs.push(`${k}: ${s}`);
      if (pairs.join(" \u00b7 ").length > MAX_LINE) break;
    }
    return pairs.length ? pairs.join(" \u00b7 ") : null;
  }
  return null;
}

const ROLE_PREFIX_RE = /^(system|user|assistant|tool|function|developer):\s+/i;

/** Inline preview cell -- role prefix in faint chrome + primary-color
 * body text. Safe to drop into a DataPage column `render`. */
export function LlmLogPreview({
  value,
  kind,
}: {
  value: unknown;
  kind: "prompt" | "response";
}): JSX.Element {
  const line = llmPreviewLine(value, kind);
  if (line === null) {
    return <span style={css("color:var(--text-faint);")}>{"\u2014"}</span>;
  }
  const match = line.match(ROLE_PREFIX_RE);
  if (match) {
    return (
      <span style={inlineRow}>
        <span style={inlineRole}>{match[1].toLowerCase()}</span>
        <span style={inlineBody}>{line.slice(match[0].length)}</span>
      </span>
    );
  }
  return <span style={inlineBody}>{line}</span>;
}

const inlineRow = css("display:inline-flex;gap:6px;min-width:0;max-width:100%;align-items:baseline;");
const inlineRole = css(
  "flex:0 0 auto;color:var(--text-faint);font-size:9px;letter-spacing:0.1em;text-transform:uppercase;",
);
const inlineBody = css(
  "color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0;",
);

const BUBBLE_LABEL_COLOR: Record<string, string> = {
  user: "var(--accent)",
  assistant: "var(--status-ok)",
  system: "var(--text-muted)",
};

const transcriptWrap = css("display:flex;flex-direction:column;gap:6px;min-width:0;");
const bubbleBody = css(
  "font-family:var(--font-mono);font-size:10.5px;line-height:1.5;color:var(--text-primary);white-space:pre-wrap;word-break:break-word;",
);
const monoBlock = css(
  "margin:0;padding:6px 8px;border:1px solid var(--border-soft);border-radius:2px;background:var(--surface-sunk);font-family:var(--font-mono);font-size:10px;line-height:1.4;color:var(--text-primary);white-space:pre-wrap;word-break:break-word;max-height:320px;overflow:auto;",
);

/** Full transcript view: role-labeled bubbles (system / user / assistant /
 * tool). Falls back to a mono block when the value isn't a chat array so
 * callers get an honest render for structured-output responses instead of
 * a fabricated transcript. Reusable in any detail panel that surfaces an
 * LLM prompt or response. */
export function LlmChatTranscript({ value }: { value: unknown }): JSX.Element {
  const messages = parseChatMessages(value);
  if (messages) {
    return (
      <div style={transcriptWrap}>
        {messages.map((m, i) => {
          const r = m.role.toLowerCase();
          const border = KNOWN_ROLES[r] ? "var(--border-soft)" : "var(--border-faint)";
          const bubbleStyle: CSSProperties = css(
            `display:flex;flex-direction:column;gap:3px;padding:6px 8px;border:1px solid ${border};border-radius:2px;background:var(--surface-sunk);min-width:0;`,
          );
          const labelColor = BUBBLE_LABEL_COLOR[r] ?? "var(--text-faint)";
          const labelStyle: CSSProperties = css(
            `font-size:8.5px;letter-spacing:0.14em;text-transform:uppercase;color:${labelColor};`,
          );
          return (
            <div key={i} style={bubbleStyle}>
              <div style={labelStyle}>{m.role}</div>
              <div style={bubbleBody}>{m.content === "" ? "\u2014" : m.content}</div>
            </div>
          );
        })}
      </div>
    );
  }
  if (value === null || value === undefined) {
    return <span style={css("color:var(--text-faint);")}>{"\u2014"}</span>;
  }
  // Not a chat transcript: pretty-print JSON when we can, plain text
  // otherwise. This is the honest fallback -- a structured response gets
  // an indented view instead of a fabricated role/content split.
  let display: string;
  if (typeof value === "string") {
    const parsed = tryJson(value);
    if (parsed !== null && typeof parsed === "object") {
      try {
        display = JSON.stringify(parsed, null, 2);
      } catch {
        display = value;
      }
    } else {
      display = value;
    }
  } else {
    try {
      display = JSON.stringify(value, null, 2);
    } catch {
      display = String(value);
    }
  }
  if (display.trim() === "") {
    return <span style={css("color:var(--text-faint);")}>{"\u2014"}</span>;
  }
  return <pre style={monoBlock}>{display}</pre>;
}

export default LlmLogPreview;
