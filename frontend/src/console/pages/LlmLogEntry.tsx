/**
 * Chat transcript renderer for the admin LLM interaction log.
 *
 * The row-preview one-liners were retired with req 52: the DataPage list no
 * longer surfaces raw prompt/response snippets (they leaked opaque JSON
 * fragments). Full stored bodies are now fetched on demand by the floating
 * LlmLogViewer via /admin/llm-log/{id}/content, which delegates the actual
 * body render to `LlmChatTranscript` below.
 *
 * The transcript component picks the chat-bubble shape when the value parses
 * as a role/content array, and falls back to a mono block otherwise -- a
 * structured-output response still gets an honest indented view rather than
 * a fabricated turn split.
 */
import type { CSSProperties, JSX } from "react";

import { css } from "../css";

export interface ChatMessage {
  role: string;
  content: string;
}

/** Roles rendered with a stronger label colour; anything else falls back to
 * the neutral bubble styling. Static string-keyed table. */
const KNOWN_ROLES: Record<string, true> = {
  system: true,
  user: true,
  assistant: true,
  tool: true,
  function: true,
  developer: true,
};

/** Parse a value into a chat-messages array when it looks like one. Accepts
 * either a parsed array or a JSON string. Returns null when the value is not
 * recognisably a chat transcript so callers fall back to plain-text rendering
 * instead of forcing a wrong shape. */
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
      // image/audio parts (they carry no readable body here).
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
  "margin:0;padding:6px 8px;border:1px solid var(--border-soft);border-radius:2px;background:var(--surface-sunk);font-family:var(--font-mono);font-size:10px;line-height:1.4;color:var(--text-primary);white-space:pre-wrap;word-break:break-word;max-height:100%;overflow:auto;",
);

/** Full transcript view: role-labeled bubbles (system / user / assistant /
 * tool). Falls back to a mono block when the value isn't a chat array so
 * callers get an honest render for structured-output responses instead of a
 * fabricated transcript. Reusable in any detail panel that surfaces an LLM
 * prompt or response. */
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
  // otherwise. This is the honest fallback -- a structured response gets an
  // indented view instead of a fabricated role/content split.
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

export default LlmChatTranscript;
