import { asRecord, readNum, readStr } from "../../../api/parse";
import type { Message } from "../../../api/types";

// Untyped JSON object at the API boundary: a message payload or a parsed tool
// command. Every field read narrows through the api/parse readers.
export type Payload = Record<string, unknown>;

export function pad2(n: number): string {
  return (n < 10 ? "0" : "") + n;
}

// Ledger / message rows carry an ISO `created_at`. Render it as a compact
// local HH:MM:SS clock for the timeline columns. Empty on a missing or
// unparseable stamp so a bad value degrades to blank, never "Invalid Date".
export function clockTime(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
}

export function turnType(kind: string): string {
  if (kind === "tool_call") return "tool_run";
  if (kind === "text") return "text";
  if (kind === "outcome_pending" || kind === "outcome_review") return "submit";
  return kind.replace(/_/g, " ");
}

// A tool_call payload's `command` is a JSON string {"tool":..,"args":..}.
// `arg` is the call's one-line summary: the first string-valued entry of
// `args` among `argKeys`, tried in order. The key preference is module-specific
// (each module's MCP tools name their primary argument differently), so the
// caller supplies it.
export function parseTool(payload: Payload, argKeys: readonly string[]): { tool: string | null; arg: string | null } {
  const raw = readStr(payload, "command");
  if (!raw) return { tool: null, arg: null };
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { tool: null, arg: null };
  }
  const rec = asRecord(parsed);
  if (!rec) return { tool: null, arg: null };
  const args = asRecord(rec["args"]);
  let arg: string | null = null;
  if (args) {
    for (const k of argKeys) {
      arg = readStr(args, k);
      if (arg !== null) break;
    }
  }
  return { tool: readStr(rec, "tool"), arg };
}

// Full tool-call parse -- tool name plus its args object -- for the expanded
// turn detail. The `command` payload field is a JSON string {tool, args}.
export function parseToolFull(payload: Payload): { tool: string | null; args: [string, string][] } {
  const cmd = readStr(payload, "command");
  if (!cmd) return { tool: null, args: [] };
  try {
    const rec = asRecord(JSON.parse(cmd)) ?? {};
    const argsRec = asRecord(rec.args) ?? {};
    const args = Object.entries(argsRec).map(
      ([k, v]): [string, string] => [k, typeof v === "string" ? v : JSON.stringify(v)],
    );
    return { tool: readStr(rec, "tool"), args };
  } catch {
    return { tool: null, args: [] };
  }
}

// The tool_call fields an expanded turn card renders: the parsed command plus
// the call's reasoning, expected observation and attached script ("" when absent).
export interface ToolCallView {
  readonly tool: string | null;
  readonly args: readonly [string, string][];
  readonly reasoning: string;
  readonly expects: string;
  readonly script: string;
}

export function toolCallView(payload: Payload): ToolCallView {
  const { tool, args } = parseToolFull(payload);
  return {
    tool,
    args,
    reasoning: readStr(payload, "reasoning") ?? "",
    expects: readStr(payload, "expected_observation") ?? "",
    script: readStr(payload, "script_content") ?? "",
  };
}

export function turnProse(m: Message): string {
  const p: Payload = m.payload ?? {};
  const kind = m.payload_kind || "text";
  if (kind === "tool_call") {
    const reason = readStr(p, "reasoning");
    if (reason) return reason;
    const t = parseToolFull(p).tool;
    return t ? `calling ${t}` : "tool call";
  }
  if (kind === "text") {
    const text = readStr(p, "text");
    if (text) return text;
    const tool = readStr(p, "tool");
    if (tool) {
      const mc = readNum(p, "match_count");
      const q = readStr(p, "query");
      return tool + (mc !== null ? ` -- ${mc} match${mc === 1 ? "" : "es"}` : "") + (q ? `: ${q}` : "");
    }
    return "";
  }
  if (kind === "outcome_pending" || kind === "outcome_review") {
    return readStr(p, "answer") ?? readStr(p, "reasoning") ?? readStr(p, "comment") ?? "outcome";
  }
  if (kind === "decompiled_function") {
    const fn = readStr(p, "function_name") ?? "function";
    return `decompiled ${fn}`;
  }
  if (kind === "xref_view") return readStr(p, "bridge_note") ?? "xrefs";
  if (kind === "taint_flow") return `taint ${readStr(p, "source") ?? "?"} -> ${readStr(p, "target") ?? "?"}`;
  if (kind === "poc_script") {
    const lang = readStr(p, "language") ?? "python";
    const st = readStr(p, "status");
    return `proof-of-concept ${lang} script${st ? ` (${st})` : ""}`;
  }
  return readStr(p, "text") ?? kind;
}

// A ledger entry's text is sometimes a compact JSON payload (oracle requests
// carry the human sentence under "reason"). Surface that sentence for display;
// leave already-prose text untouched.
export function ledgerText(text: string): string {
  const t = text.trim();
  if (t.startsWith("{") && t.endsWith("}")) {
    try {
      const o = asRecord(JSON.parse(t));
      if (o) {
        for (const k of ["reason", "summary", "note", "rationale", "claim", "directive", "message"]) {
          const v = readStr(o, k);
          if (v && v.trim()) return v;
        }
      }
    } catch {
      // not JSON -- fall through to the raw text
    }
  }
  return text;
}

// One card = ONE action + its output. An action is a tool_call; the messages
// that follow it (its result) belong to the same card, until the next
// tool_call. A turn with 3 tool_calls becomes 3 readable cards, not one wall.
// Messages are keyed to a turn by (branch, at_turn), ordered by time within
// it, then split at each tool_call. Cards are newest-first (live tail).
export function groupTurns(msgs: readonly Message[]): Message[][] {
  const turns = new Map<string, Message[]>();
  for (const m of msgs) {
    const key = `${m.branch_id ?? "-"}::${m.at_turn ?? "?"}`;
    const g = turns.get(key);
    if (g) g.push(m);
    else turns.set(key, [m]);
  }
  const blocks: Message[][] = [];
  for (const turn of turns.values()) {
    turn.sort((a, b) => (a.created_at ?? "").localeCompare(b.created_at ?? ""));
    let cur: Message[] | null = null;
    for (const m of turn) {
      if ((m.payload_kind || "") === "tool_call") {
        if (cur) blocks.push(cur);
        cur = [m];
      } else if (cur) {
        cur.push(m);
      } else {
        cur = [m];
      }
    }
    if (cur) blocks.push(cur);
  }
  blocks.sort((a, b) => (b[b.length - 1].created_at ?? "").localeCompare(a[a.length - 1].created_at ?? ""));
  return blocks;
}

// Flat newest-first message stream for the compact "activity" drawer feed.
export function newestFirst(msgs: readonly Message[]): Message[] {
  return [...msgs].sort((a, b) => (b.created_at ?? "").localeCompare(a.created_at ?? ""));
}

// Money: two decimals with a leading "$", em dash for missing values.
export function usd(n: number | null | undefined): string {
  return typeof n === "number" ? `$${n.toFixed(2)}` : "\u2014";
}
