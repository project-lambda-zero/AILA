import { readStr } from "../../../../api/parse";
import type { Branch, McpCall, Message } from "../../../../api/types";
import { parseTool, turnProse } from "../parsers";
import type { Persona } from "../persona";
import { VR_TOOL_ARG_KEYS } from "./constants";

// One tool call as the agent issued it (message-derived MCP view).
export interface ToolCallRow {
  id: string;
  tool: string;
  server: string | null;
  arg: string | null;
  persona: string;
  status: "ok" | "hard-blocked";
  turn: number | null;
  reasoning: string;
  expected: string;
}

export function deriveToolCalls(msgs: readonly Message[], resolvePersona: (m: Message) => Persona): ToolCallRow[] {
  return msgs
    .filter((m) => m.payload_kind === "tool_call")
    .map((m) => {
      const p = m.payload ?? {};
      const { tool, arg } = parseTool(p, VR_TOOL_ARG_KEYS);
      const full = tool ?? "tool";
      const dot = full.indexOf(".");
      const server = dot > 0 ? full.slice(0, dot) : null;
      const name = dot > 0 ? full.slice(dot + 1) : full;
      const prose = turnProse(m).toLowerCase();
      const status = /blocked|refused|hard-blocked/.test(prose) ? "hard-blocked" : "ok";
      return {
        id: m.id,
        tool: name,
        server,
        arg,
        persona: resolvePersona(m).name,
        status,
        turn: m.at_turn ?? null,
        reasoning: readStr(p, "reasoning") ?? "",
        expected: readStr(p, "expected_observation") ?? "",
      };
    });
}

// A PoC is an authored exploit script (script_content / code), not decompiled
// source -- so pseudocode does not qualify.
export function findPocMessage(msgs: readonly Message[]): Message | undefined {
  return msgs.find((m) => {
    const p = m.payload ?? {};
    const code = readStr(p, "script_content") ?? readStr(p, "code");
    if (typeof code !== "string") return false;
    const t = code.trim();
    // A real PoC is a multi-line script, not a placeholder or a one-line
    // tool-call expression.
    return t.length > 20 && !/^(none|n\/a|null|-)$/i.test(t) && t.includes("\n");
  });
}

// A crash artifact is sanitizer/crash output, not a generic tool error.
export function findCrashMessage(msgs: readonly Message[]): Message | undefined {
  return msgs.find((m) => /addresssanitizer|use-after-free|heap-(?:use|buffer)|==\d+==\s*error|\bsanitizer\b/i.test(turnProse(m)));
}

// One row of the ORACLE layout's MCP CALLS pane plus its DETAIL rows.
export interface McpDisplayRow {
  id: string;
  label: string;
  server: string | null;
  persona: string;
  status: string;
  latency: number | null;
  rows: [string, string][];
  body: string;
}

// The per-investigation MCP call log (with latency) when present; otherwise
// the tool-call-derived view.
export function buildMcpDisplay(mcpData: readonly McpCall[], toolCalls: readonly ToolCallRow[], branchMap: ReadonlyMap<string, Branch>): McpDisplayRow[] {
  return mcpData.length > 0
    ? mcpData.map((c) => {
        const persona = (branchMap.get(c.branch_id ?? "")?.persona_voice ?? "").toUpperCase();
        const status = c.status === "ready" ? "ok" : c.status === "pending" ? "pending" : "error";
        const rows: [string, string][] = [["action", c.action]];
        if (c.server_id) rows.push(["server", c.server_id]);
        if (persona) rows.push(["persona", persona]);
        rows.push(["status", c.status]);
        if (c.latency_ms != null) rows.push(["latency", `${c.latency_ms}ms`]);
        if (c.http_status != null) rows.push(["http", String(c.http_status)]);
        if (c.turn_number != null) rows.push(["turn", `t${c.turn_number}`]);
        if (c.called_at) rows.push(["at", c.called_at]);
        return { id: c.id, label: c.action, server: c.server_id, persona, status, latency: c.latency_ms ?? null, rows, body: c.error_excerpt ?? "" };
      })
    : toolCalls.map((c) => {
        const rows: [string, string][] = [["tool", c.tool]];
        if (c.server) rows.push(["server", c.server]);
        if (c.persona) rows.push(["persona", c.persona]);
        rows.push(["status", c.status]);
        if (c.turn != null) rows.push(["turn", `t${c.turn}`]);
        if (c.arg) rows.push(["args", c.arg]);
        if (c.expected) rows.push(["expects", c.expected]);
        return { id: c.id, label: c.tool, server: c.server, persona: c.persona, status: c.status === "ok" ? "ok" : "error", latency: null, rows, body: c.reasoning || c.arg || "" };
      });
}
