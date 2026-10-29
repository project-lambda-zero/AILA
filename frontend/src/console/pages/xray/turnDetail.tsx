import { Suspense } from "react";
import type { ReactNode } from "react";

import { readNum, readStr } from "../../../api/parse";
import type { Message } from "../../../api/types";
import { css } from "../../css";
import { LazyCodeBlock } from "./LazyCode";
import { parseToolFull, type Payload } from "./parsers";
import { argRowStyle, codeHeadStyle, codePreStyle, detLabel, detRowStyle, detVal } from "./theme";

// The expanded body of a turn: tool name + args + a code/text block + key rows,
// keyed off the payload_kind. All fields are the real payload -- nothing faked.
export function turnDetail(m: Message): ReactNode {
  const kind = m.payload_kind || "text";
  const p: Payload = m.payload ?? {};
  const rows: [string, string][] = [];
  let toolName: string | null = null;
  let toolArgs: [string, string][] = [];
  let code: { file: string; lang: string; text: string } | null = null;

  if (kind === "tool_call") {
    const parsed = parseToolFull(p);
    toolName = parsed.tool;
    toolArgs = parsed.args;
    const script = readStr(p, "script_content");
    if (script && script.trim()) code = { file: "script", lang: "python", text: script };
    const exp = readStr(p, "expected_observation");
    if (exp) rows.push(["expects", exp]);
  } else if (kind === "decompiled_function") {
    const fn = readStr(p, "function_name");
    const addr = readStr(p, "address");
    const lang = readStr(p, "language") ?? "text";
    const src = readStr(p, "pseudocode");
    if (src) code = { file: addr ?? fn ?? "function", lang, text: src };
    if (fn) rows.push(["function", fn]);
    if (addr) rows.push(["address", addr]);
    const lc = readNum(p, "line_count");
    if (lc !== null) rows.push(["lines", String(lc)]);
  } else if (kind === "text") {
    const tool = readStr(p, "tool");
    if (tool) rows.push(["tool", tool]);
    const mc = readNum(p, "match_count");
    if (mc !== null) rows.push(["matches", String(mc)]);
    const q = readStr(p, "query");
    if (q) rows.push(["query", q]);
    const chunks = readStr(p, "chunks_text");
    if (chunks && chunks.trim()) code = { file: "results", lang: "text", text: chunks };
  } else if (kind === "xref_view") {
    const target = readStr(p, "target");
    if (target) rows.push(["target", target]);
    const total = readNum(p, "total");
    if (total !== null) rows.push(["xrefs", String(total)]);
    const note = readStr(p, "bridge_note");
    if (note && note.trim()) code = { file: "bridge note", lang: "text", text: note };
  } else if (kind === "taint_flow") {
    const src = readStr(p, "source");
    const tgt = readStr(p, "target");
    if (src) rows.push(["source", src]);
    if (tgt) rows.push(["target", tgt]);
    const total = readNum(p, "total");
    if (total !== null) rows.push(["paths", String(total)]);
  } else if (kind === "outcome_pending") {
    const conf = readStr(p, "confidence");
    if (conf) rows.push(["confidence", conf]);
    const reasoning = readStr(p, "reasoning");
    if (reasoning) rows.push(["reasoning", reasoning]);
  } else if (kind === "outcome_review") {
    const vote = readStr(p, "vote");
    if (vote) rows.push(["vote", vote]);
    const reasoning = readStr(p, "reasoning");
    if (reasoning) rows.push(["reasoning", reasoning]);
  } else if (kind === "poc_script") {
    const lang = readStr(p, "language") ?? "python";
    const st = readStr(p, "status");
    if (st) rows.push(["status", st]);
    const reason = readStr(p, "reason");
    if (reason && reason.trim()) rows.push(["note", reason]);
    const src = readStr(p, "script_content") ?? readStr(p, "code");
    if (src && src.trim()) code = { file: "poc", lang, text: src };
  }

  if (!toolName && !code && rows.length === 0) {
    return null;
  }
  return (
    <div style={css("margin-top:7px;padding-top:7px;border-top:1px solid var(--border-faint);display:flex;flex-direction:column;gap:6px;")}>
      {toolName ? (
        <div style={css("display:flex;align-items:center;gap:7px;padding:3px 7px;background:color-mix(in srgb,var(--status-ok) 9%,transparent);border:1px solid color-mix(in srgb,var(--status-ok) 26%,transparent);")}>
          <span style={css("width:6px;height:6px;background:var(--status-ok);flex:0 0 auto;")} />
          <span style={css("font-size:11px;font-family:var(--font-mono);color:var(--text-primary);word-break:break-all;")}>{toolName}</span>
        </div>
      ) : null}
      {toolArgs.map(([k, v]) => (
        <div key={k} style={argRowStyle}>
          <span style={css("color:var(--text-muted);font-family:var(--font-mono);")}>{k}</span>
          <span style={css("color:var(--text-primary);font-family:var(--font-mono);word-break:break-all;")}>{v}</span>
        </div>
      ))}
      {code ? (
        <div style={css("border:1px solid var(--border-soft);overflow:hidden;")}>
          <div style={codeHeadStyle}>
            <span style={css("font-size:11px;font-family:var(--font-mono);color:var(--text-muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;")}>{code.file}</span>
            <span style={css("font-size:11px;font-family:var(--font-mono);letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);flex:0 0 auto;")}>{code.lang}</span>
          </div>
          {code.lang === "text" ? (
            <pre style={codePreStyle}>{code.text}</pre>
          ) : (
            <Suspense fallback={<pre style={codePreStyle}>{code.text}</pre>}>
              <LazyCodeBlock code={code.text} language={code.lang} />
            </Suspense>
          )}
        </div>
      ) : null}
      {rows.map(([k, v]) => (
        <div key={k} style={detRowStyle}>
          <span style={detLabel}>{k}</span>
          <span style={detVal}>{v}</span>
        </div>
      ))}
    </div>
  );
}
