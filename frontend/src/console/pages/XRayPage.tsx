import {
  lazy,
  Suspense,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ChangeEvent,
  type CSSProperties,
  type JSX,
  type KeyboardEvent,
  type MouseEvent as ReactMouseEvent,
  type ReactNode,
} from "react";

import {
  useBranches,
  useDispatch,
  useGenerateNarrative,
  useHypotheses,
  useInvestigation,
  useInvestigationControl,
  useLedger,
  useMcpCalls,
  useMessages,
  usePostMessage,
  useToggleFavorite,
} from "../../api/hooks";
import { asRecord, readNum, readStr } from "../../api/parse";
import type { Branch, DispatchState, Hypothesis, LedgerRow, McpCall, Message } from "../../api/types";
import type { ModulePageProps } from "../contract";
import { css } from "../css";
import { shortCaseId } from "../ids";
import { ConsoleWindow } from "../window";

// Monaco is heavy; load it only when a code block is actually rendered.
const CodeBlock = lazy(() => import("./CodeBlock"));

/*
 * XRayPage -- faithful port of "VR Investigation - X-Ray.dc.html". A five-layout
 * multi-panel analysis workspace over one VR investigation, switched by the
 * status-bar buttons or number keys 1-5:
 *   1 OVERVIEW -> the multi-agent TURNS stream
 *   2 RECORDS  -> LEDGER + LEDGER ENTRY + HYPOTHESES + HYPOTHESIS
 *   3 GRAPHS   -> DISPATCH HUB node graph + branch lanes
 *   4 ORACLE   -> ORACLE requests + DISPATCH HUB gate + MCP CALLS + DETAIL
 *   5 FINDING  -> FINDING + REACHABILITY + PROOF OF CONCEPT + CRASH
 * Every data-backed panel reads the live /vr investigation, branches,
 * hypotheses and messages API; panels with no backing render honest empty
 * states -- no fabricated verdicts.
 */

const H = {
  acc: "#ff5f87",
  mint: "#97dbbe",
  amber: "#ffb85f",
  lav: "#af87d7",
  sig: "#f0a8c7",
  cream: "#ffd7af",
} as const;

const PERSONA_TONES = [H.mint, H.amber, H.lav, H.sig, H.cream, H.acc] as const;

function personaTone(name: string): string {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
  return PERSONA_TONES[h % PERSONA_TONES.length];
}

const pad2 = (n: number): string => (n < 10 ? "0" : "") + n;

// Ledger / message rows carry an ISO `created_at`. Render it as a compact
// local HH:MM:SS clock for the timeline columns. Empty on a missing or
// unparseable stamp so a bad value degrades to blank, never "Invalid Date".
function clockTime(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
}

function turnType(kind: string): string {
  if (kind === "tool_call") return "tool_run";
  if (kind === "text") return "text";
  if (kind === "outcome_pending" || kind === "outcome_review") return "submit";
  return kind.replace(/_/g, " ");
}

// A tool_call payload's `command` is a JSON string {"tool":..,"args":..}.
function parseTool(payload: Record<string, unknown>): { tool: string | null; arg: string | null } {
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
  const arg = args
    ? readStr(args, "query") ??
      readStr(args, "file_path") ??
      readStr(args, "name") ??
      readStr(args, "target") ??
      readStr(args, "apk_path")
    : null;
  return { tool: readStr(rec, "tool"), arg };
}

// Full tool-call parse -- tool name plus its args object -- for the expanded
// turn detail. The `command` payload field is a JSON string {tool, args}.
function parseToolFull(payload: Record<string, unknown>): { tool: string | null; args: [string, string][] } {
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

function turnProse(m: Message): string {
  const p: Record<string, unknown> = m.payload ?? {};
  const kind = m.payload_kind || "text";
  if (kind === "tool_call") {
    const reason = readStr(p, "reasoning");
    if (reason) return reason;
    const t = parseTool(p).tool;
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

const VIEWS: readonly [id: string, label: string][] = [
  ["overview", "overview"],
  ["records", "records"],
  ["graphs", "graphs"],
  ["oracle", "oracle"],
  ["finding", "finding"],
];
const KEY_TO_VIEW: Record<string, string> = { "1": "overview", "2": "records", "3": "graphs", "4": "oracle", "5": "finding" };
const VIEW_INDEX: Record<string, number> = { overview: 1, records: 2, graphs: 3, oracle: 4, finding: 5 };

// Ordered pane ids per layout -- hjkl/jk cycle focus through these (mock's
// LAYOUTS[*].panes). The overview's brief/records/engine/activity are drawers.
const LAYOUT_PANES: Record<string, string[]> = {
  overview: ["transcript", "brief", "records", "engine", "activity"],
  records: ["ledger", "ldetail", "hypotheses", "hdetail"],
  graphs: ["phasegraph"],
  oracle: ["oracle", "dispatch", "mcp", "detail"],
  finding: ["finding", "reach", "poc", "crash"],
};
const OVERVIEW_DRAWER_SET = new Set(["brief", "records", "engine", "activity"]);
const SHORTCUTS: readonly [string, string][] = [
  ["1 - 5", "switch layout"],
  ["h / k", "focus previous pane"],
  ["l / j", "focus next pane"],
  ["f", "zoom / unzoom focused pane"],
  ["P", "pin / unpin a drawer"],
  ["p", "pause / resume the run"],
  ["?", "toggle this help"],
  ["/  \u00b7  \u2318K", "command palette"],
  ["Esc", "close zoom / help / palette"],
];
// f-key zoom: the focused pane spans the whole grid, the rest collapse.
const PV_HIDE: CSSProperties = { display: "none" };
const PV_ZOOM: CSSProperties = { gridColumn: "1 / -1", gridRow: "1 / -1", zIndex: 3 };

// The overview layout's collapsible drawer columns, in mock order (right of the
// wide turns panel). Each is a 30px vertical title strip that expands on hover.
const OVERVIEW_DRAWERS: readonly string[] = ["brief", "records", "engine", "activity"];

interface PhaseNode {
  id: string;
  label: string;
  stage: "struct" | "recon" | "source" | "binary" | "exploit";
  x: number;
  y: number;
}

// Dispatch-hub phase nodes + topological fixed positions for the GRAPHS view (viewBox 1160x450).
const HUB = { x: 260, y: 220 } as const;
const PHASES: readonly PhaseNode[] = [
  // 1. Structural Orchestration (Left)
  { id: "setup", label: "setup \u00b7 ingest", stage: "struct", x: 30, y: 45 },
  { id: "investigation_ledger", label: "ledger \u00b7 audit", stage: "struct", x: 30, y: 145 },
  { id: "oracle", label: "oracle \u00b7 strategy", stage: "struct", x: 30, y: 245 },
  { id: "emit", label: "emit \u00b7 verdict", stage: "struct", x: 30, y: 345 },

  // 2. Reconnaissance & Discovery (Col 1)
  { id: "recon", label: "recon \u00b7 discovery", stage: "recon", x: 400, y: 45 },
  { id: "variant_hunt", label: "variant_hunt", stage: "recon", x: 400, y: 145 },
  { id: "patch_diff_audit", label: "patch_diff_audit", stage: "recon", x: 400, y: 245 },
  { id: "fuzz_targeting", label: "fuzz_targeting", stage: "recon", x: 400, y: 345 },

  // 3. Source & Semantic Audits (Col 2)
  { id: "source_audit", label: "source_audit", stage: "source", x: 590, y: 45 },
  { id: "taint_analysis", label: "taint_analysis", stage: "source", x: 590, y: 91 },
  { id: "injection_audit", label: "injection_audit", stage: "source", x: 590, y: 137 },
  { id: "deserialization_audit", label: "deserialization", stage: "source", x: 590, y: 183 },
  { id: "auth_bypass_audit", label: "auth_bypass", stage: "source", x: 590, y: 229 },
  { id: "concurrency_audit", label: "concurrency_audit", stage: "source", x: 590, y: 275 },
  { id: "protocol_state_audit", label: "protocol_state", stage: "source", x: 590, y: 321 },
  { id: "dependency_audit", label: "dependency_audit", stage: "source", x: 590, y: 367 },

  // 4. Binary, Memory & Low-Level Audits (Col 3)
  { id: "binary_audit", label: "binary_audit", stage: "binary", x: 780, y: 45 },
  { id: "memory_safety_audit", label: "memory_safety", stage: "binary", x: 780, y: 91 },
  { id: "kernel_driver_audit", label: "kernel_driver", stage: "binary", x: 780, y: 137 },
  { id: "compiler_hardening_audit", label: "hardening_audit", stage: "binary", x: 780, y: 183 },
  { id: "sandbox_escape_audit", label: "sandbox_escape", stage: "binary", x: 780, y: 229 },
  { id: "crypto_audit", label: "crypto_audit", stage: "binary", x: 780, y: 275 },
  { id: "side_channel_audit", label: "side_channel", stage: "binary", x: 780, y: 321 },
  { id: "mobile_audit", label: "mobile_audit", stage: "binary", x: 780, y: 367 },

  // 5. Exploit Synthesis & Verification (Col 4)
  { id: "filter_bypass_synthesis", label: "filter_bypass", stage: "exploit", x: 970, y: 100 },
  { id: "exploit_primitive_composition", label: "exploit_compose", stage: "exploit", x: 970, y: 205 },
  { id: "poc_development", label: "poc_development", stage: "exploit", x: 970, y: 310 },
];

/* ------------------------------ small parts ------------------------------ */

const panelHatch = "height:2px;background-image:repeating-linear-gradient(135deg,var(--border) 0 1px,transparent 1px 3px);";

// WindowPanel -- the design system's load-bearing chrome primitive: an OS-window
// frame with a system-light square, diagonal hatch grips flanking the centered
// title, an optional faint signature, and an optional one-line status footer.
function Panel({
  title,
  tag,
  right,
  actions,
  signature,
  status,
  children,
  focused,
  style,
}: {
  title: string;
  tag?: string;
  right?: ReactNode;
  actions?: ReactNode;
  signature?: string;
  status?: ReactNode;
  children: ReactNode;
  focused?: boolean;
  style?: CSSProperties;
}): JSX.Element {
  return (
    <div
      style={{
        ...css(
          "position:relative;min-height:0;display:flex;flex-direction:column;border:1px solid var(--border);border-radius:var(--radius-md,3px);background:color-mix(in srgb,var(--surface-card) 84%,transparent);overflow:hidden;box-shadow:var(--bevel-raised,inset 1px 1px 0 rgba(255,255,255,0.03));",
        ),
        ...(focused
          ? {
              border: "1px solid var(--accent)",
              boxShadow:
                "0 0 0 1px color-mix(in srgb,var(--accent) 30%,transparent),0 0 24px color-mix(in srgb,var(--accent) 14%,transparent)",
            }
          : {}),
        ...style,
      }}
    >
      <div
        style={css(
          "position:relative;flex:0 0 auto;display:flex;align-items:center;gap:10px;height:var(--panel-title-h,30px);padding:0 12px 0 28px;background:var(--surface-chrome);border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:11px;text-transform:uppercase;letter-spacing:0.14em;color:var(--text-muted);",
        )}
      >
        <span aria-hidden="true" style={css("position:absolute;left:12px;top:50%;transform:translateY(-50%);width:8px;height:8px;border-radius:1px;background:var(--accent);box-shadow:0 0 6px var(--accent);")} />
        <span aria-hidden="true" style={css(panelHatch + "flex:1 1 auto;max-width:64px;")} />
        <span style={css("flex:0 0 auto;color:var(--text-primary);white-space:nowrap;")}>{title}</span>
        {actions}
        <span aria-hidden="true" style={css(panelHatch + "flex:1 1 auto;")} />
        {signature ? (
          <span style={css("flex:0 0 auto;color:var(--text-faint);text-transform:none;letter-spacing:0.06em;")}>{signature}</span>
        ) : null}
        {right}
        {tag ? (
          <span style={css("flex:0 0 auto;font-size:9.5px;letter-spacing:0.06em;color:var(--text-faint);border:1px solid var(--border-soft);padding:1px 6px;border-radius:2px;")}>{tag}</span>
        ) : null}
      </div>
      <div style={css("flex:1;min-height:0;overflow:auto;")}>{children}</div>
      {status ? (
        <div
          style={css(
            "flex:0 0 auto;display:flex;align-items:center;gap:10px;padding:0 14px;height:var(--panel-status-h,25px);border-top:1px solid var(--border-soft);background:var(--surface-chrome);font-family:var(--font-mono);font-size:10.5px;color:var(--text-faint);letter-spacing:0.06em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;",
          )}
        >
          {status}
        </div>
      ) : null}
    </div>
  );
}

const emptyNote = css(
  "padding:20px;font-family:var(--font-mono);font-size:10.5px;color:var(--text-faint);letter-spacing:0.04em;text-align:center;",
);
const kv = css("padding:11px 13px;display:grid;grid-template-columns:96px 1fr;gap:6px 10px;font-size:10.5px;");
const kLabel = css("color:var(--text-faint);letter-spacing:0.06em;");
const kVal = css("color:var(--text-primary);word-break:break-word;");

// Mirrors the VR persona -> role roster in
// src/aila/modules/vr/agents/persona_router.py (persona_role_map). The role
// is an attribute of the persona voice, not the investigation strategy.
const PERSONA_ROLE: Record<string, string> = {
  halvar: "researcher",
  noor: "researcher",
  renzo: "implementer",
  wei: "implementer",
  maddie: "critic",
  yuki: "critic",
};

function personaOf(m: Message, branchMap: Map<string, Branch>): { name: string; role: string; tone: string } {
  const branch = m.branch_id ? branchMap.get(m.branch_id) : undefined;
  // Message-carried persona wins: the branch may be abandoned (completed
  // investigation) and therefore absent from the branch list, so the
  // summary resolves it server-side. Fall back to the branch row, then
  // to sender kind.
  const voice = (m.persona_voice ?? branch?.persona_voice ?? "").toLowerCase();
  const name = (
    m.persona_voice ??
    branch?.persona_voice ??
    (m.sender_kind === "operator" ? "you" : "engine")
  ).toUpperCase();
  const roleRaw = PERSONA_ROLE[voice] ?? branch?.strategy_family ?? m.sender_kind ?? "";
  const role = (roleRaw.split(".").pop() ?? roleRaw).replace(/_/g, " ").toUpperCase();
  return { name, role, tone: personaTone(name) };
}

// A ledger entry's text is sometimes a compact JSON payload (oracle requests
// carry the human sentence under "reason"). Surface that sentence for display;
// leave already-prose text untouched.
function ledgerText(text: string): string {
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

const codeHeadStyle = css(
  "display:flex;align-items:center;justify-content:space-between;gap:8px;padding:3px 8px;background:var(--surface-chrome);border-bottom:1px solid var(--border-soft);",
);
const codePreStyle = css(
  "margin:0;padding:8px 10px;font-family:var(--font-mono);font-size:10px;line-height:1.5;color:var(--text-primary);white-space:pre;overflow:auto;max-height:340px;",
);
const argRowStyle = css("display:grid;grid-template-columns:78px minmax(0,1fr);gap:8px;font-size:9.5px;padding:0 2px;");
const detRowStyle = css("display:grid;grid-template-columns:82px minmax(0,1fr);gap:8px;font-size:9.5px;");
const detLabel = css("color:var(--text-muted);letter-spacing:0.06em;text-transform:uppercase;");
const detVal = css("color:var(--text-primary);word-break:break-word;");

// The expanded body of a turn: tool name + args + a code/text block + key rows,
// keyed off the payload_kind. All fields are the real payload -- nothing faked.
function turnDetail(m: Message): ReactNode {
  const kind = m.payload_kind || "text";
  const p: Record<string, unknown> = m.payload ?? {};
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
          <span style={css("font-size:10.5px;font-family:var(--font-mono);color:var(--text-primary);word-break:break-all;")}>{toolName}</span>
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
            <span style={css("font-size:9px;font-family:var(--font-mono);color:var(--text-muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;")}>{code.file}</span>
            <span style={css("font-size:8.5px;font-family:var(--font-mono);letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);flex:0 0 auto;")}>{code.lang}</span>
          </div>
          {code.lang === "text" ? (
            <pre style={codePreStyle}>{code.text}</pre>
          ) : (
            <Suspense fallback={<pre style={codePreStyle}>{code.text}</pre>}>
              <CodeBlock code={code.text} language={code.lang} />
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

// A labelled, colour-coded slice of an expanded card. The colour + heading
// let the eye separate reasoning from the tool from the output at a glance.
const sectionProse = css(
  "font-family:var(--font-sans,system-ui);font-size:12.5px;line-height:1.62;color:var(--text-primary);text-wrap:pretty;max-width:80ch;white-space:pre-wrap;",
);
function Section({ label, color, children }: { label: string; color: string; children: ReactNode }): JSX.Element {
  return (
    <div style={css(`margin-top:9px;padding:1px 0 3px 10px;border-left:2px solid ${color};`)}>
      <div style={css(`display:flex;align-items:center;gap:6px;margin-bottom:5px;`)}>
        <span style={css(`font-size:8px;font-weight:700;letter-spacing:0.18em;text-transform:uppercase;color:${color};`)}>{label}</span>
        <span aria-hidden="true" style={css(`flex:1;height:1px;background:color-mix(in srgb,${color} 22%,transparent);`)} />
      </div>
      {children}
    </div>
  );
}

// One card = one action + its output: a tool_call plus the result message(s)
// that follow it, or a standalone reasoning / submission message. Collapsed
// shows the action's headline reasoning; expanded splits into REASONING /
// TOOL / OUTPUT sections so the three are visually distinct -- not one wall.
function TurnRow({
  group,
  branchMap,
  open,
  onToggle,
}: {
  group: Message[];
  branchMap: Map<string, Branch>;
  open: boolean;
  onToggle: () => void;
}): JSX.Element {
  const primary = group[0];
  const { name, role, tone } = personaOf(primary, branchMap);
  // A turn is a submission if ANY step is an outcome review / submit; engine
  // turns are the engine's own (no persona). Both get an attention colour --
  // engine lavender, submission mint (the mock's "submit" tone).
  const isSubmit = group.some((s) => turnType(s.payload_kind || "text") === "submit");
  const isEngine = name === "ENGINE";
  const hasTool = group.some((s) => (s.payload_kind || "") === "tool_call");
  const type = isSubmit ? "submit" : hasTool ? "tool run" : turnType(primary.payload_kind || "text");
  // Headline = the first step carrying real prose (usually the tool_call
  // reasoning); tool results often have empty prose.
  const headline = group.map(turnProse).find((t) => t.trim()) || turnProse(primary);
  const turnNo = typeof primary.at_turn === "number" ? `t${primary.at_turn}` : "";
  const cardTone = isEngine ? H.lav : tone;
  const signal = isSubmit ? H.mint : isEngine ? H.lav : tone;
  const badge = isSubmit ? H.mint : isEngine ? H.lav : H.amber;
  const attention = isSubmit || isEngine;
  // Structured split for the expanded card: the action (a tool_call) and its
  // output (the messages after it). Sections are colour-coded so reasoning,
  // tool and output read as three distinct things, not one wash.
  const toolMsg = (primary.payload_kind || "") === "tool_call" ? primary : null;
  const results = toolMsg ? group.slice(1) : group;
  const tp: Record<string, unknown> = toolMsg?.payload ?? {};
  const toolParsed = toolMsg ? parseToolFull(tp) : { tool: null, args: [] as [string, string][] };
  const reasoning = toolMsg ? readStr(tp, "reasoning") ?? "" : "";
  const expects = toolMsg ? readStr(tp, "expected_observation") ?? "" : "";
  const script = toolMsg ? readStr(tp, "script_content") ?? "" : "";
  return (
    <div
      onClick={onToggle}
      style={css(
        `display:flex;flex-direction:column;gap:5px;padding:11px 13px;border-left:${attention ? "3px" : "2px"} solid ${signal};border-bottom:1px solid var(--border-faint);cursor:pointer;${
          attention
            ? `background:color-mix(in srgb,${signal} 8%,transparent);`
            : open
              ? "background:color-mix(in srgb,var(--surface-sunk) 42%,transparent);"
              : ""
        }`,
      )}
    >
      <div style={css("display:flex;align-items:center;gap:8px;")}>
        <span style={css(`width:16px;height:16px;flex:0 0 auto;display:flex;align-items:center;justify-content:center;border-radius:2px;font-size:9px;font-weight:700;color:#0d0d0d;background:${cardTone};`)}>
          {name.charAt(0)}
        </span>
        <span style={css(`font-size:10px;font-weight:700;letter-spacing:0.1em;color:${cardTone};`)}>{name}</span>
        {role && role !== name ? (
          <span style={css("font-size:8.5px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);")}>{role}</span>
        ) : null}
        <span style={css("flex:1;")} />
        {clockTime(primary.created_at) ? (
          <span style={css("font-size:9px;color:var(--text-faint);font-variant-numeric:tabular-nums;letter-spacing:0.04em;")}>{clockTime(primary.created_at)}</span>
        ) : null}
        <span style={css("font-size:9px;color:var(--text-faint);letter-spacing:0.06em;")}>{turnNo}</span>
        <span style={css(`font-size:8px;letter-spacing:0.1em;text-transform:uppercase;padding:1px 6px;border:1px solid ${badge}66;color:${badge};background:${badge}14;border-radius:2px;`)}>{type}</span>
        <span style={css("font-size:9px;color:var(--text-faint);width:10px;text-align:center;flex:0 0 auto;")}>{open ? "\u25be" : "\u25b8"}</span>
      </div>
      {open ? (
        <div style={css("display:flex;flex-direction:column;")}>
          {toolMsg ? (
            <>
              {reasoning.trim() ? (
                <Section label="reasoning" color={H.lav}>
                  <div style={sectionProse}>{reasoning}</div>
                  {expects.trim() ? (
                    <div style={css("margin-top:6px;font-size:11px;line-height:1.5;color:var(--text-muted);")}>
                      <span style={css("font-size:8px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-faint);margin-right:6px;")}>expecting</span>
                      {expects}
                    </div>
                  ) : null}
                </Section>
              ) : null}
              <Section label={toolParsed.tool ? "tool" : "action"} color={H.mint}>
                {toolParsed.tool ? (
                  <div style={css("display:inline-flex;align-items:center;gap:7px;padding:3px 9px;background:color-mix(in srgb,var(--status-ok) 12%,transparent);border:1px solid color-mix(in srgb,var(--status-ok) 32%,transparent);border-radius:2px;")}>
                    <span style={css("width:6px;height:6px;background:var(--status-ok);flex:0 0 auto;border-radius:1px;")} />
                    <span style={css("font-size:11px;font-family:var(--font-mono);color:var(--text-primary);word-break:break-all;")}>{toolParsed.tool}</span>
                  </div>
                ) : null}
                {toolParsed.args.length ? (
                  <div style={css("margin-top:6px;display:flex;flex-direction:column;gap:3px;")}>
                    {toolParsed.args.map(([k, v]) => (
                      <div key={k} style={argRowStyle}>
                        <span style={css("color:var(--text-muted);font-family:var(--font-mono);")}>{k}</span>
                        <span style={css("color:var(--text-primary);font-family:var(--font-mono);word-break:break-all;")}>{v}</span>
                      </div>
                    ))}
                  </div>
                ) : null}
                {script.trim() ? (
                  <div style={css("margin-top:6px;border:1px solid var(--border-soft);overflow:hidden;")}>
                    <Suspense fallback={<pre style={codePreStyle}>{script}</pre>}>
                      <CodeBlock code={script} language="python" />
                    </Suspense>
                  </div>
                ) : null}
              </Section>
              {results.length ? (
                <Section label="output" color={H.amber}>
                  {results.map((m) => {
                    const outText = readStr(m.payload ?? {}, "text") ?? "";
                    return (
                      <div key={m.id} style={css("margin-bottom:7px;")}>
                        {outText.trim() ? (
                          <pre style={css("margin:0 0 6px 0;font-family:var(--font-mono);font-size:11px;line-height:1.55;color:var(--text-primary);white-space:pre-wrap;word-break:break-word;max-width:80ch;")}>{outText}</pre>
                        ) : null}
                        {turnDetail(m)}
                      </div>
                    );
                  })}
                </Section>
              ) : null}
            </>
          ) : (
            group.map((m) => {
              const op = turnProse(m);
              const k = turnType(m.payload_kind || "text");
              return (
                <Section key={m.id} label={k} color={k === "submit" ? H.mint : H.lav}>
                  {op.trim() ? <div style={sectionProse}>{op}</div> : null}
                  {turnDetail(m)}
                </Section>
              );
            })
          )}
        </div>
      ) : (
        <div
          style={css(
            "font-family:var(--font-sans,system-ui);font-size:12.5px;line-height:1.6;color:var(--text-primary);text-wrap:pretty;max-width:80ch;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;",
          )}
        >
          {headline}
        </div>
      )}
    </div>
  );
}

function hypTone(state: string): string {
  const s = state.toLowerCase();
  return s === "live" ? H.mint : s === "rejected" ? H.amber : H.lav;
}

/* ---------------------------------- root ---------------------------------- */

export default function XRayPage(props: ModulePageProps): JSX.Element {
  const { section, investigationId, windowId, title, isFocused, onFocus, onBack, onMinimize, onNavigate, isFullscreen, onToggleFullscreen } = props;
  // section may carry a registry-slug prefix ("xray" from openNamedPage, or a
  // sub-intent like "xray:records"); validate the last segment against the
  // view vocabulary and fall back to the default overview.
  const viewSeg = (section ?? "overview").split(":").pop() ?? "overview";
  const view = VIEW_INDEX[viewSeg] ? viewSeg : "overview";
  const invId = investigationId ?? null;

  const inv = useInvestigation(invId);
  const branches = useBranches(invId);
  const hyps = useHypotheses(invId);
  const msgs = useMessages(invId);
  const post = usePostMessage(invId);
  const dispatch = useDispatch(invId);
  const ledgerRows = useLedger(invId);
  const mcpCallLog = useMcpCalls(invId);
  const control = useInvestigationControl(invId);
  const favorite = useToggleFavorite(invId);
  const narrative = useGenerateNarrative(invId);

  const [steer, setSteer] = useState("");
  const [steerIntent, setSteerIntent] = useState("steering");
  const [clock, setClock] = useState("");
  const [openDrawer, setOpenDrawer] = useState<string | null>(null);
  const [openTurn, setOpenTurn] = useState<string | null>(null);
  const [ledgerSel, setLedgerSel] = useState<LedgerRow | null>(null);
  const [showAudit, setShowAudit] = useState(false);
  const [hypSel, setHypSel] = useState<Hypothesis | null>(null);
  const [detail, setDetail] = useState<{ title: string; rows?: [string, string][]; body?: string } | null>(null);
  const [focus, setFocus] = useState("transcript");
  const [zoom, setZoom] = useState<string | null>(null);
  const [pinned, setPinned] = useState<string[]>([]);
  const [help, setHelp] = useState(false);
  const [palette, setPalette] = useState(false);
  const [palQuery, setPalQuery] = useState("");
  const [palSel, setPalSel] = useState(0);

  useEffect(() => {
    const tick = () => {
      const d = new Date();
      setClock(`${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`);
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  // Keyboard model (mirrors the mock's handleKey): 1-5 switch layout, h/k and
  // l/j move pane focus, f zooms the focused pane, P pins an overview drawer,
  // p pauses / resumes, ? toggles the keymap, Esc closes zoom / help. Refs hold
  // the live values so the window listener registers exactly once.
  const focusRef = useRef(focus);
  const viewRef = useRef(view);
  const navRef = useRef(onNavigate);
  const controlRef = useRef(control);
  const statusRef = useRef("");
  const zoomRef = useRef(zoom);
  const helpRef = useRef(help);
  focusRef.current = focus;
  viewRef.current = view;
  navRef.current = onNavigate;
  controlRef.current = control;
  statusRef.current = (inv.data?.status ?? "").toLowerCase();
  zoomRef.current = zoom;
  helpRef.current = help;

  // Reset pane focus to the first pane whenever the layout changes.
  useEffect(() => {
    const panes = LAYOUT_PANES[view] ?? [];
    setFocus((prev) => (panes.includes(prev) ? prev : panes[0] ?? "transcript"));
    setZoom(null);
  }, [view]);

  useEffect(() => {
    const move = (d: number): void => {
      const panes = LAYOUT_PANES[viewRef.current] ?? [];
      if (!panes.length) return;
      setFocus((prev) => panes[(panes.indexOf(prev) + d + panes.length) % panes.length] ?? prev);
      setZoom(null);
    };
    const onKeyDown = (e: globalThis.KeyboardEvent): void => {
      const tgt = e.target;
      if (
        tgt instanceof HTMLInputElement ||
        tgt instanceof HTMLTextAreaElement ||
        tgt instanceof HTMLSelectElement ||
        (tgt instanceof HTMLElement && tgt.isContentEditable)
      )
        return;
      if ((e.ctrlKey || e.metaKey) && (e.key === "k" || e.key === "K")) {
        e.preventDefault();
        setPalette(true);
        setPalQuery("");
        setPalSel(0);
        return;
      }
      if (e.altKey || e.ctrlKey || e.metaKey) return;
      if (e.key === "Escape") {
        // Only consume Esc when a local overlay owns it; otherwise let it reach
        // the window primitive (which closes the window). Capture phase +
        // stopImmediatePropagation guarantees this handler wins when it fires.
        if (zoomRef.current || helpRef.current) {
          e.preventDefault();
          e.stopImmediatePropagation();
          setZoom(null);
          setHelp(false);
        }
        return;
      }
      if (e.key === "/") {
        e.preventDefault();
        setPalette(true);
        setPalQuery("");
        setPalSel(0);
        return;
      }
      const layout = KEY_TO_VIEW[e.key];
      if (layout) {
        e.preventDefault();
        navRef.current(layout);
        return;
      }
      if (e.key === "l" || e.key === "j") {
        e.preventDefault();
        move(1);
        return;
      }
      if (e.key === "h" || e.key === "k") {
        e.preventDefault();
        move(-1);
        return;
      }
      if (e.key === "f") {
        e.preventDefault();
        setZoom((z) => (z ? null : focusRef.current));
        return;
      }
      if (e.key === "?") {
        e.preventDefault();
        setHelp((h) => !h);
        return;
      }
      if (e.key === "P") {
        e.preventDefault();
        const id = focusRef.current;
        if (viewRef.current === "overview" && OVERVIEW_DRAWER_SET.has(id)) {
          setPinned((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id].slice(-2)));
        }
        return;
      }
      if (e.key === "p") {
        e.preventDefault();
        const st = statusRef.current;
        if (st === "paused") controlRef.current.mutate("resume");
        else if (!["completed", "failed", "cancelled"].includes(st)) controlRef.current.mutate("pause");
        return;
      }
    };
    window.addEventListener("keydown", onKeyDown, true);
    return () => window.removeEventListener("keydown", onKeyDown, true);
  }, []);

  const branchList: Branch[] = branches.data ?? [];
  const branchMap = useMemo(() => {
    const map = new Map<string, Branch>();
    for (const b of branchList) map.set(b.id, b);
    return map;
  }, [branchList]);

  const allMsgs: Message[] = msgs.data ?? [];
  // One card = ONE action + its output. An action is a tool_call; the messages
  // that follow it (its result) belong to the same card, until the next
  // tool_call. A turn with 3 tool_calls becomes 3 readable cards, not one wall.
  // Messages are keyed to a turn by (branch, at_turn), ordered by time within
  // it, then split at each tool_call. Cards are newest-first (live tail).
  const turnGroups: Message[][] = useMemo(() => {
    const turns = new Map<string, Message[]>();
    for (const m of allMsgs) {
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
  }, [allMsgs]);
  // Flat newest-first message stream for the compact "activity" drawer feed.
  const recentMsgs: Message[] = useMemo(
    () => [...allMsgs].sort((a, b) => (b.created_at ?? "").localeCompare(a.created_at ?? "")),
    [allMsgs],
  );

  const mcpCalls = useMemo(
    () =>
      allMsgs
        .filter((m) => m.payload_kind === "tool_call")
        .map((m) => {
          const p = m.payload ?? {};
          const { tool, arg } = parseTool(p);
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
            persona: personaOf(m, branchMap).name,
            status,
            turn: m.at_turn ?? null,
            reasoning: readStr(p, "reasoning") ?? "",
            expected: readStr(p, "expected_observation") ?? "",
          };
        }),
    [allMsgs, branchMap],
  );

  const taintMsgs = useMemo(() => allMsgs.filter((m) => m.payload_kind === "taint_flow"), [allMsgs]);
  // A PoC is an authored exploit script (script_content / code), not decompiled
  // source -- so pseudocode does not qualify.
  const pocMsg = useMemo(
    () =>
      allMsgs.find((m) => {
        const p = m.payload ?? {};
        const code = readStr(p, "script_content") ?? readStr(p, "code");
        if (typeof code !== "string") return false;
        const t = code.trim();
        // A real PoC is a multi-line script, not a placeholder or a one-line
        // tool-call expression.
        return t.length > 20 && !/^(none|n\/a|null|-)$/i.test(t) && t.includes("\n");
      }),
    [allMsgs],
  );
  // A crash artifact is sanitizer/crash output, not a generic tool error.
  const crashMsg = useMemo(
    () => allMsgs.find((m) => /addresssanitizer|use-after-free|heap-(?:use|buffer)|==\d+==\s*error|\bsanitizer\b/i.test(turnProse(m))),
    [allMsgs],
  );

  const hypList: Hypothesis[] = hyps.data ?? [];
  const topHyp = hypList.find((h) => (h.state ?? "").toLowerCase() === "live") ?? hypList[0];
  const liveHyps = hypList.filter((h) => (h.state ?? "").toLowerCase() === "live").length;
  // The engine's draft outcome (answer + confidence + reasoning) drives the
  // finding view; the investigation row carries the ratified verdict head.
  const outcomeMsg = useMemo(() => allMsgs.find((m) => m.payload_kind === "outcome_pending"), [allMsgs]);

  // Real dispatch-hub state (visited / current phases + hub fields), aggregated
  // across the investigation's branch cursors. Node coloring is driven by this,
  // never by a fabricated heuristic.
  const dispatchState: DispatchState | undefined = dispatch.data;
  const visitedSet = useMemo(() => new Set(dispatchState?.visited ?? []), [dispatchState]);
  const currentSet = useMemo(() => new Set(dispatchState?.current ?? []), [dispatchState]);
  // Structural nodes are not gated dispatch phases; infer their state from real
  // signals -- setup/oracle/ledger have run once any branch exists; emit only
  // completes when the investigation does.
  const STRUCTURAL = new Set(["setup", "oracle", "emit", "investigation_ledger"]);
  const invRunning = !["completed", "failed", "cancelled"].includes((inv.data?.status ?? "").toLowerCase());
  const nodeState = (id: string): "active" | "done" | "eligible" => {
    // Only a running investigation has a live "active" phase; a finished run's
    // current_state is just the last phase it reached -> render as done.
    if (invRunning && currentSet.has(id)) return "active";
    if (visitedSet.has(id) || currentSet.has(id)) return "done";
    if (STRUCTURAL.has(id)) {
      if (id === "emit") return invRunning ? "eligible" : "done";
      return branchList.length > 0 ? "done" : "eligible";
    }
    return "eligible";
  };

  // Real append-only investigation ledger; oracle requests are its kind=request
  // rows. MCP call log (with latency) falls back to the tool-call-derived view
  // until the per-investigation endpoint is live.
  const ledgerData: LedgerRow[] = ledgerRows.data ?? [];
  const requestRows = useMemo(() => ledgerData.filter((r) => r.kind === "request"), [ledgerData]);
  // kind=recovery rows are the platform's operator/audit trail (every stale-
  // cursor GC, re-enqueue and crash-heal the resilience layer journals). They
  // are not investigation narrative -- a single reconcile sweep can append
  // hundreds -- so they are split out of the main ledger list and hidden
  // behind a toggle, leaving the discovery / decision / objective narrative
  // legible. See ResilienceLayer.emit_recovery_event.
  const narrativeLedger = useMemo(
    () => ledgerData.filter((r) => r.kind !== "recovery"),
    [ledgerData],
  );
  const auditLedger = useMemo(
    () => ledgerData.filter((r) => r.kind === "recovery"),
    [ledgerData],
  );
  const visibleLedger = showAudit ? ledgerData : narrativeLedger;
  const mcpData: McpCall[] = mcpCallLog.data ?? [];

  const caseId = invId ? shortCaseId("vr", invId) : "--";
  const target = inv.data?.title ?? "investigation";
  const promoted = branchList.filter((b) => b.promoted).length;
  const turnCount = inv.data?.message_count ?? allMsgs.length;

  const doSteer = (): void => {
    const text = steer.trim();
    if (!text || !invId || post.isPending) return;
    post.mutate({ text, intent: steerIntent }, { onSuccess: () => setSteer("") });
  };

  // TURNS-header operator controls, each backed by a real VR endpoint.
  const invStatus = (inv.data?.status ?? "").toLowerCase();
  const isPaused = invStatus === "paused";
  const doExport = (): void => {
    if (!invId) return;
    const blob = new Blob(
      [JSON.stringify({ investigation: inv.data, messages: allMsgs, ledger: ledgerData, dispatch: dispatchState }, null, 2)],
      { type: "application/json" },
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${caseId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };
  const doReset = (): void => {
    if (!invId) return;
    if (window.confirm("Hard-reset this investigation? This permanently deletes all messages, outcomes, and non-root branches. No undo.")) {
      control.mutate("reset");
    }
  };
  const doReenqueue = (): void => {
    if (!invId) return;
    if (window.confirm("Re-enqueue this investigation? Clears all prior cursors, cancels queued/running tasks, and dispatches a fresh run from CREATED. No checkpoint is resumed. No undo.")) {
      control.mutate("re-enqueue");
    }
  };
  // Truthful resume feedback: the resume endpoint reports what it actually
  // did -- restored a checkpoint ("resumed"), no checkpoint so it re-enqueued
  // fresh ("reenqueued"), or nothing could be enqueued ("noop_failed"). Keyed
  // to the most recent control action so a pause/verify/reset does not carry
  // stale resume text.
  const resumeFeedback = ((): { tone: string; text: string } | null => {
    if (control.variables !== "resume" || !control.data?.resume_action) return null;
    if (control.data.resume_action === "resumed") return { tone: H.mint, text: "resumed from checkpoint" };
    if (control.data.resume_action === "reenqueued") return { tone: H.amber, text: "no checkpoint \u2014 re-enqueued fresh" };
    return { tone: H.acc, text: "resume failed \u2014 nothing enqueued" };
  })();
  const ctlBtn = (label: string, onClick: () => void, enabled: boolean): JSX.Element => (
    <button
      type="button"
      onClick={enabled ? onClick : undefined}
      disabled={!enabled}
      style={css(
        `flex:0 0 auto;font-family:var(--font-mono);font-size:10px;letter-spacing:0.08em;text-transform:uppercase;padding:4px 10px;height:26px;border:1px solid var(--border-soft);border-radius:2px;background:transparent;color:var(--text-muted);cursor:${enabled ? "pointer" : "default"};${enabled ? "" : "opacity:0.4;"}`,
      )}
    >
      {label}
    </button>
  );
  const onSteerKey = (e: KeyboardEvent<HTMLInputElement>): void => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      doSteer();
    }
  };

  const grid2 = css("flex:1;min-height:0;display:grid;grid-template-columns:1fr 1fr;grid-template-rows:1fr 1fr;gap:10px;padding:12px;");

  // Per-pane focus ring + zoom style, spread onto each Panel as {...pv(id)}.
  const pv = (id: string): { focused: boolean; style?: CSSProperties } => {
    if (zoom) return zoom === id ? { focused: true, style: PV_ZOOM } : { focused: false, style: PV_HIDE };
    return { focused: focus === id };
  };

  /* -------------------------------- layouts ------------------------------ */

  const loading = inv.isLoading || msgs.isLoading;
  let body: JSX.Element;

  if (!invId) {
    body = <div style={css("flex:1;display:flex;align-items:center;justify-content:center;")}><span style={emptyNote}>no investigation bound &mdash; open one from the console.</span></div>;
  } else if (loading) {
    body = <div style={css("flex:1;display:flex;align-items:center;justify-content:center;")}><span style={emptyNote}>loading investigation&#8230;</span></div>;
  } else if (view === "overview") {
    const d = inv.data;
    const activeBr = branchList.filter((b) => b.status === "active").length;
    const rejectedHyps = hypList.filter((h) => (h.state ?? "").toLowerCase() === "rejected").length;
    const usd = (n: number | null | undefined): string => (typeof n === "number" ? `$${n.toFixed(2)}` : "\u2014");
    // Body of each collapsible overview drawer column.
    const drawerBody = (id: string): ReactNode => {
      if (id === "brief") {
        return (
          <div style={css("padding:11px 13px;display:flex;flex-direction:column;gap:10px;")}>
            <div>
              <div style={css("font-size:9px;letter-spacing:0.12em;text-transform:uppercase;color:var(--accent);")}>prompt</div>
              <div style={css("margin-top:4px;font-family:var(--font-sans,system-ui);font-size:11.5px;line-height:1.45;color:var(--text-primary);text-wrap:pretty;")}>{target}</div>
            </div>
            <div style={kv}>
              <span style={kLabel}>case</span><span style={kVal}>{caseId}</span>
              <span style={kLabel}>kind</span><span style={kVal}>{d?.kind ?? "\u2014"}</span>
              <span style={kLabel}>strategy</span><span style={kVal}>{d?.strategy_family ?? "\u2014"}</span>
              <span style={kLabel}>status</span><span style={kVal}>{d?.status ?? "\u2014"}</span>
              <span style={kLabel}>budget</span><span style={kVal}>{usd(d?.cost_budget_usd)}</span>
              {d?.primary_outcome_verdict_head ? (<><span style={kLabel}>verdict</span><span style={kVal}>{d.primary_outcome_verdict_head.replace(/^#+\s*/, "")}</span></>) : null}
            </div>
          </div>
        );
      }
      if (id === "records") {
        return hypList.length === 0 ? (
          <div style={emptyNote}>no hypotheses filed.</div>
        ) : (
          hypList.map((h) => (
            <div key={h.id} onClick={() => { setHypSel(h); onNavigate("records"); }} style={css("display:flex;align-items:center;gap:8px;padding:6px 11px;border-bottom:1px solid var(--border-faint);cursor:pointer;")}>
              <span style={css("flex:0 0 auto;font-size:8.5px;color:var(--text-faint);")}>{h.id}</span>
              <span style={css("flex:1;min-width:0;font-size:10px;color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;")}>{h.claim}</span>
              <span style={css(`flex:0 0 auto;font-size:8px;letter-spacing:0.08em;text-transform:uppercase;color:${hypTone(h.state)};`)}>{h.state}</span>
            </div>
          ))
        );
      }
      if (id === "engine") {
        return (
          <div style={kv}>
            <span style={kLabel}>loops</span><span style={kVal}>{branchList.length} &#183; {activeBr} active</span>
            <span style={kLabel}>turns</span><span style={kVal}>{turnCount}</span>
            <span style={kLabel}>hypotheses</span><span style={kVal}>{liveHyps} live &#183; {rejectedHyps} rej &#183; {hypList.length} total</span>
            <span style={kLabel}>promoted</span><span style={kVal}>{promoted}</span>
            <span style={kLabel}>budget</span><span style={kVal}>{usd(d?.cost_actual_usd)} / {usd(d?.cost_budget_usd)}</span>
            {d?.primary_outcome_kind ? (<><span style={kLabel}>outcome</span><span style={kVal}>{d.primary_outcome_kind}{d.primary_outcome_confidence ? ` \u00b7 ${d.primary_outcome_confidence}` : ""}</span></>) : null}
            {d?.verifier_verdict ? (<><span style={kLabel}>verifier</span><span style={kVal}>{d.verifier_verdict}{d.verifier_confidence ? ` \u00b7 ${d.verifier_confidence}` : ""}</span></>) : null}
            <span style={kLabel}>auto-pilot</span><span style={kVal}>{d?.auto_pilot ? "on" : "off"}</span>
          </div>
        );
      }
      return recentMsgs.length === 0 ? (
        <div style={emptyNote}>no activity yet.</div>
      ) : (
        recentMsgs.slice(0, 50).map((m) => {
          const pr = personaOf(m, branchMap);
          return (
            <div key={m.id} style={css("display:flex;align-items:center;gap:7px;padding:5px 11px;border-bottom:1px solid var(--border-faint);")}>
              <span style={css(`width:6px;height:6px;flex:0 0 auto;border-radius:1px;background:${pr.tone};`)} />
              <span style={css(`flex:0 0 auto;font-size:8.5px;font-weight:700;color:${pr.tone};`)}>{pr.name}</span>
              <span style={css("flex:1;min-width:0;font-size:9.5px;color:var(--text-muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;")}>{turnProse(m)}</span>
              <span style={css("flex:0 0 auto;font-size:7.5px;letter-spacing:0.06em;text-transform:uppercase;color:var(--text-faint);")}>{turnType(m.payload_kind || "text")}</span>
            </div>
          );
        })
      );
    };
    body = (
      <div style={css("flex:1;min-height:0;display:flex;gap:4px;padding:4px;")}>
        <div style={css("flex:1 1 0;min-width:0;display:flex;flex-direction:column;")}>
          <Panel
            {...pv("transcript")}
            title="turns"
            tag="T"
            actions={
              <div style={css("flex:0 0 auto;display:flex;align-items:center;gap:5px;")}>
                {ctlBtn(isPaused ? "resume" : "pause", () => control.mutate(isPaused ? "resume" : "pause"), (invRunning || isPaused) && !control.isPending)}
                {resumeFeedback ? <span style={css(`font-size:8px;letter-spacing:0.08em;text-transform:uppercase;color:${resumeFeedback.tone};border:1px solid ${resumeFeedback.tone}66;padding:1px 6px;border-radius:2px;`)}>{resumeFeedback.text}</span> : null}
                {ctlBtn("narrative", () => narrative.mutate(), (inv.data?.outcome_count ?? 0) > 0 && !narrative.isPending)}
                {ctlBtn("re-verify", () => control.mutate("verify"), (inv.data?.outcome_count ?? 0) > 0 && !control.isPending)}
                {ctlBtn("export", doExport, allMsgs.length > 0)}
                {ctlBtn("reset", doReset, Boolean(invId) && !control.isPending)}
                <button
                  type="button"
                  onClick={Boolean(invId) && !control.isPending ? doReenqueue : undefined}
                  disabled={!Boolean(invId) || control.isPending}
                  title="Clear all cursors, cancel queued/running tasks, dispatch a fresh run (no checkpoint resume)"
                  style={css(`flex:0 0 auto;font-family:var(--font-mono);font-size:8px;letter-spacing:0.1em;text-transform:uppercase;padding:2px 7px;border:1px solid ${H.acc}88;border-radius:2px;background:transparent;color:${H.acc};cursor:${Boolean(invId) && !control.isPending ? "pointer" : "default"};${Boolean(invId) && !control.isPending ? "" : "opacity:0.4;"}`)}
                >
                  re-enqueue
                </button>
                {control.isPending ? (
                  <span style={css(`font-size:8px;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-faint);border:1px solid var(--border-soft);padding:1px 6px;border-radius:2px;`)}>
                    working{"\u2026"}
                  </span>
                ) : null}
                {control.isError ? (
                  <span style={css(`font-size:8px;letter-spacing:0.08em;text-transform:uppercase;color:${H.acc};border:1px solid ${H.acc}66;padding:1px 6px;border-radius:2px;`)}>
                    {control.error instanceof Error ? control.error.message : "action failed"}
                  </span>
                ) : null}
                {control.isSuccess ? (
                  <span style={css(`font-size:8px;letter-spacing:0.08em;text-transform:uppercase;color:${H.mint};border:1px solid ${H.mint}66;padding:1px 6px;border-radius:2px;`)}>
                    action applied
                  </span>
                ) : null}
              </div>
            }
            right={
              <>
                <span style={css("font-size:9px;color:var(--text-faint);")}>{turnGroups.length} turns</span>
                <button type="button" onClick={() => favorite.mutate()} title="toggle favorite" style={css(`flex:0 0 auto;background:transparent;border:0;padding:0;cursor:pointer;font-size:10px;color:${d?.is_favorite ? H.amber : "var(--text-faint)"};`)}>{d?.is_favorite ? "\u2605" : "\u2606"}</button>
                <span style={css(`font-size:8.5px;letter-spacing:0.1em;text-transform:uppercase;color:${H.mint};border:1px solid ${H.mint}66;padding:1px 6px;border-radius:2px;`)}>live tail</span>
              </>
            }
          >
            {turnGroups.length === 0 ? (
              <div style={css("padding:16px 18px;display:flex;flex-direction:column;gap:14px;")}>
                <div style={css("font-size:11px;line-height:1.6;color:var(--text-muted);")}>
                  No turn-by-turn transcript was recorded for this investigation. Its summary and any ratified outcome are below; the records and finding layouts show what was captured.
                </div>
                <div style={kv}>
                  <span style={kLabel}>case</span><span style={kVal}>{caseId}</span>
                  <span style={kLabel}>target</span><span style={kVal}>{target}</span>
                  <span style={kLabel}>kind</span><span style={kVal}>{d?.kind ?? "\u2014"}</span>
                  <span style={kLabel}>status</span><span style={kVal}>{d?.status ?? "\u2014"}</span>
                  <span style={kLabel}>strategy</span><span style={kVal}>{d?.strategy_family ?? "\u2014"}</span>
                  <span style={kLabel}>branches</span><span style={kVal}>{branchList.length}</span>
                  <span style={kLabel}>hypotheses</span><span style={kVal}>{hypList.length}</span>
                  <span style={kLabel}>outcomes</span><span style={kVal}>{d?.outcome_count ?? 0}</span>
                </div>
                {d?.primary_outcome_verdict_head ? (
                  <div style={css("border-top:1px solid var(--border-faint);padding-top:12px;display:flex;flex-direction:column;gap:8px;")}>
                    <div style={css("display:flex;align-items:center;gap:8px;")}>
                      <span style={css(`font-size:8.5px;letter-spacing:0.1em;text-transform:uppercase;color:${H.acc};border:1px solid ${H.acc}66;padding:1px 6px;border-radius:2px;`)}>{(d.primary_outcome_kind ?? "outcome").replace(/_/g, " ")}</span>
                      {d.primary_outcome_confidence ? <span style={css(`font-size:8.5px;letter-spacing:0.1em;text-transform:uppercase;color:${H.amber};`)}>{d.primary_outcome_confidence}</span> : null}
                    </div>
                    <div style={css("font-family:var(--font-sans,system-ui);font-size:13px;line-height:1.5;color:var(--text-primary);")}>{d.primary_outcome_verdict_head.replace(/^#+\s*/, "")}</div>
                  </div>
                ) : null}
              </div>
            ) : (
              turnGroups.map((g) => {
                const key = g[0].id;
                return (
                  <TurnRow
                    key={key}
                    group={g}
                    branchMap={branchMap}
                    open={openTurn === key}
                    onToggle={() => setOpenTurn((cur) => (cur === key ? null : key))}
                  />
                );
              })
            )}
          </Panel>
        </div>
        {OVERVIEW_DRAWERS.map((id) => {
          // A drawer opens on hover, when pane focus lands on it (hjkl), or when
          // it is pinned (P / the pin button). Focus rings it in accent, a pin
          // rings it in signal -- mirroring the mock's foc / pin outlines.
          const drawerFocused = focus === id;
          const drawerPinned = pinned.includes(id);
          const open = openDrawer === id || drawerFocused || drawerPinned;
          const ring = drawerFocused ? "var(--accent)" : drawerPinned ? H.sig : open ? "var(--border)" : "var(--border-soft)";
          const glow = drawerFocused
            ? "box-shadow:0 0 0 1px color-mix(in srgb,var(--accent) 30%,transparent),0 0 20px color-mix(in srgb,var(--accent) 12%,transparent);"
            : drawerPinned
              ? `box-shadow:0 0 0 1px color-mix(in srgb,${H.sig} 34%,transparent);`
              : "";
          const togglePin = (e: ReactMouseEvent): void => {
            e.stopPropagation();
            setPinned((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id].slice(-2)));
          };
          return (
            <div
              key={id}
              onMouseEnter={() => setOpenDrawer(id)}
              onMouseLeave={() => setOpenDrawer((cur) => (cur === id ? null : cur))}
              onClick={() => { setOpenDrawer(id); setFocus(id); }}
              style={css(
                `flex:${open ? "0 0 320px" : "0 0 30px"};min-width:0;display:flex;flex-direction:column;border:1px solid ${ring};border-radius:3px;background:color-mix(in srgb,var(--surface-card) 84%,transparent);overflow:hidden;cursor:pointer;transition:flex-basis 220ms cubic-bezier(0.22,1,0.36,1);${glow}`,
              )}
            >
              {open ? (
                <>
                  <div style={css("flex:0 0 auto;display:flex;align-items:center;gap:8px;padding:6px 10px;background:var(--surface-chrome);border-bottom:1px solid var(--border);")}>
                    <span style={css(`width:6px;height:6px;background:${drawerFocused ? "var(--accent)" : drawerPinned ? H.sig : "var(--accent)"};box-shadow:0 0 6px var(--accent);flex:0 0 auto;`)} />
                    <span style={css("font-size:9.5px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-primary);")}>{id}</span>
                    <span style={css("flex:1;")} />
                    <button
                      type="button"
                      onClick={togglePin}
                      title={drawerPinned ? "unpin (P)" : "pin (P)"}
                      style={css(`flex:0 0 auto;background:transparent;border:1px solid ${drawerPinned ? H.sig : "var(--border-soft)"};color:${drawerPinned ? H.sig : "var(--text-faint)"};font-family:var(--font-mono);font-size:8px;letter-spacing:0.1em;text-transform:uppercase;padding:1px 6px;border-radius:2px;cursor:pointer;`)}
                    >
                      {drawerPinned ? "pinned" : "pin"}
                    </button>
                  </div>
                  <div style={css("flex:1;min-height:0;overflow:auto;")}>{drawerBody(id)}</div>
                </>
              ) : (
                <div style={css("flex:1;min-width:0;display:flex;align-items:center;justify-content:flex-start;gap:9px;writing-mode:vertical-rl;text-orientation:mixed;padding:9px 0;font-size:10px;letter-spacing:0.16em;text-transform:uppercase;white-space:nowrap;overflow:hidden;background:var(--surface-chrome);color:var(--text-muted);")}>
                  <span style={css("width:6px;height:6px;background:var(--accent);flex:0 0 auto;")} />
                  {id}
                </div>
              )}
            </div>
          );
        })}
      </div>
    );
  } else if (view === "records") {
    body = (
      <div style={grid2}>
        <Panel {...pv("ledger")} title="ledger" tag="L" signature="append-only" right={
          <span style={css("display:flex;align-items:center;gap:8px;font-size:9px;color:var(--text-faint);")}>
            <span>{narrativeLedger.length} entries</span>
            {auditLedger.length > 0 ? (
              <span
                onClick={(ev) => { ev.stopPropagation(); setShowAudit((v) => !v); }}
                style={css(`cursor:pointer;padding:1px 6px;border-radius:2px;letter-spacing:0.06em;text-transform:uppercase;border:1px solid ${showAudit ? H.amber + "88" : "var(--border-faint)"};color:${showAudit ? H.amber : "var(--text-faint)"};`)}
                title={showAudit ? "hide recovery / audit events" : "show recovery / audit events"}
              >{auditLedger.length} audit</span>
            ) : null}
          </span>
        }>
          {visibleLedger.length === 0 ? (
            <div style={emptyNote}>
              {auditLedger.length > 0
                ? `no narrative ledger entries yet - ${auditLedger.length} recovery/audit events hidden (use the "audit" toggle above).`
                : "no ledger entries yet - append-only."}
            </div>
          ) : (
            visibleLedger.map((e) => {
              const who = (branchMap.get(e.author_branch_id ?? "")?.persona_voice ?? "").toUpperCase();
              const isAudit = e.kind === "recovery";
              return (
                <div
                  key={e.id}
                  onClick={() => setLedgerSel(e)}
                  style={css(`display:flex;align-items:center;gap:9px;padding:7px 11px;border-bottom:1px solid var(--border-faint);cursor:pointer;${isAudit ? "opacity:0.55;" : ""}${ledgerSel?.id === e.id ? "background:color-mix(in srgb,var(--accent) 8%,transparent);" : ""}`)}
                >
                  <span style={css("flex:0 0 auto;min-width:52px;font-size:8.5px;font-variant-numeric:tabular-nums;color:var(--text-faint);")}>{clockTime(e.created_at) || "\u2014"}</span>
                  <span style={css(`flex:0 0 auto;font-size:8px;letter-spacing:0.08em;text-transform:uppercase;min-width:64px;color:${e.kind === "request" ? H.lav : e.kind === "decision" ? H.mint : e.kind === "objective" ? H.amber : isAudit ? "var(--text-faint)" : H.cream};`)}>{e.intent ? e.intent.replace(/_/g, " ") : e.kind}</span>
                  <span style={css(`flex:0 0 auto;min-width:50px;font-size:8.5px;font-weight:700;letter-spacing:0.06em;color:${who ? personaTone(who) : "var(--text-faint)"};`)}>{who || "\u2014"}</span>
                  <span style={css("flex:1;min-width:0;font-size:11px;color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;")}>{ledgerText(e.text)}</span>
                  {e.status ? <span style={css("flex:0 0 auto;font-size:8px;letter-spacing:0.06em;text-transform:uppercase;color:var(--text-faint);")}>{e.status}</span> : null}
                </div>
              );
            })
          )}
        </Panel>
        <Panel {...pv("ldetail")} title="ledger entry" tag="E" signature="in plain terms">
          {ledgerSel ? (
            <div style={kv}>
              <span style={kLabel}>kind</span><span style={kVal}>{ledgerSel.kind}</span>
              {ledgerSel.created_at ? (<><span style={kLabel}>when</span><span style={kVal}>{clockTime(ledgerSel.created_at) || ledgerSel.created_at}</span></>) : null}
              {ledgerSel.intent ? (<><span style={kLabel}>intent</span><span style={kVal}>{ledgerSel.intent.replace(/_/g, " ")}</span></>) : null}
              <span style={kLabel}>by</span><span style={css(`color:${personaTone((branchMap.get(ledgerSel.author_branch_id ?? "")?.persona_voice ?? "").toUpperCase())};font-weight:700;letter-spacing:0.06em;`)}>{(branchMap.get(ledgerSel.author_branch_id ?? "")?.persona_voice ?? "unknown").toUpperCase()}</span>
              {ledgerSel.owner_branch_id ? (<><span style={kLabel}>owner</span><span style={kVal}>{(branchMap.get(ledgerSel.owner_branch_id)?.persona_voice ?? ledgerSel.owner_branch_id).toUpperCase()}</span></>) : null}
              {ledgerSel.objective_key ? (<><span style={kLabel}>objective</span><span style={kVal}>{ledgerSel.objective_key}</span></>) : null}
              {ledgerSel.target_capability ? (<><span style={kLabel}>capability</span><span style={kVal}>{ledgerSel.target_capability}</span></>) : null}
              {ledgerSel.status ? (<><span style={kLabel}>status</span><span style={kVal}>{ledgerSel.status}</span></>) : null}
              <span style={kLabel}>text</span><span style={kVal}>{ledgerText(ledgerSel.text)}</span>
            </div>
          ) : (
            <div style={css("padding:13px;")}>
              <div style={css("font-size:11px;color:var(--text-muted);")}>Select an entry on the left.</div>
              <div style={css("margin-top:11px;")}>
                <div style={kv}>
                  <span style={kLabel}>entries</span><span style={kVal}>{narrativeLedger.length} narrative, {auditLedger.length} audit</span>
                  <span style={kLabel}>kinds</span><span style={kVal}>discovery, request, decision, objective, note, recovery</span>
                </div>
              </div>
            </div>
          )}
        </Panel>
        <Panel {...pv("hypotheses")} title="hypotheses" tag="H" signature="held privately" right={<span style={css("font-size:9px;color:var(--text-faint);")}>{liveHyps} live</span>}>
          {hypList.length === 0 ? (
            <div style={emptyNote}>no hypotheses filed yet.</div>
          ) : (
            hypList.map((h) => (
              <div
                key={h.id}
                onClick={() => setHypSel(h)}
                style={css(`display:flex;align-items:center;gap:9px;padding:8px 11px;border-bottom:1px solid var(--border-faint);cursor:pointer;${hypSel?.id === h.id ? "background:color-mix(in srgb,var(--accent) 8%,transparent);" : ""}`)}
              >
                <span style={css("flex:1;min-width:0;font-size:11px;color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;")}>{h.claim}</span>
                <span style={css(`flex:0 0 auto;font-size:8px;letter-spacing:0.1em;text-transform:uppercase;color:${hypTone(h.state)};`)}>{h.state}</span>
              </div>
            ))
          )}
        </Panel>
        <Panel {...pv("hdetail")} title="hypothesis" tag="Y" signature="in plain terms">
          {hypSel ? (
            <div style={kv}>
              <span style={kLabel}>state</span><span style={css(`color:${hypTone(hypSel.state)};text-transform:uppercase;letter-spacing:0.08em;`)}>{hypSel.state}</span>
              <span style={kLabel}>claim</span><span style={kVal}>{hypSel.claim}</span>
              {hypSel.why_plausible ? (<><span style={kLabel}>why plausible</span><span style={kVal}>{hypSel.why_plausible}</span></>) : null}
              {hypSel.kill_criterion ? (<><span style={kLabel}>kill criterion</span><span style={kVal}>{hypSel.kill_criterion}</span></>) : null}
              {hypSel.rejection_reason ? (<><span style={kLabel}>why rejected</span><span style={kVal}>{hypSel.rejection_reason}</span></>) : null}
              {hypSel.resolution_note ? (<><span style={kLabel}>resolution</span><span style={kVal}>{hypSel.resolution_note}</span></>) : null}
              {(() => {
                const ids = [...(hypSel.live_in_branches ?? []), ...(hypSel.rejected_in_branches ?? []), ...(hypSel.resolved_in_branches ?? [])];
                const who = [...new Set(ids)].map((x) => (branchMap.get(x)?.persona_voice ?? x).toUpperCase()).join(", ");
                return who ? (<><span style={kLabel}>held by</span><span style={kVal}>{who}</span></>) : null;
              })()}
            </div>
          ) : (
            <div style={css("padding:13px;")}>
              <div style={css("font-size:11px;color:var(--text-muted);")}>Select a hypothesis on the left.</div>
              <div style={kv}>
                <span style={kLabel}>states</span><span style={kVal}>live, rejected, resolved</span>
                <span style={kLabel}>held by</span><span style={kVal}>each branch privately</span>
              </div>
            </div>
          )}
        </Panel>
      </div>
    );
  } else if (view === "graphs") {
    body = (
      <div style={css("flex:1;min-height:0;display:flex;flex-direction:column;padding:12px;gap:10px;")}>
        <Panel {...pv("phasegraph")} title="dispatch hub · vr.investigate.hub" tag="3" signature="phase graph">
          <div style={css("display:flex;flex-direction:column;height:100%;min-height:0;overflow:hidden;")}>
            <svg viewBox="0 0 1160 420" preserveAspectRatio="xMidYMid meet" style={{ width: "100%", height: "100%", flex: 1, minHeight: 0, background: "#0a0a0a" }}>
              {/* Category Column Headers */}
              <text x={100} y={20} fill="#555" fontSize={8.5} fontFamily="var(--font-mono, monospace)" letterSpacing="0.1em" textAnchor="middle">ORCHESTRATION</text>
              <text x={470} y={20} fill="#555" fontSize={8.5} fontFamily="var(--font-mono, monospace)" letterSpacing="0.1em" textAnchor="middle">RECON &amp; DISCOVERY</text>
              <text x={660} y={20} fill="#555" fontSize={8.5} fontFamily="var(--font-mono, monospace)" letterSpacing="0.1em" textAnchor="middle">SOURCE &amp; SEMANTIC</text>
              <text x={850} y={20} fill="#555" fontSize={8.5} fontFamily="var(--font-mono, monospace)" letterSpacing="0.1em" textAnchor="middle">BINARY &amp; MEMORY</text>
              <text x={1040} y={20} fill="#555" fontSize={8.5} fontFamily="var(--font-mono, monospace)" letterSpacing="0.1em" textAnchor="middle">SYNTHESIS &amp; POC</text>

              {/* Column Separator Guides */}
              <line x1={180} y1={25} x2={180} y2={405} stroke="#181818" strokeDasharray="2 4" />
              <line x1={360} y1={25} x2={360} y2={405} stroke="#181818" strokeDasharray="2 4" />
              <line x1={560} y1={25} x2={560} y2={405} stroke="#181818" strokeDasharray="2 4" />
              <line x1={750} y1={25} x2={750} y2={405} stroke="#181818" strokeDasharray="2 4" />
              <line x1={940} y1={25} x2={940} y2={405} stroke="#181818" strokeDasharray="2 4" />

              {/* Hub to Node Edges */}
              {PHASES.map((p) => {
                const st = nodeState(p.id);
                const col = st === "active" ? H.mint : st === "done" ? H.cream : "#252525";
                const targetX = p.x < HUB.x ? p.x + 140 : p.x;
                const targetY = p.y + 11;
                return (
                  <line
                    key={`l-${p.id}`}
                    x1={HUB.x}
                    y1={HUB.y}
                    x2={targetX}
                    y2={targetY}
                    stroke={col}
                    strokeWidth={st === "active" ? 2 : 1}
                    strokeDasharray={st === "eligible" ? "3 3" : "0"}
                    opacity={st === "eligible" ? 0.4 : 0.85}
                  />
                );
              })}

              {/* Central Dispatch Hub */}
              <g>
                <rect x={HUB.x - 65} y={HUB.y - 17} width={130} height={34} rx={4} fill="#141414" stroke={H.acc} strokeWidth={1.8} />
                <text x={HUB.x} y={HUB.y + 4} fill={H.acc} fontSize={10} fontFamily="var(--font-mono, monospace)" fontWeight="700" textAnchor="middle">vr.investigate.hub</text>
              </g>

              {/* Phase Nodes */}
              {PHASES.map((p) => {
                const st = nodeState(p.id);
                const col = st === "active" ? H.mint : st === "done" ? H.cream : "#333";
                const fill = st === "active" ? "#102218" : st === "done" ? "#181812" : "#0f0f0f";
                const txt = st === "eligible" ? "var(--text-faint)" : col;
                return (
                  <g key={p.id}>
                    <rect
                      x={p.x}
                      y={p.y}
                      width={140}
                      height={22}
                      rx={3}
                      fill={fill}
                      stroke={col}
                      strokeWidth={st === "active" ? 1.8 : 1}
                      strokeDasharray={st === "eligible" ? "3 3" : "0"}
                    />
                    <text
                      x={p.x + 70}
                      y={p.y + 14}
                      fill={txt}
                      fontSize={8.5}
                      fontFamily="var(--font-mono, monospace)"
                      textAnchor="middle"
                    >
                      {p.label}
                    </text>
                  </g>
                );
              })}
            </svg>
            <div style={css("flex:0 0 auto;display:flex;gap:16px;padding:8px 12px;border-top:1px solid var(--border-soft);font-size:8.5px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);")}>
              {([["active", H.mint], ["done", H.cream], ["eligible", "#3a3a3a"], ["gated", H.amber], ["blocked", H.acc]] as const).map(([lbl, c]) => (
                <span key={lbl} style={css("display:flex;align-items:center;gap:5px;")}>
                  <span style={css(`width:7px;height:7px;background:${c};border-radius:1px;`)} />{lbl}
                </span>
              ))}
            </div>
          </div>
        </Panel>
        <div style={css("flex:0 0 auto;display:flex;flex-direction:column;gap:6px;")}>
          <div style={css("font-size:9px;letter-spacing:0.16em;text-transform:uppercase;color:var(--text-muted);")}>branch lanes ({branchList.length})</div>
          {branchList.length === 0 ? (
            <div style={css("font-size:10.5px;color:var(--text-faint);padding:4px 0;")}>no branches spawned yet.</div>
          ) : (
            branchList.map((b) => {
              const name = (b.persona_voice ?? "branch").toUpperCase();
              const role = PERSONA_ROLE[(b.persona_voice ?? "").toLowerCase()] ?? (b.strategy_family ?? "").split(".").pop() ?? "";
              return (
                <div key={b.id} style={css("display:flex;align-items:center;gap:10px;padding:7px 11px;border:1px solid var(--border-soft);border-radius:3px;background:var(--surface-card);")}>
                  <span style={css(`width:8px;height:8px;flex:0 0 auto;border-radius:1px;background:${b.promoted ? H.mint : personaTone(name)};`)} />
                  <span style={css(`font-size:11px;font-weight:700;letter-spacing:0.08em;color:${personaTone(name)};`)}>{name}</span>
                  <span style={css("font-size:10px;color:var(--text-faint);")}>{role}</span>
                  <span style={css("flex:1;")} />
                  <span style={css("font-size:9.5px;color:var(--text-muted);")}>{b.turn_count ?? 0} turns</span>
                  <span style={css("font-size:8.5px;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-faint);")}>{b.status}</span>
                </div>
              );
            })
          )}
        </div>
      </div>
    );
  } else if (view === "oracle") {
    const activePhase = dispatchState?.current?.[0] ?? dispatchState?.last ?? null;
    const mcpDisplay: { id: string; label: string; server: string | null; persona: string; status: string; latency: number | null; rows: [string, string][]; body: string }[] =
      mcpData.length > 0
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
        : mcpCalls.map((c) => {
            const rows: [string, string][] = [["tool", c.tool]];
            if (c.server) rows.push(["server", c.server]);
            if (c.persona) rows.push(["persona", c.persona]);
            rows.push(["status", c.status]);
            if (c.turn != null) rows.push(["turn", `t${c.turn}`]);
            if (c.arg) rows.push(["args", c.arg]);
            if (c.expected) rows.push(["expects", c.expected]);
            return { id: c.id, label: c.tool, server: c.server, persona: c.persona, status: c.status === "ok" ? "ok" : "error", latency: null, rows, body: c.reasoning || c.arg || "" };
          });
    body = (
      <div style={grid2}>
        <Panel {...pv("oracle")} title="oracle" tag="R" signature="ledger coordinator" right={<span style={css("font-size:9px;color:var(--text-faint);")}>{requestRows.length}</span>}>
          {requestRows.length === 0 ? (
            <div style={emptyNote}>no governance requests filed.</div>
          ) : (
            requestRows.map((r) => {
              const author = (branchMap.get(r.author_branch_id ?? "")?.persona_voice ?? "").toUpperCase();
              const intent = (r.intent ?? "request").replace(/_/g, " ").toUpperCase();
              const ratified = ["ratified", "applied"].includes((r.status ?? "").toLowerCase());
              return (
                <div key={r.id} onClick={() => setDetail({ title: `req #${r.id} \u00b7 ${intent}`, body: ledgerText(r.text) })} style={css("padding:8px 11px;border-bottom:1px solid var(--border-faint);cursor:pointer;")}>
                  <div style={css("display:flex;align-items:center;gap:8px;flex-wrap:wrap;")}>
                    <span style={css("font-size:9px;color:var(--text-faint);")}>req #{r.id}</span>
                    <span style={css(`font-size:8px;letter-spacing:0.1em;text-transform:uppercase;color:${H.lav};border:1px solid ${H.lav}66;padding:1px 6px;border-radius:2px;`)}>{intent}</span>
                    <span style={css("flex:1;")} />
                    {r.status ? <span style={css(`font-size:8px;letter-spacing:0.1em;text-transform:uppercase;color:${ratified ? H.mint : H.amber};`)}>{r.status}</span> : null}
                  </div>
                  <div style={css("margin-top:4px;display:grid;grid-template-columns:auto 1fr;gap:2px 10px;font-size:9.5px;")}>
                    {author ? (<><span style={css("color:var(--text-faint);")}>author</span><span style={css(`color:${personaTone(author)};`)}>{author}</span></>) : null}
                    {r.target_capability ? (<><span style={css("color:var(--text-faint);")}>capability</span><span style={css("color:var(--text-primary);")}>{r.target_capability}</span></>) : null}
                    {r.objective_key ? (<><span style={css("color:var(--text-faint);")}>objective</span><span style={css("color:var(--text-primary);")}>{r.objective_key}</span></>) : null}
                  </div>
                  <div style={css("margin-top:4px;font-size:10px;color:var(--text-muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;")}>{ledgerText(r.text)}</div>
                </div>
              );
            })
          )}
        </Panel>
        <Panel {...pv("dispatch")} title="dispatch hub" tag="D" signature="gate + hub state">
          <div style={kv}>
            <span style={kLabel}>active phase</span><span style={kVal}>{activePhase ?? "\u2014"}</span>
          </div>
          <div style={css("padding:0 13px 8px;font-size:9px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-muted);")}>gate evaluation</div>
          {dispatchState && dispatchState.phases.length > 0 ? (
            dispatchState.phases.map((p) => {
              const st = nodeState(p.id);
              const col = st === "active" ? H.mint : st === "done" ? H.cream : "#3a3a3a";
              return (
                <div key={p.id} style={css("display:flex;align-items:center;gap:9px;padding:4px 13px;font-size:10px;")}>
                  <span style={css(`width:6px;height:6px;flex:0 0 auto;border-radius:1px;background:${col};`)} />
                  <span style={css("color:var(--text-primary);")}>{p.id}</span>
                  {p.capability ? <span style={css("font-size:8.5px;color:var(--text-faint);")}>{p.capability}</span> : null}
                  <span style={css("flex:1;")} />
                  {p.trust ? <span style={css("font-size:8px;letter-spacing:0.06em;text-transform:uppercase;color:var(--text-faint);")}>{p.trust}</span> : null}
                  <span style={css(`color:${st === "eligible" ? "var(--text-faint)" : col};font-size:8.5px;letter-spacing:0.08em;text-transform:uppercase;`)}>{st === "done" ? "visited" : st}</span>
                </div>
              );
            })
          ) : (
            <div style={emptyNote}>dispatch state unavailable.</div>
          )}
          {dispatchState ? (
            <>
              <div style={css("padding:8px 13px 6px;margin-top:4px;border-top:1px solid var(--border-faint);font-size:9px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-muted);")}>hub state</div>
              <div style={kv}>
                <span style={kLabel}>visited</span><span style={kVal}>{dispatchState.visited.length ? dispatchState.visited.join(", ") : "\u2014"}</span>
                <span style={kLabel}>last</span><span style={kVal}>{dispatchState.last ?? "\u2014"}</span>
                {dispatchState.reason ? (<><span style={kLabel}>reason</span><span style={kVal}>{dispatchState.reason}</span></>) : null}
                <span style={kLabel}>phase trust</span><span style={kVal}>{dispatchState.phase_trust ?? "\u2014"}</span>
                <span style={kLabel}>replan relax</span><span style={kVal}>{dispatchState.replan_relax ? "true" : "false"}</span>
                <span style={kLabel}>budget</span><span style={kVal}>{dispatchState.budget_exhausted ? "exhausted" : "ok"}</span>
              </div>
            </>
          ) : null}
        </Panel>
        <Panel {...pv("mcp")} title="mcp calls" tag="M" signature="provider · persona" right={<span style={css("font-size:9px;color:var(--text-faint);")}>{mcpDisplay.length}</span>}>
          {mcpDisplay.length === 0 ? (
            <div style={emptyNote}>no mcp calls yet.</div>
          ) : (
            mcpDisplay.map((c) => {
              const stCol = c.status === "ok" ? H.mint : c.status === "pending" ? H.amber : H.acc;
              return (
                <div key={c.id} onClick={() => setDetail({ title: c.label, rows: c.rows, body: c.body })} style={css("display:flex;align-items:center;gap:8px;padding:6px 11px;border-bottom:1px solid var(--border-faint);cursor:pointer;")}>
                  <span style={css(`flex:0 0 auto;font-size:8px;letter-spacing:0.08em;text-transform:uppercase;padding:1px 5px;border-radius:2px;color:${stCol};border:1px solid ${stCol}66;`)}>{c.status}</span>
                  <span style={css("flex:1;min-width:0;font-size:10.5px;color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;")}>{c.label}</span>
                  {c.latency !== null ? <span style={css("flex:0 0 auto;font-size:8.5px;color:var(--text-faint);")}>{c.latency}ms</span> : null}
                  {c.server ? <span style={css("flex:0 0 auto;font-size:8px;letter-spacing:0.04em;color:var(--text-faint);")}>{c.server}</span> : null}
                  {c.persona ? <span style={css(`flex:0 0 auto;font-size:8.5px;color:${personaTone(c.persona)};`)}>{c.persona}</span> : null}
                </div>
              );
            })
          )}
        </Panel>
        <Panel {...pv("detail")} title="detail" tag="D" signature="click any row">
          {detail ? (
            <div style={kv}>
              <span style={kLabel}>item</span><span style={kVal}>{detail.title}</span>
              {(detail.rows ?? []).map(([k, v]) => (
                <span key={k} style={{ display: "contents" }}><span style={kLabel}>{k}</span><span style={kVal}>{v}</span></span>
              ))}
              {detail.body ? (<><span style={kLabel}>detail</span><span style={kVal}>{detail.body}</span></>) : null}
            </div>
          ) : (
            <div style={css("padding:13px;font-size:11px;color:var(--text-muted);line-height:1.5;")}>
              Nothing selected.
              <div style={css("margin-top:8px;font-size:10px;color:var(--text-faint);")}>Click any ledger row, hypothesis or MCP call. The record opens here &mdash; a pane, never a modal.</div>
            </div>
          )}
        </Panel>
      </div>
    );
  } else if (view === "finding") {
    const d = inv.data;
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
    body = (
      <div style={grid2}>
        <Panel {...pv("finding")} title="finding" tag="F" signature="the artifact">
          {hasFinding ? (
            <div style={css("padding:13px;display:flex;flex-direction:column;gap:9px;")}>
              <div style={css("display:flex;align-items:center;gap:8px;flex-wrap:wrap;")}>
                <span style={css(`font-size:8.5px;letter-spacing:0.1em;text-transform:uppercase;color:${H.acc};border:1px solid ${H.acc}66;padding:1px 6px;border-radius:2px;`)}>{(d?.primary_outcome_kind ?? "direct_finding").replace(/_/g, " ")}</span>
                {d?.primary_outcome_confidence ? (
                  <span style={css(`font-size:8.5px;letter-spacing:0.1em;text-transform:uppercase;color:${H.amber};`)}>{d.primary_outcome_confidence}</span>
                ) : (
                  <span style={css(`font-size:8.5px;letter-spacing:0.1em;text-transform:uppercase;color:${H.lav};`)}>{sev}</span>
                )}
                {d?.primary_outcome_polarity ? (
                  <span style={css("font-size:8.5px;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-faint);")}>{d.primary_outcome_polarity}</span>
                ) : null}
                <span style={css("flex:1;")} />
                <span style={css("font-size:9.5px;color:var(--text-faint);")}>{caseId}-F1</span>
              </div>
              <div style={css("font-family:var(--font-sans,system-ui);font-size:13px;line-height:1.5;color:var(--text-primary);")}>{headline || "\u2014"}</div>
              {bodyText ? (
                <div style={css("font-size:11.5px;line-height:1.55;color:var(--text-muted);")}>{bodyText}</div>
              ) : topHyp?.why_plausible ? (
                <div style={css("font-size:11.5px;line-height:1.5;color:var(--text-muted);")}>{topHyp.why_plausible}</div>
              ) : null}
              {reasoning ? (
                <div style={css("font-size:10.5px;line-height:1.5;color:var(--text-faint);border-top:1px solid var(--border-faint);padding-top:8px;")}>{reasoning}</div>
              ) : null}
              <div style={css("margin-top:4px;font-size:9px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);")}>{(d?.status ?? "").toLowerCase() === "completed" ? `${d?.outcome_count ?? 1} outcome ratified` : "draft \u00b7 awaiting quorum"}</div>
            </div>
          ) : (
            <div style={emptyNote}>no finding drafted yet.</div>
          )}
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
          {pocMsg ? (
            <div style={css("padding:8px;")}>
              <Suspense fallback={<div style={emptyNote}>loading editor&#8230;</div>}>
                <CodeBlock
                  code={readStr(pocMsg.payload ?? {}, "script_content") ?? readStr(pocMsg.payload ?? {}, "code") ?? readStr(pocMsg.payload ?? {}, "pseudocode") ?? ""}
                  language={readStr(pocMsg.payload ?? {}, "language") ?? "python"}
                />
              </Suspense>
            </div>
          ) : (
            <div style={emptyNote}>no proof-of-concept drafted yet.</div>
          )}
        </Panel>
        <Panel {...pv("crash")} title="crash" tag="C" signature="sanitizer output">
          {crashMsg ? (
            <pre style={css("margin:0;padding:12px;font-family:var(--font-mono);font-size:10.5px;line-height:1.5;color:var(--text-primary);white-space:pre-wrap;word-break:break-word;")}>
              {turnProse(crashMsg)}
            </pre>
          ) : (
            <div style={emptyNote}>no crash artifact captured.</div>
          )}
        </Panel>
      </div>
    );
  } else {
    body = <div style={css("flex:1;display:flex;align-items:center;justify-content:center;")}><span style={emptyNote}>unknown view.</span></div>;
  }

  // Command palette (/ or Ctrl-K). Every command is a real action -- layouts,
  // pane focus, zoom/keymap, and the same investigation controls as the turns
  // toolbar. Nothing here is a demo no-op.
  type PalCmd = { group: string; label: string; hint?: string; run: () => void };
  const palCommands: PalCmd[] = [];
  for (const [id, label] of VIEWS) {
    palCommands.push({ group: "layout", label: `layout \u00b7 ${label}`, hint: String(VIEW_INDEX[id]), run: () => onNavigate(id) });
  }
  for (const pane of LAYOUT_PANES[view] ?? []) {
    palCommands.push({ group: "focus", label: `focus \u00b7 ${pane}`, hint: "\u21b5", run: () => { setFocus(pane); setZoom(null); } });
  }
  palCommands.push({ group: "view", label: "zoom focused pane", hint: "f", run: () => setZoom((z) => (z ? null : focus)) });
  palCommands.push({ group: "view", label: "keymap", hint: "?", run: () => setHelp(true) });
  const palHasOutcome = (inv.data?.outcome_count ?? 0) > 0;
  palCommands.push({ group: "run", label: isPaused ? "resume investigation" : "pause investigation", hint: "p", run: () => control.mutate(isPaused ? "resume" : "pause") });
  if (palHasOutcome) {
    palCommands.push({ group: "run", label: "generate narrative", run: () => narrative.mutate() });
    palCommands.push({ group: "run", label: "re-verify outcome", run: () => control.mutate("verify") });
  }
  palCommands.push({ group: "run", label: "export report (json)", run: doExport });
  palCommands.push({ group: "run", label: inv.data?.is_favorite ? "unfavorite" : "favorite", run: () => favorite.mutate() });
  palCommands.push({ group: "run", label: "reset investigation", run: doReset });
  palCommands.push({ group: "run", label: "re-enqueue investigation", run: doReenqueue });
  const palQ = palQuery.trim().toLowerCase();
  const palFiltered = (palQ ? palCommands.filter((c) => c.label.toLowerCase().includes(palQ)) : palCommands).slice(0, 40);
  const palIdx = palFiltered.length ? Math.min(palSel, palFiltered.length - 1) : 0;
  const runPal = (c: PalCmd): void => {
    setPalette(false);
    setPalQuery("");
    c.run();
  };

  /* -------------------------------- render ------------------------------- */

  const statusStrip = (
    <>
      <span style={{ display: "flex", alignItems: "center", padding: "0 12px", background: "var(--status-ok)", color: "var(--text-on-accent)", fontWeight: 700, letterSpacing: "0.14em" }}>{inv.data?.status ?? "running"}</span>
      {VIEWS.map(([id, label], i) => {
        const on = id === view;
        return (
          <button key={id} type="button" onClick={() => onNavigate(id)} style={css(`display:flex;align-items:center;padding:0 11px;background:${on ? "color-mix(in srgb,var(--accent) 16%,transparent)" : "transparent"};color:${on ? "var(--accent)" : "var(--text-faint)"};border:0;border-right:1px solid var(--border-soft);font-family:var(--font-mono);font-size:10.5px;letter-spacing:0.1em;text-transform:uppercase;cursor:pointer;`)}>{i + 1} {label}</button>
        );
      })}
      <span style={{ display: "flex", alignItems: "center", padding: "0 10px", color: "var(--accent)", letterSpacing: "0.1em" }}>focus {focus}{zoom ? " \u00b7 zoom" : ""}{pinned.length ? ` \u00b7 pin ${pinned.join("+")}` : ""}</span>
      <span style={{ flex: 1 }} />
      <span style={{ display: "flex", alignItems: "center", padding: "0 11px", textTransform: "none", letterSpacing: "0.04em" }}>1-5 layout &#183; hjkl focus &#183; f zoom &#183; / find &#183; p pause &#183; ? keys</span>
      <span style={{ display: "flex", alignItems: "center", padding: "0 11px", borderLeft: "1px solid var(--border-soft)", textTransform: "none" }}>{branchList.length} live loops</span>
    </>
  );

  return (
    <ConsoleWindow
      id={windowId}
      kind="page"
      title={title}
      isFullscreen={isFullscreen}
      isFocused={isFocused}
      onFocus={onFocus}
      onClose={onBack}
      onMinimize={onMinimize}
      onToggleFullscreen={onToggleFullscreen}
      footerExtras={statusStrip}
    >

      {/* body */}
      <main style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
        {body}
        {/* steering */}
        <div style={css("flex:0 0 auto;display:flex;align-items:center;gap:9px;padding:8px 14px;border-top:1px solid var(--border-soft);background:color-mix(in srgb,var(--surface-sunk) 60%,transparent);")}>
          <span style={css(`font-size:9px;letter-spacing:0.12em;text-transform:uppercase;color:${H.acc};font-weight:700;`)}>steering</span>
          <input value={steer} onChange={(e: ChangeEvent<HTMLInputElement>) => setSteer(e.target.value)} onKeyDown={onSteerKey} placeholder="context the engine sees verbatim next turn" disabled={!invId} style={css("flex:1;min-width:0;background:transparent;border:0;outline:none;color:var(--text-primary);font-family:var(--font-mono);font-size:12px;")} />
          <select value={steerIntent} onChange={(e: ChangeEvent<HTMLSelectElement>) => setSteerIntent(e.target.value)} disabled={!invId} title="operator intent" style={css("flex:0 0 auto;height:28px;background:var(--surface-chrome);border:1px solid var(--border-soft);border-radius:2px;color:var(--text-muted);font-family:var(--font-mono);font-size:10px;padding:0 6px;cursor:pointer;")}>
            {["steering", "correction", "dismissal", "question", "outcome_selection", "branch_command"].map((o) => (
              <option key={o} value={o}>{o}</option>
            ))}
          </select>
          <button type="button" onClick={doSteer} disabled={!invId || steer.trim().length === 0 || post.isPending} style={css(`flex:0 0 auto;padding:0 14px;height:28px;font-family:var(--font-mono);font-size:10px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-on-accent);background:var(--accent);border:1px solid var(--accent);border-radius:2px;cursor:pointer;${!invId || steer.trim().length === 0 || post.isPending ? "opacity:0.45;cursor:not-allowed;" : ""}`)}>send</button>
        </div>
      </main>

      {/* command palette (/ or Ctrl-K; Esc / click-away closes) */}
      {palette ? (
        <div
          onClick={() => setPalette(false)}
          style={{ position: "absolute", inset: 0, zIndex: 70, display: "flex", alignItems: "flex-start", justifyContent: "center", paddingTop: "12vh", background: "rgba(9,9,9,0.62)" }}
        >
          <div
            onClick={(e: ReactMouseEvent) => e.stopPropagation()}
            style={css("width:min(560px,88%);max-height:64vh;display:flex;flex-direction:column;background:var(--surface-card);border:1px solid var(--accent);border-radius:4px;overflow:hidden;box-shadow:0 24px 80px rgba(0,0,0,0.6);")}
          >
            <div style={css("display:flex;align-items:center;gap:9px;padding:10px 12px;border-bottom:1px solid var(--border);background:var(--surface-chrome);")}>
              <span style={css("color:var(--accent);font-size:13px;")}>:</span>
              <input
                autoFocus
                value={palQuery}
                onChange={(e: ChangeEvent<HTMLInputElement>) => { setPalQuery(e.target.value); setPalSel(0); }}
                onKeyDown={(e: KeyboardEvent<HTMLInputElement>) => {
                  if (e.key === "Escape") { e.preventDefault(); setPalette(false); }
                  else if (e.key === "Enter") { e.preventDefault(); const c = palFiltered[palIdx]; if (c) runPal(c); }
                  else if (e.key === "ArrowDown") { e.preventDefault(); setPalSel((s) => Math.min(s + 1, palFiltered.length - 1)); }
                  else if (e.key === "ArrowUp") { e.preventDefault(); setPalSel((s) => Math.max(s - 1, 0)); }
                }}
                placeholder={"layout, pane, action\u2026"}
                style={css("flex:1;min-width:0;background:transparent;border:0;outline:none;color:var(--text-primary);font-family:var(--font-mono);font-size:13px;")}
              />
              <span style={css("font-size:9px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);")}>esc</span>
            </div>
            <div style={css("flex:1;min-height:0;overflow:auto;")}>
              {palFiltered.length === 0 ? (
                <div style={emptyNote}>no command matches.</div>
              ) : (
                palFiltered.map((c, i) => (
                  <div
                    key={`${c.group}-${c.label}`}
                    onClick={() => runPal(c)}
                    onMouseEnter={() => setPalSel(i)}
                    style={css(
                      `display:flex;align-items:center;gap:10px;padding:7px 12px;cursor:pointer;border-bottom:1px solid var(--border-faint);${i === palIdx ? "background:color-mix(in srgb,var(--accent) 14%,transparent);" : ""}`,
                    )}
                  >
                    <span style={css("flex:0 0 52px;font-size:8px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);")}>{c.group}</span>
                    <span style={css(`flex:1;min-width:0;font-size:12px;color:${i === palIdx ? "var(--accent)" : "var(--text-primary)"};white-space:nowrap;overflow:hidden;text-overflow:ellipsis;`)}>{c.label}</span>
                    {c.hint ? <span style={css("flex:0 0 auto;font-size:9px;font-family:var(--font-mono);color:var(--text-faint);border:1px solid var(--border-soft);padding:0 5px;border-radius:2px;")}>{c.hint}</span> : null}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      ) : null}

      {/* keymap help (? toggles, Esc / click-away closes) */}
      {help ? (
        <div
          onClick={() => setHelp(false)}
          style={{ position: "absolute", inset: 0, zIndex: 60, display: "flex", alignItems: "center", justifyContent: "center", background: "rgba(9,9,9,0.62)" }}
        >
          <div
            onClick={(e: ReactMouseEvent) => e.stopPropagation()}
            style={css("width:min(520px,86%);background:var(--surface-card);border:1px solid var(--accent);border-radius:4px;overflow:hidden;box-shadow:0 24px 80px rgba(0,0,0,0.6);")}
          >
            <div style={css("display:flex;align-items:center;gap:10px;padding:10px 13px;border-bottom:1px solid var(--border);background:var(--surface-chrome);font-size:10.5px;letter-spacing:0.16em;text-transform:uppercase;color:var(--text-primary);")}>
              <span style={css("width:8px;height:8px;background:var(--accent);flex:0 0 auto;")} />
              <span>keymap</span>
              <span style={css("flex:1;")} />
              <button type="button" onClick={() => setHelp(false)} style={css("background:transparent;border:0;color:var(--text-muted);font-family:inherit;font-size:14px;cursor:pointer;")}>{"\u2715"}</button>
            </div>
            <div style={css("padding:14px;display:flex;flex-direction:column;gap:6px;")}>
              {SHORTCUTS.map(([k, v]) => (
                <div key={k} style={css("display:flex;align-items:center;gap:12px;font-size:11px;")}>
                  <span style={css("flex:0 0 76px;border:1px solid var(--border);padding:1px 6px;text-align:center;color:var(--accent);font-family:var(--font-mono);font-size:10px;")}>{k}</span>
                  <span style={css("color:var(--text-muted);letter-spacing:0.02em;")}>{v}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : null}
    </ConsoleWindow>
  );
}
