import { Suspense } from "react";
import type { Dispatch, JSX, ReactNode, SetStateAction } from "react";

import { readStr } from "../../../api/parse";
import type { Message } from "../../../api/types";
import { css } from "../../css";
import { LazyCodeBlock } from "./LazyCode";
import { Section } from "./Section";
import { clockTime, toolCallView, turnProse, turnType } from "./parsers";
import type { Persona } from "./persona";
import { turnDetail } from "./turnDetail";
import { H, argRowStyle, codePreStyle, sectionProse } from "./theme";

// One card = one action + its output: a tool_call plus the result message(s)
// that follow it, or a standalone reasoning / submission message. Collapsed
// shows the action's headline reasoning; expanded splits into REASONING /
// TOOL / OUTPUT sections so the three are visually distinct -- not one wall.
export function TurnRow({
  group,
  resolvePersona,
  showClock,
  open,
  onToggle,
  headerAction,
}: {
  group: Message[];
  resolvePersona: (m: Message) => Persona;
  showClock: boolean; // VR shows the step clock; malware does not.
  open: boolean;
  onToggle: () => void;
  // Module-specific control rendered in the card header (malware: operator
  // message ACK). Its clicks must not toggle the card.
  headerAction?: (group: readonly Message[]) => ReactNode;
}): JSX.Element {
  const primary = group[0];
  const { name, role, tone } = resolvePersona(primary);
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
  const view = toolMsg ? toolCallView(toolMsg.payload ?? {}) : null;
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
        <span style={css(`width:16px;height:16px;flex:0 0 auto;display:flex;align-items:center;justify-content:center;border-radius:2px;font-size:11px;font-weight:700;color:#0d0d0d;background:${cardTone};`)}>
          {name.charAt(0)}
        </span>
        <span style={css(`font-size:11px;font-weight:700;letter-spacing:0.1em;color:${cardTone};`)}>{name}</span>
        {role && role !== name ? (
          <span style={css("font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);")}>{role}</span>
        ) : null}
        <span style={css("flex:1;")} />
        {showClock && clockTime(primary.created_at) ? (
          <span style={css("font-size:11px;color:var(--text-faint);font-variant-numeric:tabular-nums;letter-spacing:0.04em;")}>{clockTime(primary.created_at)}</span>
        ) : null}
        {headerAction ? headerAction(group) : null}
        <span style={css("font-size:11px;color:var(--text-faint);letter-spacing:0.06em;")}>{turnNo}</span>
        <span style={css(`font-size:11px;letter-spacing:0.1em;text-transform:uppercase;padding:1px 6px;border:1px solid ${badge}66;color:${badge};background:${badge}14;border-radius:2px;`)}>{type}</span>
        <span style={css("font-size:11px;color:var(--text-faint);width:10px;text-align:center;flex:0 0 auto;")}>{open ? "\u25be" : "\u25b8"}</span>
      </div>
      {open ? (
        <div style={css("display:flex;flex-direction:column;")}>
          {view ? (
            <>
              {view.reasoning.trim() ? (
                <Section label="reasoning" color={H.lav}>
                  <div style={sectionProse}>{view.reasoning}</div>
                  {view.expects.trim() ? (
                    <div style={css("margin-top:6px;font-size:11px;line-height:1.5;color:var(--text-muted);")}>
                      <span style={css("font-size:11px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-faint);margin-right:6px;")}>expecting</span>
                      {view.expects}
                    </div>
                  ) : null}
                </Section>
              ) : null}
              <Section label={view.tool ? "tool" : "action"} color={H.mint}>
                {view.tool ? (
                  <div style={css("display:inline-flex;align-items:center;gap:7px;padding:3px 9px;background:color-mix(in srgb,var(--status-ok) 12%,transparent);border:1px solid color-mix(in srgb,var(--status-ok) 32%,transparent);border-radius:2px;")}>
                    <span style={css("width:6px;height:6px;background:var(--status-ok);flex:0 0 auto;border-radius:1px;")} />
                    <span style={css("font-size:11px;font-family:var(--font-mono);color:var(--text-primary);word-break:break-all;")}>{view.tool}</span>
                  </div>
                ) : null}
                {view.args.length ? (
                  <div style={css("margin-top:6px;display:flex;flex-direction:column;gap:3px;")}>
                    {view.args.map(([k, v]) => (
                      <div key={k} style={argRowStyle}>
                        <span style={css("color:var(--text-muted);font-family:var(--font-mono);")}>{k}</span>
                        <span style={css("color:var(--text-primary);font-family:var(--font-mono);word-break:break-all;")}>{v}</span>
                      </div>
                    ))}
                  </div>
                ) : null}
                {view.script.trim() ? (
                  <div style={css("margin-top:6px;border:1px solid var(--border-soft);overflow:hidden;")}>
                    <Suspense fallback={<pre style={codePreStyle}>{view.script}</pre>}>
                      <LazyCodeBlock code={view.script} language="python" />
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

// The TURNS stream: one TurnRow per action card, one card open at a time.
export function TurnList({
  groups,
  openTurn,
  setOpenTurn,
  resolvePersona,
  showClock,
  headerAction,
}: {
  groups: readonly Message[][];
  openTurn: string | null;
  setOpenTurn: Dispatch<SetStateAction<string | null>>;
  resolvePersona: (m: Message) => Persona;
  showClock: boolean;
  headerAction?: (group: readonly Message[]) => ReactNode;
}): JSX.Element {
  return (
    <>
      {groups.map((g) => {
        const key = g[0].id;
        return (
          <TurnRow
            key={key}
            group={g}
            resolvePersona={resolvePersona}
            showClock={showClock}
            headerAction={headerAction}
            open={openTurn === key}
            onToggle={() => setOpenTurn((cur) => (cur === key ? null : key))}
          />
        );
      })}
    </>
  );
}
