import { Fragment, useMemo, useState } from "react";
import type { ComponentType } from "react";
import type { IconProps } from "@phosphor-icons/react/lib";
import { Brain } from "@phosphor-icons/react/dist/csr/Brain";
import { GearSix } from "@phosphor-icons/react/dist/csr/GearSix";
import { User } from "@phosphor-icons/react/dist/csr/User";
import { Wrench } from "@phosphor-icons/react/dist/csr/Wrench";

import { MonoBadge } from "@/components/aila/mock";

import { CodeBlock } from "./CodeBlock";
import { personaMeta } from "./personaMeta";
import type { VRMessageSummary } from "../types";

/** Per-turn card in the VR X-Ray timeline. Mock design language:
 *  a mono, bordered row with a persona logo tile + role label + turn
 *  number + payload-kind chip in the header. Body is sans-serif prose
 *  (truncated at 600 chars). Clicking the header expands a bordered
 *  detail block: tool-call cards, metadata k/v grid, source excerpt. */

type IconCmp = ComponentType<IconProps>;

const COLLAPSE_THRESHOLD_CHARS = 600;

// ─── Sender identity ────────────────────────────────────────────────────
interface SenderStyle {
  hue: string;
  Icon: IconCmp;
  label: string;
}

const SENDER_STYLES: Record<string, SenderStyle> = {
  engine: { hue: "var(--status-info)", Icon: Brain, label: "Researcher" },
  operator: { hue: "var(--accent)", Icon: User, label: "Operator" },
  tool: { hue: "var(--status-ok)", Icon: Wrench, label: "Tool" },
  system: { hue: "var(--text-faint)", Icon: GearSix, label: "System" },
};

const SENDER_FALLBACK: SenderStyle = SENDER_STYLES.system;

function resolveDisplaySender(senderKind: string, senderId: string | null): string {
  if (senderKind === "engine" && senderId === "tool_executor") return "tool";
  if (senderKind === "operator" && senderId === "auto_steering") return "system";
  return senderKind || "system";
}

// ─── Payload-kind → action chip ─────────────────────────────────────────
interface ActionChip {
  label: string;
  tone: string;
}

const ACTION_CHIPS: Record<string, ActionChip> = {
  text: { label: "TEXT", tone: "muted" },
  agent_text: { label: "TEXT", tone: "muted" },
  tool_call: { label: "TOOL_RUN", tone: "info" },
  tool_result: { label: "TOOL_OUT", tone: "ok" },
  outcome_emit: { label: "SUBMIT", tone: "accent" },
  outcome_pending: { label: "SUBMIT", tone: "accent" },
  submit: { label: "SUBMIT", tone: "accent" },
  steering: { label: "STEER", tone: "warn" },
  system: { label: "SYSTEM", tone: "muted" },
  hypothesis_update: { label: "HYPOTHESIS", tone: "info" },
  decompiled_function: { label: "CODE", tone: "info" },
  code_pointer: { label: "CODE", tone: "info" },
};

function actionChipFor(payloadKind: string): ActionChip {
  const hit = ACTION_CHIPS[payloadKind];
  if (hit) return hit;
  const label = payloadKind
    ? payloadKind.replace(/_/g, " ").toUpperCase()
    : "TURN";
  return { label, tone: "muted" };
}

// ─── Payload content extraction ─────────────────────────────────────────
const PROSE_KEYS = ["text", "reasoning", "summary", "message", "content", "description"];

function extractProse(payload: Record<string, unknown>): string | null {
  for (const k of PROSE_KEYS) {
    const v = payload[k];
    if (typeof v === "string" && v.trim().length > 0) return v;
  }
  return null;
}

function extractToolName(payload: Record<string, unknown>): string | null {
  for (const k of ["tool", "tool_name", "name", "callee"]) {
    const v = payload[k];
    if (typeof v === "string" && v.trim().length > 0) return v.trim();
  }
  return null;
}

function extractToolArgs(payload: Record<string, unknown>): Record<string, unknown> | null {
  for (const k of ["args", "arguments", "input", "params"]) {
    const v = payload[k];
    if (v && typeof v === "object" && !Array.isArray(v)) {
      return v as Record<string, unknown>;
    }
  }
  return null;
}

function formatArgValue(v: unknown): string {
  if (v === null || v === undefined) return v === null ? "null" : "--";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}

function fullTimestamp(iso?: string | null): string {
  if (!iso) return "";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

// ─── Component ──────────────────────────────────────────────────────────
export function TurnCard({
  message,
  index,
  persona: personaVoice,
}: {
  message: VRMessageSummary;
  index: number;
  /** Persona voice from the branch record. Message rows themselves don't
   *  carry the persona name (sender_id is 'engine' / 'tool_executor'). */
  persona?: string | null;
}) {
  const [expanded, setExpanded] = useState(false);
  const [proseExpanded, setProseExpanded] = useState(false);

  const rawSender = message.sender_kind ?? "system";
  const senderId = message.sender_id ?? null;
  const payloadKind: string = message.payload_kind ?? "";
  const payload = message.payload ?? {};

  const displaySender = resolveDisplaySender(rawSender, senderId);
  const senderStyle = SENDER_STYLES[displaySender] ?? SENDER_FALLBACK;
  const chip = actionChipFor(payloadKind);
  const pm = personaMeta(personaVoice);

  // Persona logo hue: real persona voice (engine turns) → persona hue.
  // Otherwise → sender hue (operator=accent, tool=ok, system=faint).
  const hasPersona = Boolean(personaVoice && pm.initial !== "?");
  const tileHue = hasPersona ? pm.hue : senderStyle.hue;
  const tileInitial = hasPersona
    ? pm.initial
    : (senderStyle.label[0] ?? "?").toUpperCase();

  const prose = useMemo(() => extractProse(payload), [payload]);
  const toolName = useMemo(() => extractToolName(payload), [payload]);
  const toolArgs = useMemo(() => extractToolArgs(payload), [payload]);

  const roleLabel = useMemo(() => {
    if (rawSender === "operator" && senderId === "auto_steering") return "auto-steering";
    if (rawSender === "operator" && senderId && senderId !== "auto_steering") {
      return senderId;
    }
    if (hasPersona) return senderStyle.label.toLowerCase();
    return senderStyle.label.toLowerCase();
  }, [rawSender, senderId, senderStyle.label, hasPersona]);

  const personaDisplay = hasPersona
    ? pm.label
    : (rawSender === "operator" && senderId && senderId !== "auto_steering"
        ? senderId
        : senderStyle.label);

  const SenderIcon = senderStyle.Icon;
  const turnNum = message.at_turn ?? index + 1;

  const showToolCard = payloadKind === "tool_call" && toolName !== null;
  const codeSource =
    typeof payload.pseudocode === "string" && payload.pseudocode.length > 0
      ? String(payload.pseudocode)
      : typeof payload.chunks_text === "string" && payload.chunks_text.length > 0
        ? String(payload.chunks_text)
        : null;
  const codePath =
    typeof payload.function_name === "string" && payload.function_name.length > 0
      ? String(payload.function_name)
      : typeof payload.query === "string" && payload.query.length > 0
        ? String(payload.query)
        : "";
  const codeAddress =
    typeof payload.address === "string" ? String(payload.address) : undefined;

  // Metadata k/v pairs surfaced in the expanded body: everything on the
  // payload that isn't already rendered above as prose / tool card / code.
  const metaEntries = useMemo(() => {
    const shownKeys = new Set([
      ...PROSE_KEYS,
      "tool",
      "tool_name",
      "name",
      "callee",
      "args",
      "arguments",
      "input",
      "params",
      "pseudocode",
      "chunks_text",
      "function_name",
      "query",
    ]);
    const out: [string, unknown][] = [];
    for (const [k, v] of Object.entries(payload)) {
      if (shownKeys.has(k)) continue;
      if (v === null || v === undefined) continue;
      if (typeof v === "object" && !Array.isArray(v) && Object.keys(v as object).length === 0) continue;
      out.push([k, v]);
    }
    return out;
  }, [payload]);

  return (
    <div
      id={`turn-${index}`}
      className="font-mono"
      style={{
        border: "1px solid var(--border-faint)",
        background: "var(--surface-card)",
        padding: 7,
        display: "flex",
        flexDirection: "column",
        gap: 5,
      }}
    >
      {/* Header row */}
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        aria-expanded={expanded}
        aria-controls={`turn-${index}-detail`}
        className="flex items-center font-mono"
        style={{
          gap: 8,
          padding: 0,
          background: "transparent",
          border: "none",
          color: "inherit",
          cursor: "pointer",
          width: "100%",
          textAlign: "left",
        }}
      >
        {/* Persona / sender logo tile — 22x22 mock square */}
        <span
          aria-hidden
          className="inline-flex items-center justify-center font-mono uppercase shrink-0"
          style={{
            width: 22,
            height: 22,
            fontSize: 11,
            background: `color-mix(in srgb, ${tileHue} 18%, transparent)`,
            border: `1px solid color-mix(in srgb, ${tileHue} 40%, transparent)`,
            color: tileHue,
          }}
        >
          {hasPersona ? (
            tileInitial
          ) : (
            <SenderIcon size={12} weight="duotone" />
          )}
        </span>

        {/* Persona voice (11px uppercase mono) */}
        <span
          className="uppercase shrink-0"
          style={{
            fontSize: 11,
            letterSpacing: "0.06em",
            color: "var(--text-primary)",
          }}
        >
          {personaDisplay}
        </span>

        {/* Role label (10px uppercase muted) */}
        <span
          className="uppercase shrink-0"
          style={{
            fontSize: 10,
            letterSpacing: "0.14em",
            color: "var(--text-faint)",
          }}
        >
          {roleLabel}
        </span>

        {/* Spacer */}
        <span style={{ flex: 1 }} />

        {/* Turn number */}
        <span
          className="tabular-nums shrink-0"
          style={{
            fontSize: 10,
            color: "var(--text-faint)",
          }}
          title={fullTimestamp(message.created_at)}
        >
          t{turnNum}
        </span>

        {/* Action chip */}
        <MonoBadge tone={chip.tone}>{chip.label}</MonoBadge>

        {/* Operator intent overlay chip */}
        {message.operator_intent && (
          <MonoBadge tone="warn">
            {message.operator_intent.replace(/_/g, " ").toUpperCase()}
          </MonoBadge>
        )}
      </button>

      {/* Prose body */}
      {prose && (
        <ProseBody
          text={prose}
          expanded={proseExpanded}
          onToggle={() => setProseExpanded((v) => !v)}
        />
      )}

      {/* Expanded detail row */}
      {expanded && (
        <div
          id={`turn-${index}-detail`}
          className="flex flex-col"
          style={{
            gap: 8,
            paddingTop: 7,
            borderTop: "1px solid var(--border-faint)",
          }}
        >
          {/* Tool-call card */}
          {showToolCard && (
            <ToolCallCard name={toolName!} args={toolArgs} />
          )}

          {/* Source excerpt */}
          {codeSource && (
            <div
              style={{
                border: "1px solid var(--border-faint)",
                background: "var(--surface-sunk)",
              }}
            >
              <div
                className="font-mono uppercase flex items-center"
                style={{
                  gap: 8,
                  padding: "3px 7px",
                  background: "var(--surface-chrome)",
                  borderBottom: "1px solid var(--border-faint)",
                  fontSize: 9,
                  letterSpacing: "0.14em",
                  color: "var(--text-faint)",
                }}
              >
                <span
                  className="truncate"
                  style={{ color: "var(--text-muted)", flex: 1, minWidth: 0 }}
                  title={codePath}
                >
                  {codePath || "source"}
                </span>
                {codeAddress && (
                  <span style={{ color: "var(--text-faint)" }}>{codeAddress}</span>
                )}
              </div>
              <CodeBlock
                code={codeSource}
                filePath={codePath}
                address={codeAddress}
              />
            </div>
          )}

          {/* Metadata k/v grid */}
          {metaEntries.length > 0 && (
            <dl
              className="font-mono"
              style={{
                display: "grid",
                gridTemplateColumns: "78px minmax(0,1fr)",
                columnGap: 8,
                rowGap: 3,
                fontSize: 9.5,
                margin: 0,
              }}
            >
              {metaEntries.map(([k, v]) => (
                <Fragment key={k}>
                  <dt
                    className="uppercase"
                    style={{
                      letterSpacing: "0.14em",
                      color: "var(--text-faint)",
                      margin: 0,
                    }}
                  >
                    {k.replace(/_/g, " ")}
                  </dt>
                  <dd
                    className="break-all"
                    style={{
                      color: "var(--text-primary)",
                      whiteSpace: "pre-wrap",
                      margin: 0,
                    }}
                  >
                    {formatArgValue(v)}
                  </dd>
                </Fragment>
              ))}
            </dl>
          )}

          {/* Evidence refs */}
          {message.evidence_refs && message.evidence_refs.length > 0 && (
            <div
              className="flex items-center font-mono"
              style={{ gap: 4, flexWrap: "wrap" }}
            >
              <span
                className="uppercase shrink-0"
                style={{
                  fontSize: 9,
                  letterSpacing: "0.14em",
                  color: "var(--text-faint)",
                }}
              >
                evidence
              </span>
              {message.evidence_refs.map((ref) => (
                <MonoBadge key={ref} tone="muted">
                  {ref}
                </MonoBadge>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Sub-renderers ──────────────────────────────────────────────────────

function ToolCallCard({
  name,
  args,
}: {
  name: string;
  args: Record<string, unknown> | null;
}) {
  const entries = args ? Object.entries(args) : [];
  return (
    <div>
      {/* Green-accent tool header */}
      <div
        className="flex items-center font-mono"
        style={{
          gap: 6,
          padding: "3px 7px",
          background: "color-mix(in srgb, var(--status-ok) 9%, transparent)",
          border: "1px solid color-mix(in srgb, var(--status-ok) 26%, transparent)",
          fontSize: 10.5,
          color: "var(--text-primary)",
        }}
      >
        <span
          aria-hidden
          style={{ width: 6, height: 6, background: "var(--status-ok)", flex: "0 0 auto" }}
        />
        <code className="break-all" style={{ fontFamily: "var(--font-mono)" }}>
          {name}
        </code>
      </div>
      {/* Arg rows */}
      {entries.length > 0 && (
        <dl
          className="font-mono"
          style={{
            display: "grid",
            gridTemplateColumns: "74px minmax(0,1fr)",
            columnGap: 8,
            rowGap: 3,
            fontSize: 9.5,
            marginTop: 5,
          }}
        >
          {entries.map(([k, v]) => (
            <Fragment key={k}>
              <dt
                className="uppercase"
                style={{
                  letterSpacing: "0.14em",
                  color: "var(--text-faint)",
                  margin: 0,
                }}
              >
                {k}
              </dt>
              <dd
                className="break-all"
                style={{
                  color: "var(--text-primary)",
                  whiteSpace: "pre-wrap",
                  margin: 0,
                }}
              >
                {formatArgValue(v)}
              </dd>
            </Fragment>
          ))}
        </dl>
      )}
    </div>
  );
}

function ProseBody({
  text,
  expanded,
  onToggle,
}: {
  text: string;
  expanded: boolean;
  onToggle: () => void;
}) {
  const long = text.length > COLLAPSE_THRESHOLD_CHARS;
  const shown = !long || expanded ? text : text.slice(0, COLLAPSE_THRESHOLD_CHARS);
  return (
    <div>
      <div
        className="break-words"
        style={{
          fontFamily: "var(--font-sans)",
          fontSize: 11.5,
          lineHeight: 1.42,
          color: "var(--text-primary)",
          whiteSpace: "pre-wrap",
        }}
      >
        {shown}
        {long && !expanded && (
          <span style={{ color: "var(--text-faint)" }}>
            {" "}… (+{text.length - COLLAPSE_THRESHOLD_CHARS} chars)
          </span>
        )}
      </div>
      {long && (
        <button
          type="button"
          onClick={onToggle}
          className="font-mono uppercase"
          style={{
            marginTop: 3,
            padding: 0,
            background: "transparent",
            border: "none",
            color: "var(--text-muted)",
            fontSize: 9,
            letterSpacing: "0.14em",
            textDecoration: "underline",
            cursor: "pointer",
          }}
        >
          {expanded ? "collapse" : "expand"}
        </button>
      )}
    </div>
  );
}
