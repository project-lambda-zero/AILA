import { useState } from "react";

import { AilaBadge } from "@/components/aila/AilaBadge";

import type { VRMessageSummary } from "../types";

/** Per-turn card from 08_FRONTEND_UX.md §1.10.
 *
 *  Investigation timeline is a vertical stack of these. Header strip
 *  carries turn number + sender badge + payload kind + timestamp; body
 *  shows the payload content (collapsed past a threshold with click-to-
 *  expand); evidence refs surface as inline chips.
 *
 *  Sender kind tone mapping:
 *    operator  → cyan info badge (operator-driven turn)
 *    persona   → orange (LLM reasoning / agent role)
 *    tool      → blue info (tool dispatch / observation)
 *    system    → muted info (platform events) */
const SENDER_TONE: Record<
  string,
  "info" | "low" | "medium" | "high" | "critical"
> = {
  operator: "info",
  persona: "medium",
  tool: "low",
  system: "info",
};

const PAYLOAD_TONE: Record<
  string,
  "info" | "low" | "medium" | "high" | "critical"
> = {
  thought: "medium",
  action: "info",
  observation: "low",
  outcome: "low",
  finding: "high",
  blocked: "critical",
  user_message: "info",
};

const COLLAPSE_THRESHOLD_CHARS = 600;

function formatRelative(iso?: string | null): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleTimeString();
  } catch {
    return iso;
  }
}

function renderPayload(payload: Record<string, unknown>): string {
  // Render-priority: text-shaped fields > full JSON
  const textKeys = ["text", "reasoning", "summary", "message", "content"];
  for (const k of textKeys) {
    const v = payload[k];
    if (typeof v === "string" && v.trim().length > 0) return v;
  }
  try {
    return JSON.stringify(payload, null, 2);
  } catch {
    return String(payload);
  }
}

function truncate(s: string, n: number): { head: string; rest: string } {
  if (s.length <= n) return { head: s, rest: "" };
  return { head: s.slice(0, n), rest: s.slice(n) };
}

export function TurnCard({
  message,
  index,
}: {
  message: VRMessageSummary;
  index: number;
}) {
  const [expanded, setExpanded] = useState(false);
  const sender = message.sender_kind ?? "system";
  const payloadKind = message.payload_kind ?? "";
  const senderTone = SENDER_TONE[sender] ?? "info";
  const payloadTone = payloadKind
    ? PAYLOAD_TONE[payloadKind] ?? "info"
    : "info";

  const text = renderPayload(message.payload ?? {});
  const { head, rest } = truncate(text, COLLAPSE_THRESHOLD_CHARS);
  const hasMore = rest.length > 0;

  return (
    <article
      className="border border-border-default rounded-md bg-surface/40 overflow-hidden"
      id={`turn-${index}`}
    >
      <header className="flex items-center justify-between gap-2 px-3 py-1.5 border-b border-border-default bg-surface/60">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[10px] font-mono text-text-muted">
            #{message.at_turn ?? index + 1}
          </span>
          <AilaBadge severity={senderTone} size="sm">
            {sender}
            {message.sender_id ? `:${message.sender_id}` : ""}
          </AilaBadge>
          {payloadKind && (
            <AilaBadge severity={payloadTone} size="sm">
              {payloadKind}
            </AilaBadge>
          )}
          {message.operator_intent && (
            <AilaBadge severity="info" size="sm">
              intent: {message.operator_intent}
            </AilaBadge>
          )}
        </div>
        <span className="text-[10px] font-mono text-text-muted whitespace-nowrap">
          {formatRelative(message.created_at)}
        </span>
      </header>

      <div className="px-3 py-2">
        <pre className="text-xs font-mono whitespace-pre-wrap text-foreground leading-relaxed break-words">
          {expanded ? text : head}
          {hasMore && !expanded && (
            <span className="text-text-muted">… ({rest.length} more)</span>
          )}
        </pre>
        {hasMore && (
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            className="mt-1 text-[10px] font-mono text-text-muted hover:text-foreground underline-offset-2 hover:underline"
          >
            {expanded ? "collapse" : "expand"}
          </button>
        )}
        {message.evidence_refs && message.evidence_refs.length > 0 && (
          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            <span className="text-[10px] uppercase tracking-wide text-text-muted">
              evidence:
            </span>
            {message.evidence_refs.map((ref) => (
              <span
                key={ref}
                className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-surface border border-border-default text-text-muted"
              >
                {ref}
              </span>
            ))}
          </div>
        )}
      </div>
    </article>
  );
}
