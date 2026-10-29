import { useState, type CSSProperties, type JSX, type MouseEvent as ReactMouseEvent } from "react";

import type { Branch } from "../../../api/types";
import { css } from "../../css";
import { H } from "./theme";

// Shared operator-action controls for the X-Ray panes: 28px buttons, a
// two-step confirm for destructive ops, and matching input styling.

export type ActTone = "neutral" | "accent" | "ok" | "warn";

const TONE_COLOR = {
  neutral: "var(--text-muted)",
  accent: H.acc,
  ok: H.mint,
  warn: H.amber,
} as const satisfies Record<ActTone, string>;

function buttonStyle(tone: ActTone, enabled: boolean): CSSProperties {
  const col = TONE_COLOR[tone];

  return css(
    `flex:0 0 auto;font-family:var(--font-mono);font-size:11px;letter-spacing:0.06em;text-transform:uppercase;padding:0 10px;height:28px;border:1px solid ${tone === "neutral" ? "var(--border-soft)" : `${col}88`};border-radius:2px;background:transparent;color:${col};cursor:${enabled ? "pointer" : "default"};${enabled ? "" : "opacity:0.45;"}`,
  );
}

// Clicks never bubble: action rows sit inside clickable list items.
export function stopClick(e: ReactMouseEvent): void {
  e.stopPropagation();
}

export function ActButton({
  label,
  pendingLabel,
  onClick,
  disabled = false,
  pending = false,
  tone = "neutral",
  title,
}: {
  label: string;
  pendingLabel?: string;
  onClick: () => void;
  disabled?: boolean;
  pending?: boolean;
  tone?: ActTone;
  title?: string;
}): JSX.Element {
  const enabled = !disabled && !pending;

  return (
    <button
      type="button"
      title={title}
      disabled={!enabled}
      onClick={(e) => {
        stopClick(e);

        if (enabled) onClick();
      }}
      style={buttonStyle(tone, enabled)}
    >
      {pending ? (pendingLabel ?? `${label}…`) : label}
    </button>
  );
}

// Destructive op: the first click arms, the second commits, cancel disarms.
export function ConfirmButton({
  label,
  confirmLabel,
  onConfirm,
  disabled = false,
  pending = false,
  tone = "warn",
}: {
  label: string;
  confirmLabel: string;
  onConfirm: () => void;
  disabled?: boolean;
  pending?: boolean;
  tone?: ActTone;
}): JSX.Element {
  const [armed, setArmed] = useState(false);

  if (!armed || pending) {
    return <ActButton label={label} onClick={() => setArmed(true)} disabled={disabled} pending={pending} tone={tone} />;
  }

  return (
    <span style={css("display:inline-flex;gap:4px;")}>
      <ActButton
        label={confirmLabel}
        tone={tone}
        disabled={disabled}
        onClick={() => {
          setArmed(false);
          onConfirm();
        }}
      />
      <ActButton label="cancel" onClick={() => setArmed(false)} />
    </span>
  );
}

export const fieldStyle = css(
  "height:28px;min-width:0;padding:0 8px;font-family:var(--font-mono);font-size:11px;color:var(--text-primary);background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:2px;",
);

export const actionRow = css("display:flex;align-items:center;gap:6px;flex-wrap:wrap;");

export const formLabel = css("font-size:11px;letter-spacing:0.06em;color:var(--text-faint);");

// Operator-selectable branch voices (the synthetic merge/fork voices are
// written by the engine only).
export const PERSONA_VOICES = ["halvar", "maddie", "yuki", "renzo", "noor", "wei"] as const;

// Branch option label for operator pickers: persona plus a short id.
export function branchLabel(b: Branch): string {
  return `${(b.persona_voice ?? "branch").toUpperCase()} ${b.id.slice(0, 8)}`;
}
