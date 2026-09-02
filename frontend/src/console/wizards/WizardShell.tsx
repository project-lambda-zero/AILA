/** WizardShell -- the one guided-flow chrome every chat-reachable wizard
 * renders inside. It owns:
 *   - a persistent `step N of M \u00b7 <title>` strip with a one-sentence
 *     purpose and one filled progress segment per completed step,
 *   - the Back / Next / Finish controls (Next becomes Finish on the last step;
 *     Back is disabled on the first),
 *   - a compact inline summary that lists every invalid field by label +
 *     reason whenever the primary control is disabled (no silent disables),
 *   - an inline backend-error row with a Retry control that keeps the operator
 *     on the current step rather than throwing them back to step one.
 *
 * Consumers own the per-step body (`children`), declare `steps`, drive
 * `current`, and compute the current step's `issues`. The shell reads CSS vars
 * from globals.css via the `css()` helper; no Tailwind, no new dependency.
 *
 * `FieldHelp` is the shared `?` affordance every field label pairs with to
 * open a plain-language explanation. */

import { useState } from "react";
import type { CSSProperties, JSX } from "react";

import { css } from "../css";
import type { WizardShellProps } from "./types";

export type { WizardShellProps, WizardStepDef, WizardFieldIssue } from "./types";

const wrapStyle = css(
  "height:100%;min-height:0;display:flex;flex-direction:column;font-family:var(--font-mono);color:var(--text-primary);",
);
const headStyle = css(
  "flex:0 0 auto;padding:14px 18px 12px;border-bottom:1px solid var(--border-soft);display:flex;flex-direction:column;gap:9px;",
);
const bodyStyle = css("flex:1;min-height:0;overflow:auto;padding:16px 18px;display:flex;flex-direction:column;gap:14px;");
const footStyle = css(
  "flex:0 0 auto;display:flex;align-items:center;gap:12px;padding:11px 18px;border-top:1px solid var(--border-soft);background:color-mix(in srgb,var(--surface-chrome) 60%,transparent);",
);
const headingStyle = css(
  "font-size:11px;letter-spacing:0.16em;text-transform:uppercase;color:var(--text-primary);",
);
const stepLineStyle = css(
  "font-size:10px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-muted);",
);
const purposeStyle = css("font-size:11.5px;letter-spacing:0.02em;color:var(--text-faint);");
const segRowStyle = css("display:flex;align-items:center;gap:5px;");
const backStyleBase =
  "padding:0 12px;height:30px;font-family:var(--font-mono);font-size:10px;letter-spacing:0.1em;text-transform:uppercase;background:transparent;border:1px solid var(--border-soft);border-radius:2px;";
const helpBtnStyle = css(
  "width:15px;height:15px;flex:0 0 auto;display:inline-flex;align-items:center;justify-content:center;border:1px solid var(--border-soft);border-radius:50%;background:transparent;color:var(--text-muted);font-family:var(--font-mono);font-size:9px;line-height:1;cursor:pointer;padding:0;",
);
const helpPopStyle = css(
  "position:absolute;left:0;top:20px;z-index:5;max-width:280px;padding:8px 10px;background:var(--surface-chrome);border:1px solid var(--border);border-radius:3px;box-shadow:0 8px 24px rgba(0,0,0,0.5);color:var(--text-muted);font-family:var(--font-mono);font-size:11px;letter-spacing:0.01em;line-height:1.4;text-transform:none;white-space:normal;",
);

function segStyle(state: "done" | "active" | "pending"): CSSProperties {
  const color = state === "done" ? "var(--status-ok)" : state === "active" ? "var(--accent)" : "var(--border-soft)";
  const glow = state === "active" ? "box-shadow:0 0 8px var(--accent);" : "";
  return css(`flex:1 1 0;height:3px;border-radius:2px;background:${color};${glow}`);
}

function primaryStyle(enabled: boolean): CSSProperties {
  return css(
    `padding:0 16px;height:30px;font-family:var(--font-mono);font-size:10px;letter-spacing:0.1em;text-transform:uppercase;color:${
      enabled ? "var(--text-on-accent)" : "var(--text-faint)"
    };background:${enabled ? "var(--accent)" : "var(--surface-card)"};border:1px solid ${
      enabled ? "var(--accent)" : "var(--border-soft)"
    };border-radius:2px;cursor:${enabled ? "pointer" : "not-allowed"};box-shadow:${
      enabled ? "0 0 16px rgba(255,95,135,0.3)" : "none"
    };`,
  );
}

function backStyle(enabled: boolean): CSSProperties {
  return css(
    `${backStyleBase}color:${enabled ? "var(--text-muted)" : "var(--text-faint)"};cursor:${
      enabled ? "pointer" : "not-allowed"
    };opacity:${enabled ? "1" : "0.55"};`,
  );
}

/** The shared `?` field-help affordance: a small round button that toggles a
 * plain-language explanation. Keyboard-operable (a real button, aria-expanded). */
export function FieldHelp({ text }: { text: string }): JSX.Element {
  const [open, setOpen] = useState(false);
  return (
    <span style={{ position: "relative", display: "inline-flex", verticalAlign: "middle" }}>
      <button
        type="button"
        aria-label="field help"
        aria-expanded={open}
        title={text}
        onClick={() => setOpen((v) => !v)}
        onBlur={() => setOpen(false)}
        style={helpBtnStyle}
      >
        ?
      </button>
      {open ? (
        <span role="note" style={helpPopStyle}>
          {text}
        </span>
      ) : null}
    </span>
  );
}

export function WizardShell(props: WizardShellProps): JSX.Element {
  const { steps, current, issues, heading, error, onRetry } = props;
  const total = Math.max(1, steps.length);
  const idx = Math.max(0, Math.min(current, total - 1));
  const step = steps[idx] ?? { id: "step", title: "", purpose: "" };
  const isLast = idx >= total - 1;
  const showPrimary = props.showPrimary !== false;
  const busy = props.busy === true;
  const canPrimary = issues.length === 0 && !busy;
  const canBack = idx > 0 && !busy;

  const primaryLabel = busy
    ? "working\u2026"
    : isLast
      ? props.finishLabel ?? "finish"
      : props.nextLabel ?? "next";

  return (
    <div style={wrapStyle}>
      <div style={headStyle}>
        {heading ? <span style={headingStyle}>{heading}</span> : null}
        <span style={stepLineStyle}>
          {`step ${idx + 1} of ${total}`}
          {step.title ? ` \u00b7 ${step.title}` : ""}
        </span>
        {step.purpose ? <span style={purposeStyle}>{step.purpose}</span> : null}
        <div style={segRowStyle} role="progressbar" aria-valuenow={idx + 1} aria-valuemin={1} aria-valuemax={total} aria-label="wizard progress">
          {steps.map((s, i) => (
            <span key={s.id} style={segStyle(i < idx ? "done" : i === idx ? "active" : "pending")} />
          ))}
        </div>
      </div>

      <div style={bodyStyle}>{props.children}</div>

      {error ? (
        <div
          role="alert"
          style={css(
            "flex:0 0 auto;margin:0 18px 4px;padding:9px 11px;border:1px solid var(--accent);border-radius:3px;background:color-mix(in srgb,var(--accent) 10%,transparent);display:flex;align-items:center;gap:12px;",
          )}
        >
          <span style={css("flex:1;min-width:0;font-size:11px;letter-spacing:0.01em;color:var(--text-primary);text-transform:none;")}>
            {error}
          </span>
          {onRetry ? (
            <button
              type="button"
              onClick={onRetry}
              style={css(
                "flex:0 0 auto;padding:0 12px;height:26px;font-family:var(--font-mono);font-size:10px;letter-spacing:0.1em;text-transform:uppercase;color:var(--accent);background:transparent;border:1px solid var(--accent);border-radius:2px;cursor:pointer;",
              )}
            >
              retry
            </button>
          ) : null}
        </div>
      ) : null}

      <div style={footStyle}>
        {idx > 0 ? (
          <button type="button" disabled={!canBack} onClick={props.onBack} style={backStyle(canBack)}>
            {props.backLabel ?? "back"}
          </button>
        ) : null}

        {!canPrimary && issues.length > 0 ? (
          <div style={css("flex:1;min-width:0;display:flex;flex-direction:column;gap:2px;")}>
            <span style={css("font-size:9px;letter-spacing:0.1em;text-transform:uppercase;color:var(--status-warn);")}>
              {issues.length === 1 ? "1 field needs attention" : `${issues.length} fields need attention`}
            </span>
            {issues.map((f, i) => (
              <span
                key={`${f.label}-${i}`}
                style={css("font-size:11px;letter-spacing:0.01em;text-transform:none;color:var(--text-muted);")}
              >
                <span style={{ color: "var(--text-primary)" }}>{f.label}</span>
                {` \u2014 ${f.reason}`}
              </span>
            ))}
          </div>
        ) : (
          <div style={{ flex: 1 }} />
        )}

        {showPrimary ? (
          <button
            type="button"
            disabled={!canPrimary}
            aria-disabled={!canPrimary}
            onClick={isLast ? props.onFinish : props.onNext}
            style={primaryStyle(canPrimary)}
          >
            {primaryLabel}
          </button>
        ) : null}
      </div>
    </div>
  );
}

export default WizardShell;
