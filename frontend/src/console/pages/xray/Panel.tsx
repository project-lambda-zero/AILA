import type { CSSProperties, JSX, ReactNode } from "react";

import { css } from "../../css";
import { panelHatch } from "./theme";

// WindowPanel -- the design system's load-bearing chrome primitive: an OS-window
// frame with a system-light square, diagonal hatch grips flanking the centered
// title, an optional faint signature, and an optional one-line status footer.
export function Panel({
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
          <span style={css("flex:0 0 auto;font-size:11px;letter-spacing:0.06em;color:var(--text-faint);border:1px solid var(--border-soft);padding:1px 6px;border-radius:2px;")}>{tag}</span>
        ) : null}
      </div>
      <div style={css("flex:1;min-height:0;overflow:auto;")}>{children}</div>
      {status ? (
        <div
          style={css(
            "flex:0 0 auto;display:flex;align-items:center;gap:10px;padding:0 14px;height:var(--panel-status-h,25px);border-top:1px solid var(--border-soft);background:var(--surface-chrome);font-family:var(--font-mono);font-size:11px;color:var(--text-faint);letter-spacing:0.06em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;",
          )}
        >
          {status}
        </div>
      ) : null}
    </div>
  );
}
