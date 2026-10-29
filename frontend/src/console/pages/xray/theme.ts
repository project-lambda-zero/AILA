import type { CSSProperties } from "react";

import { css } from "../../css";

export const H = {
  acc: "#ff5f87",
  mint: "#97dbbe",
  amber: "#ffb85f",
  lav: "#af87d7",
  sig: "#f0a8c7",
  cream: "#ffd7af",
} as const;

export function hypTone(state: string): string {
  const s = state.toLowerCase();
  return s === "live" ? H.mint : s === "rejected" ? H.amber : H.lav;
}

// f-key zoom: the focused pane spans the whole grid, the rest collapse.
export const PV_HIDE: CSSProperties = { display: "none" };
export const PV_ZOOM: CSSProperties = { gridColumn: "1 / -1", gridRow: "1 / -1", zIndex: 3 };

export const panelHatch = "height:2px;background-image:repeating-linear-gradient(135deg,var(--border) 0 1px,transparent 1px 3px);";

export const emptyNote = css(
  "padding:20px;font-family:var(--font-mono);font-size:11px;color:var(--text-faint);letter-spacing:0.04em;text-align:center;",
);
export const kv = css("padding:11px 13px;display:grid;grid-template-columns:96px 1fr;gap:6px 10px;font-size:11px;");
export const kLabel = css("color:var(--text-faint);letter-spacing:0.06em;");
export const kVal = css("color:var(--text-primary);word-break:break-word;");

export const codeHeadStyle = css(
  "display:flex;align-items:center;justify-content:space-between;gap:8px;padding:3px 8px;background:var(--surface-chrome);border-bottom:1px solid var(--border-soft);",
);
export const codePreStyle = css(
  "margin:0;padding:8px 10px;font-family:var(--font-mono);font-size:11px;line-height:1.5;color:var(--text-primary);white-space:pre;overflow:auto;max-height:340px;",
);
export const argRowStyle = css("display:grid;grid-template-columns:78px minmax(0,1fr);gap:8px;font-size:11px;padding:0 2px;");
export const detRowStyle = css("display:grid;grid-template-columns:82px minmax(0,1fr);gap:8px;font-size:11px;");
export const detLabel = css("color:var(--text-muted);letter-spacing:0.06em;text-transform:uppercase;");
export const detVal = css("color:var(--text-primary);word-break:break-word;");

// Body prose inside an expanded turn card's Section.
export const sectionProse = css(
  "font-family:var(--font-sans,system-ui);font-size:12.5px;line-height:1.62;color:var(--text-primary);text-wrap:pretty;max-width:80ch;white-space:pre-wrap;",
);
