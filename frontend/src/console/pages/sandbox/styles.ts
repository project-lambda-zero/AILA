/** Shared styles for the sandbox page (top bar, buttons, chips, inputs). */

import type { CSSProperties } from "react";

import { css } from "../../css";

export const H_WARN = "#ffb85f";

export const topBar: CSSProperties = css(
  "flex:0 0 auto;display:flex;align-items:center;justify-content:space-between;gap:12px;padding:8px 14px;background:var(--surface-chrome);border-bottom:1px solid var(--border);flex-wrap:wrap;",
);

export const controlGroup: CSSProperties = css(
  "display:flex;align-items:center;gap:8px;flex-wrap:wrap;",
);

export const selectStyle: CSSProperties = css(
  "background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:2px;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;padding:4px 8px;min-width:180px;outline:none;",
);

export const btnPrimary: CSSProperties = css(
  "padding:4px 12px;border:1px solid var(--accent);border-radius:2px;background:color-mix(in srgb,var(--accent) 15%,transparent);color:var(--accent);font-family:var(--font-mono);font-size:11px;font-weight:600;letter-spacing:0.06em;text-transform:uppercase;cursor:pointer;",
);

export const btnPrimaryDisabled: CSSProperties = css(
  "padding:4px 12px;border:1px solid var(--border-faint);border-radius:2px;background:transparent;color:var(--text-faint);font-family:var(--font-mono);font-size:11px;letter-spacing:0.06em;text-transform:uppercase;cursor:not-allowed;",
);

export const btnGhost: CSSProperties = css(
  "padding:4px 9px;border:1px solid var(--border-soft);border-radius:2px;background:transparent;color:var(--text-muted);font-family:var(--font-mono);font-size:11px;letter-spacing:0.04em;cursor:pointer;",
);

export const btnGhostActive: CSSProperties = css(
  "padding:4px 9px;border:1px solid var(--accent);border-radius:2px;background:color-mix(in srgb,var(--accent) 12%,transparent);color:var(--accent);font-family:var(--font-mono);font-size:11px;font-weight:600;letter-spacing:0.04em;cursor:pointer;",
);

export const chipOk: CSSProperties = css(
  "display:inline-flex;align-items:center;gap:4px;padding:2px 7px;border:1px solid color-mix(in srgb,var(--status-ok,#4ade80) 55%,transparent);border-radius:2px;font-family:var(--font-mono);font-size:11px;line-height:1.5;letter-spacing:0.04em;color:var(--status-ok,#4ade80);background:color-mix(in srgb,var(--status-ok,#4ade80) 10%,transparent);",
);

export const chipWarn: CSSProperties = css(
  `display:inline-flex;align-items:center;gap:4px;padding:2px 7px;border:1px solid color-mix(in srgb,${H_WARN} 55%,transparent);border-radius:2px;font-family:var(--font-mono);font-size:11px;line-height:1.5;letter-spacing:0.04em;color:${H_WARN};background:color-mix(in srgb,${H_WARN} 10%,transparent);`,
);

export const chipFaint: CSSProperties = css(
  "display:inline-flex;align-items:center;gap:4px;padding:2px 7px;border:1px solid var(--border-faint);border-radius:2px;font-family:var(--font-mono);font-size:11px;line-height:1.5;color:var(--text-faint);background:transparent;",
);

export const inputStyle: CSSProperties = css(
  "flex:1;background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:2px;color:var(--text-primary);font-family:var(--font-mono);font-size:12px;padding:6px 10px;outline:none;",
);
