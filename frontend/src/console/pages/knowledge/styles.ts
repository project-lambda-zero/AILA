/** Shared styles for the knowledge page panels. */

import type { CSSProperties } from "react";

import { css } from "../../css";

export const PAGE_SIZE = 50;
export const CODE_LOOK_MAX = 240;
export const H_WARN = "#ffb85f";

export const panelBox: CSSProperties = css(
  "min-height:0;display:flex;flex-direction:column;border:1px solid var(--border);border-radius:var(--radius-md,3px);background:color-mix(in srgb,var(--surface-card) 84%,transparent);overflow:hidden;box-shadow:var(--bevel-raised,inset 1px 1px 0 rgba(255,255,255,0.03));",
);
export const panelTitle: CSSProperties = css(
  "flex:0 0 auto;display:flex;align-items:center;gap:10px;height:var(--panel-title-h,27px);padding:0 12px;background:var(--surface-chrome);border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:11px;text-transform:uppercase;letter-spacing:0.14em;color:var(--text-muted);",
);
export const dot: CSSProperties = css(
  "width:8px;height:8px;border-radius:1px;background:var(--accent);box-shadow:0 0 6px var(--accent);flex:0 0 auto;",
);
export const scroll: CSSProperties = css("flex:1;min-height:0;overflow:auto;");
export const pad: CSSProperties = css("padding:12px 13px;");
export const stack: CSSProperties = css("display:flex;flex-direction:column;gap:10px;");
export const emptyNote: CSSProperties = css(
  "flex:1;display:flex;align-items:center;justify-content:center;padding:20px;font-family:var(--font-mono);font-size:11px;color:var(--text-faint);letter-spacing:0.04em;text-align:center;",
);
export const inputStyle: CSSProperties = css(
  "background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:2px;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;padding:5px 8px;min-width:0;outline:none;",
);
export const labelStyle: CSSProperties = css(
  "display:flex;flex-direction:column;gap:3px;font-family:var(--font-mono);font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);min-width:0;",
);
export const btnPrimary: CSSProperties = css(
  "padding:5px 12px;border:1px solid var(--accent);border-radius:2px;background:transparent;color:var(--accent);font-family:var(--font-mono);font-size:11px;letter-spacing:0.1em;text-transform:uppercase;cursor:pointer;",
);
export const btnGhost: CSSProperties = css(
  "padding:4px 10px;border:1px solid var(--border-soft);border-radius:2px;background:transparent;color:var(--text-muted);font-family:var(--font-mono);font-size:11px;letter-spacing:0.1em;text-transform:uppercase;cursor:pointer;",
);
export const btnGhostDisabled: CSSProperties = css(
  "padding:4px 10px;border:1px solid var(--border-faint);border-radius:2px;background:transparent;color:var(--text-faint);font-family:var(--font-mono);font-size:11px;letter-spacing:0.1em;text-transform:uppercase;cursor:not-allowed;",
);
export const chip: CSSProperties = css(
  "display:inline-block;padding:1px 6px;border:1px solid var(--border-soft);border-radius:2px;font-family:var(--font-mono);font-size:11px;line-height:1.5;color:var(--text-primary);background:var(--surface-sunk);word-break:break-word;",
);
export const chipAccent: CSSProperties = css(
  "display:inline-block;padding:1px 6px;border:1px solid color-mix(in srgb,var(--accent) 55%,transparent);border-radius:2px;font-family:var(--font-mono);font-size:11px;line-height:1.5;color:var(--accent);background:color-mix(in srgb,var(--accent) 10%,transparent);word-break:break-word;",
);
export const chipFaint: CSSProperties = css(
  "display:inline-block;padding:1px 6px;border:1px solid var(--border-faint);border-radius:2px;font-family:var(--font-mono);font-size:11px;line-height:1.5;color:var(--text-faint);background:transparent;word-break:break-word;",
);
export const monoBlock: CSSProperties = css(
  "margin:0;padding:8px 10px;border:1px solid var(--border-soft);border-radius:2px;background:var(--surface-sunk);font-family:var(--font-mono);font-size:11px;line-height:1.5;color:var(--text-primary);white-space:pre-wrap;word-break:break-word;max-height:280px;overflow:auto;",
);
export const proseBlock: CSSProperties = css(
  "margin:0;font-family:var(--font-mono);font-size:11px;line-height:1.55;color:var(--text-primary);white-space:pre-wrap;word-break:break-word;max-height:200px;overflow:auto;",
);
export const hitCard: CSSProperties = css(
  "display:flex;flex-direction:column;gap:6px;padding:9px 11px;border:1px solid var(--border-soft);border-left:2px solid color-mix(in srgb,var(--accent) 55%,transparent);border-radius:2px;background:color-mix(in srgb,var(--surface-card) 60%,transparent);min-width:0;",
);
export const hitHeader: CSSProperties = css(
  "display:flex;align-items:center;gap:8px;flex-wrap:wrap;",
);
export const scoreChip: CSSProperties = css(
  "display:inline-flex;align-items:center;gap:4px;padding:1px 7px;border:1px solid color-mix(in srgb,var(--status-ok) 55%,transparent);border-radius:2px;font-family:var(--font-mono);font-size:11px;line-height:1.5;color:var(--status-ok);background:color-mix(in srgb,var(--status-ok) 10%,transparent);font-variant-numeric:tabular-nums;",
);
export const twoUp: CSSProperties = css(
  "display:grid;grid-template-columns:1fr 1fr;gap:12px;min-height:0;min-width:0;",
);
export const statFigure: CSSProperties = css(
  "display:flex;flex-direction:column;gap:2px;padding:12px 14px;border:1px solid var(--border-soft);border-radius:2px;background:var(--surface-sunk);min-width:0;",
);
export const statValue: CSSProperties = css(
  "font-family:var(--font-mono);font-size:22px;line-height:1.1;color:var(--accent);font-variant-numeric:tabular-nums;letter-spacing:0.02em;",
);
export const statLabel: CSSProperties = css(
  "font-family:var(--font-mono);font-size:11px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-faint);",
);
export const bucketRow: CSSProperties = css(
  "display:grid;grid-template-columns:1fr 40px 90px;gap:8px;align-items:center;padding:3px 0;font-family:var(--font-mono);font-size:11px;color:var(--text-primary);min-width:0;",
);
export const bucketLabelCell: CSSProperties = css(
  "min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text-primary);",
);
export const bucketCountCell: CSSProperties = css(
  "text-align:right;font-variant-numeric:tabular-nums;color:var(--text-muted);",
);
export const barTrack: CSSProperties = css(
  "position:relative;height:6px;background:var(--surface-sunk);border:1px solid var(--border-faint);border-radius:1px;overflow:hidden;",
);
export const kvGrid: CSSProperties = css(
  "display:grid;grid-template-columns:minmax(120px,140px) 1fr;gap:5px 12px;font-size:11px;font-family:var(--font-mono);color:var(--text-primary);align-content:start;",
);
export const kvLabel: CSSProperties = css(
  "color:var(--text-faint);letter-spacing:0.04em;text-transform:uppercase;font-size:11px;",
);
export const kvVal: CSSProperties = css("color:var(--text-primary);word-break:break-word;min-width:0;");
export const tableEl: CSSProperties = css(
  "width:100%;border-collapse:collapse;font-family:var(--font-mono);font-size:11px;",
);
export const thStyle: CSSProperties = css(
  "position:sticky;top:0;text-align:left;padding:7px 10px;background:var(--surface-chrome);border-bottom:1px solid var(--border);font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);white-space:nowrap;z-index:1;",
);
export const tdStyle: CSSProperties = css(
  "padding:6px 10px;border-bottom:1px solid var(--border-faint);color:var(--text-primary);vertical-align:top;max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;",
);
export const modalBackdrop: CSSProperties = css(
  "position:fixed;inset:0;z-index:60;display:flex;align-items:center;justify-content:center;padding:24px;background:color-mix(in srgb,var(--surface-base,#0b0b0b) 62%,transparent);backdrop-filter:blur(2px);",
);
export const modalCard: CSSProperties = css(
  "width:min(560px,94vw);max-height:88vh;display:flex;flex-direction:column;border:1px solid var(--border);border-radius:var(--radius-md,3px);background:var(--surface-card);overflow:hidden;box-shadow:0 18px 48px rgba(0,0,0,0.5);",
);
export const textareaStyle: CSSProperties = css(
  "background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:2px;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;line-height:1.55;padding:8px 10px;min-width:0;outline:none;resize:vertical;min-height:120px;",
);
export const headerBtn: CSSProperties = css(
  "padding:4px 11px;border:1px solid var(--accent);border-radius:2px;background:color-mix(in srgb,var(--accent) 10%,transparent);color:var(--accent);font-family:var(--font-mono);font-size:11px;letter-spacing:0.12em;text-transform:uppercase;cursor:pointer;",
);
