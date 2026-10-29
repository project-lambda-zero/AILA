/** Shared DataPage styling. Raw strings (PANEL_BOX, FILTER_CTL, ACTION_INPUT)
 * are concatenated per widget; the rest are resolved style objects. */

import type { CSSProperties } from "react";

import { css } from "../../css";
import type { PageAction } from "./types";

export const H_WARN = "#ffb85f";

export const emptyNote = css(
  "flex:1;display:flex;align-items:center;justify-content:center;padding:20px;font-family:var(--font-mono);font-size:11px;color:var(--text-faint);letter-spacing:0.04em;text-align:center;",
);
export const PANEL_BOX =
  ";min-height:0;display:flex;flex-direction:column;border:1px solid var(--border);border-radius:var(--radius-md,3px);background:color-mix(in srgb,var(--surface-card) 84%,transparent);overflow:hidden;box-shadow:var(--bevel-raised,inset 1px 1px 0 rgba(255,255,255,0.03));";
export const panelTitle = css(
  "flex:0 0 auto;display:flex;align-items:center;gap:10px;height:var(--panel-title-h,27px);padding:0 12px;background:var(--surface-chrome);border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:11px;text-transform:uppercase;letter-spacing:0.14em;color:var(--text-muted);",
);
export const dot = css("width:8px;height:8px;border-radius:1px;background:var(--accent);box-shadow:0 0 6px var(--accent);flex:0 0 auto;");
export const panelHeading = css("color:var(--text-primary);font-family:var(--font-display);font-weight:400;");
export const FILTER_CTL =
  "background:var(--surface-sunk);border:1px solid var(--border-soft);color:var(--text-muted);font-family:var(--font-mono);font-size:11px;padding:3px 8px;border-radius:2px;text-transform:none;letter-spacing:normal;";
export const ACTION_INPUT =
  "background:var(--surface-sunk);border:1px solid var(--border);border-radius:2px;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;padding:6px 8px;letter-spacing:0.02em;text-transform:none;outline:none;";
export const actionLabel = css(
  "display:flex;flex-direction:column;gap:4px;font-family:var(--font-mono);font-size:11px;letter-spacing:0.06em;text-transform:uppercase;color:var(--text-muted);",
);
export const actionErrBox = css(
  "border:1px solid #ffb85f;border-radius:2px;padding:7px 9px;background:color-mix(in srgb,#ffb85f 12%,transparent);color:#ffb85f;font-family:var(--font-mono);font-size:11px;letter-spacing:0.02em;text-transform:none;",
);
export const actionPrimaryBtn = css(
  "padding:6px 14px;border:1px solid var(--accent);background:var(--accent);color:var(--text-on-accent);font-family:var(--font-mono);font-size:11px;letter-spacing:0.1em;text-transform:uppercase;cursor:pointer;border-radius:2px;",
);
export const actionGhostBtn = css(
  "padding:6px 12px;border:1px solid var(--border);background:transparent;color:var(--text-muted);font-family:var(--font-mono);font-size:11px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;border-radius:2px;",
);
export const modalScrim = (z: number): CSSProperties =>
  css(`position:absolute;inset:0;background:rgba(0,0,0,0.55);display:flex;align-items:center;justify-content:center;padding:32px;z-index:${z};`);
export const modalCard = (width: number): CSSProperties =>
  css(
    `width:min(${width}px,100%);max-height:100%;overflow:auto;display:flex;flex-direction:column;gap:12px;padding:18px;background:var(--surface-card);border:1px solid var(--border);border-radius:3px;`,
  );
export const modalTitle = css(
  "font-family:var(--font-mono);font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-primary);",
);

/** Outlined action button, toned warn when the action is destructive.
 * `padding` differs between the filter bar (4px 10px) and detail header
 * (3px 10px). */
export function actionBtn(a: PageAction, padding: string): CSSProperties {
  const tone = a.destructive ? H_WARN : "var(--accent)";
  return css(
    `padding:${padding};border:1px solid ${tone}66;border-radius:2px;background:transparent;color:${tone};font-family:var(--font-mono);font-size:11px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;`,
  );
}
