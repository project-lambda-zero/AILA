/** Shared field chrome for the console wizards: the label/column/input/help
 * styles every wizard re-declared inline, plus the ApiError-to-message
 * helper they all copy. */

import { ApiError } from "../../api/client";
import { css } from "../css";

export const labelStyle = css(
  "font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);",
);
export const fieldCol = css("display:flex;flex-direction:column;gap:4px;");
export const inputStyleRaw =
  "background:var(--surface-sunk);border:1px solid var(--border-soft);outline:none;padding:7px 9px;color:var(--text-primary);font-family:var(--font-mono);font-size:11.5px;border-radius:2px;";
export const inputStyle = css(inputStyleRaw);
export const selectStyle = inputStyle;
export const helpText = css("font-size:11px;color:var(--text-faint);line-height:1.5;");

/** Best-effort message out of a thrown mutation/query error. */
export function apiErrMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message || `HTTP ${err.status}`;
  if (err instanceof Error) return err.message;
  return String(err);
}
