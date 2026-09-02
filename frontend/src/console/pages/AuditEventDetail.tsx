import type { ReactNode } from "react";

import { css } from "../css";

/**
 * Humanized detail body for one audit event. Reads the whole row so the
 * `details` cell reads as a plain sentence ("<actor> <action> <target> at
 * <when> -> <status>") ABOVE the parsed `details_json` payload. The raw JSON
 * is never hidden -- it renders in a mono block below the sentence so an
 * operator gets both the read and the ground truth (spec req 51).
 */

/** Parse an ISO timestamp to the local wall-clock string; fall back to the
 * raw string on an unparseable value rather than printing "Invalid Date". */
function fmtWhen(value: unknown): string {
  const s = value === null || value === undefined ? "" : String(value);
  if (!s) return "";
  const t = Date.parse(s);
  return Number.isNaN(t) ? s : new Date(t).toLocaleString();
}

/** Pretty-print the parsed `details` payload: a non-empty object becomes
 * indented JSON, a scalar becomes its string, and an empty/absent payload
 * returns null so the caller renders an honest "no payload" note. */
function prettyDetails(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value !== "object") {
    const s = String(value);
    return s === "" ? null : s;
  }
  if (Object.keys(value as Record<string, unknown>).length === 0) return null;
  return JSON.stringify(value, null, 2);
}

export function AuditEventDetail({
  value,
  row,
}: {
  value: unknown;
  row: Record<string, unknown>;
}): ReactNode {
  const actor = String(row["user_id"] ?? "").trim() || "system";
  const action = String(row["action"] ?? "").trim() || "acted";
  const target = String(row["target"] ?? "").trim() || "(no target)";
  const status = String(row["status"] ?? "").trim() || "unknown";
  const when = fmtWhen(row["created_at"]);
  const json = prettyDetails(value);
  return (
    <div style={css("display:flex;flex-direction:column;gap:8px;min-width:0;")}>
      <div style={css("color:var(--text-primary);line-height:1.5;word-break:break-word;")}>
        <b>{actor}</b> {action} <b>{target}</b>
        {when ? ` at ${when}` : ""}
        {" \u2192 "}
        {status}
      </div>
      {json ? (
        <pre
          style={css(
            "margin:0;padding:8px 10px;background:var(--surface-card);border:1px solid var(--border-soft);border-radius:2px;font-family:var(--font-mono);font-size:10.5px;line-height:1.45;white-space:pre-wrap;word-break:break-word;overflow:auto;max-height:320px;color:var(--text-primary);",
          )}
        >
          {json}
        </pre>
      ) : (
        <span style={css("color:var(--text-faint);font-size:10.5px;")}>no detail payload</span>
      )}
    </div>
  );
}
