import type { ReactNode } from "react";

import { css } from "../css";
import { StructuredData } from "../StructuredData";

/** Audit action summary followed by structured detail fields. */

/** Parse an ISO timestamp to the local wall-clock string; fall back to the
 * raw string on an unparseable value rather than printing "Invalid Date". */
function fmtWhen(value: unknown): string {
  const s = value === null || value === undefined ? "" : String(value);
  if (!s) return "";
  const t = Date.parse(s);
  return Number.isNaN(t) ? s : new Date(t).toLocaleString();
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
  return (
    <div style={css("display:flex;flex-direction:column;gap:8px;min-width:0;")}>
      <div style={css("color:var(--text-primary);line-height:1.5;word-break:break-word;")}>
        <b>{actor}</b> {action} <b>{target}</b>
        {when ? ` at ${when}` : ""}
        {" \u2192 "}
        {status}
      </div>
      <StructuredData label="Audit detail" value={value} />
    </div>
  );
}
