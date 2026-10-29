/** The sandbox Recent Runs tab: the recent execution history table. */

import type { JSX } from "react";

import { useSandboxHistory } from "../../../api/sandbox";
import type { SandboxHistoryRow } from "../../../api/sandbox";
import { css } from "../../css";
import { fmtDuration } from "./helpers";
import { btnGhost, chipOk, chipWarn } from "./styles";

export function SandboxHistoryTab(): JSX.Element {
  const q = useSandboxHistory();
  const rows: SandboxHistoryRow[] = q.data ?? [];

  return (
    <div style={css("flex:1;min-height:0;overflow:auto;padding:16px 20px;display:flex;flex-direction:column;gap:12px;")}>
      <div style={css("display:flex;align-items:center;justify-content:space-between;gap:8px;")}>
        <span style={css("font-family:var(--font-mono);font-size:11px;color:var(--text-muted);")}>
          Recent executions dispatched across the platform ({rows.length} records):
        </span>
        <button type="button" onClick={() => void q.refetch()} style={btnGhost}>
          refresh
        </button>
      </div>

      <div style={css("border:1px solid var(--border);border-radius:3px;background:var(--surface-card);overflow:hidden;")}>
        <table style={css("width:100%;border-collapse:collapse;font-family:var(--font-mono);font-size:11px;")}>
          <thead>
            <tr style={css("background:var(--surface-chrome);border-bottom:1px solid var(--border);text-align:left;color:var(--text-muted);font-size:11px;text-transform:uppercase;letter-spacing:0.06em;")}>
              <th style={css("padding:8px 12px;")}>Time</th>
              <th style={css("padding:8px 12px;")}>Command (argv)</th>
              <th style={css("padding:8px 12px;")}>Exit</th>
              <th style={css("padding:8px 12px;")}>Duration</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={4} style={css("padding:24px;text-align:center;color:var(--text-faint);")}>
                  No recent execution records found.
                </td>
              </tr>
            ) : (
              rows.map((r) => (
                <tr key={r.id} style={css("border-bottom:1px solid var(--border-soft);")}>
                  <td style={css("padding:8px 12px;color:var(--text-faint);white-space:nowrap;")}>
                    {new Date(r.created_at).toLocaleTimeString()}
                  </td>
                  <td style={css("padding:8px 12px;color:var(--text-primary);font-family:var(--font-mono);word-break:break-all;")}>
                    <code>{r.argv.join(" ")}</code>
                  </td>
                  <td style={css("padding:8px 12px;")}>
                    <span style={r.exit_code === 0 ? chipOk : chipWarn}>
                      exit {r.exit_code ?? "\u2014"}
                    </span>
                  </td>
                  <td style={css("padding:8px 12px;color:var(--text-muted);white-space:nowrap;")}>
                    {fmtDuration(r.duration_s)}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
