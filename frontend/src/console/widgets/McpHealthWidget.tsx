/** McpHealthWidget -- live MCP server probe status.
 *
 * GET /platform/mcp/servers live-probes every declared server per request.
 * We use the default 20s stale window (no aggressive refetchInterval, since
 * each read costs one probe per server). */

import type { JSX } from "react";
import { useQuery } from "@tanstack/react-query";

import { apiFetch } from "../../api/client";
import { css } from "../css";
import type { WidgetProps } from "./types";

interface McpServerRow {
  id: string;
  name: string;
  status: "reachable" | "unreachable" | string;
  latency_ms: number | null;
  last_probed_at: string | null;
  tool_count: number;
  error: string | null;
  module_scope: string;
}

const ROOT = css(
  "flex:1;min-height:0;display:flex;flex-direction:column;overflow:auto;" +
  "padding:10px 12px;background:var(--surface-card);" +
  "font-family:var(--font-mono);color:var(--text-primary);gap:6px;",
);

const LABEL = css(
  "font-size:9px;letter-spacing:0.12em;text-transform:uppercase;" +
  "color:var(--text-faint);margin-bottom:4px;",
);

const EMPTY = css("font-size:11px;color:var(--text-faint);padding:6px 0;");

const PILL = css(
  "padding:1px 5px;border-radius:2px;font-size:9px;letter-spacing:0.08em;" +
  "text-transform:uppercase;border:1px solid currentColor;",
);

function fmtWhen(iso: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}

export default function McpHealthWidget(_props: WidgetProps): JSX.Element {
  const q = useQuery({
    queryKey: ["platform", "mcp", "servers"],
    queryFn: () => apiFetch<McpServerRow[]>("/platform/mcp/servers"),
    staleTime: 20000,
  });

  if (q.isLoading) {
    return (
      <div style={ROOT}>
        <div style={LABEL}>mcp servers</div>
        <div style={EMPTY}>probing...</div>
      </div>
    );
  }
  if (q.isError) {
    return (
      <div style={ROOT}>
        <div style={LABEL}>mcp servers</div>
        <div style={{ ...EMPTY, color: "var(--status-warn)" }}>failed to load</div>
      </div>
    );
  }

  const rows = q.data ?? [];
  if (rows.length === 0) {
    return (
      <div style={ROOT}>
        <div style={LABEL}>mcp servers</div>
        <div style={EMPTY}>no servers declared</div>
      </div>
    );
  }

  return (
    <div style={ROOT}>
      <div style={LABEL}>mcp servers</div>
      {rows.map((row) => {
        const ok = row.status === "reachable";
        const pillColor = ok ? "var(--status-ok)" : "var(--status-warn)";
        return (
          <div
            key={row.id}
            style={{
              display: "flex",
              flexDirection: "column",
              gap: 2,
              padding: "4px 0",
              borderTop: "1px solid var(--border-faint)",
              fontSize: 11,
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ ...PILL, color: pillColor }}>{row.status}</span>
              <span style={{ color: "var(--text-primary)", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {row.name}
              </span>
              <span style={{ color: "var(--text-muted)", fontVariantNumeric: "tabular-nums" }}>
                {`${row.tool_count} tools`}
              </span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", gap: 8, color: "var(--text-faint)", fontSize: 10 }}>
              <span>{row.module_scope}</span>
              <span style={{ fontVariantNumeric: "tabular-nums" }}>{fmtWhen(row.last_probed_at)}</span>
            </div>
            {!ok && row.error ? (
              <div style={{ color: "var(--text-muted)", fontSize: 10, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {row.error.length > 120 ? `${row.error.slice(0, 117)}...` : row.error}
              </div>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}
