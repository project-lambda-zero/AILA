import { useState, type CSSProperties } from "react";

import { WindowPanel } from "@/components/aila/WindowPanel";
import {
  DataGrid,
  MonoBadge,
  SectionHeader,
  type GridColumn,
} from "@/components/aila/mock";

import { useMcpCalls } from "../queries";

/** Operator audit trail of every MCP call AILA forwarded.
 *
 * One row per delegated forward() through audit_mcp_bridge or
 * ida_bridge. Auto-refreshes every 3 seconds so an operator running
 * an analyze, rank, or fuzz session sees the calls land in near-real
 * time. Drives the answer to "where are the MCP logs anyway?" -- they
 * are *here*, not buried in worker stdout.
 */

const CTRL: CSSProperties = {
  height: 26,
  padding: "0 8px",
  fontSize: 10,
  letterSpacing: "0.06em",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  fontFamily: "var(--font-mono)",
};

const LABEL: CSSProperties = {
  fontSize: 9,
  letterSpacing: "0.14em",
  color: "var(--text-faint)",
};

export function McpCallLogPage() {
  const [serverFilter, setServerFilter] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const { data, isLoading, isError } = useMcpCalls({
    serverId: serverFilter || undefined,
    status: statusFilter || undefined,
  });
  const rows = data?.data ?? [];

  const columns: GridColumn[] = [
    { label: "when", width: "100px" },
    { label: "server", width: "130px" },
    { label: "action", width: "1fr" },
    { label: "status", width: "90px", align: "center" },
    { label: "http", width: "60px", align: "right" },
    { label: "latency", width: "80px", align: "right" },
    { label: "error", width: "220px" },
  ];

  return (
    <div className="flex flex-col" style={{ gap: 14 }}>
      <SectionHeader icon="\u25c8" title="mcp call log" />

      <WindowPanel title="filters" tone="muted">
        <div
          className="flex items-center"
          style={{ gap: 10, flexWrap: "wrap" }}
        >
          <label
            className="flex items-center font-mono uppercase"
            style={{ gap: 6 }}
          >
            <span style={LABEL}>server</span>
            <select
              value={serverFilter}
              onChange={(e) => setServerFilter(e.target.value)}
              aria-label="Filter by MCP server"
              className="font-mono"
              style={CTRL}
            >
              <option value="">all</option>
              <option value="audit_mcp">audit-mcp</option>
              <option value="ida_headless">ida-headless</option>
            </select>
          </label>
          <label
            className="flex items-center font-mono uppercase"
            style={{ gap: 6 }}
          >
            <span style={LABEL}>status</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              aria-label="Filter by status"
              className="font-mono"
              style={CTRL}
            >
              <option value="">all</option>
              <option value="ready">ready</option>
              <option value="pending">pending</option>
              <option value="error">error</option>
            </select>
          </label>
          <span style={{ flex: 1 }} />
          <span
            className="font-mono tabular-nums uppercase"
            style={{
              fontSize: 10,
              letterSpacing: "0.08em",
              color: "var(--text-muted)",
            }}
          >
            {rows.length} row{rows.length === 1 ? "" : "s"}
          </span>
        </div>
      </WindowPanel>

      {isError ? (
        <WindowPanel title="error" tone="accent">
          <div
            className="font-mono"
            style={{
              padding: 12,
              fontSize: 11,
              color: "var(--accent)",
              letterSpacing: "0.04em",
            }}
          >
            failed to load call log.
          </div>
        </WindowPanel>
      ) : (
        <WindowPanel
          title="calls"
          tone="accent"
          flush
          actions={
            <span
              className="font-mono tabular-nums"
              style={{
                fontSize: 10,
                letterSpacing: "0.08em",
                color: "var(--text-muted)",
              }}
            >
              {rows.length}
            </span>
          }
        >
          <table className="sr-only">
            <caption>MCP call log</caption>
          </table>
          {isLoading ? (
            <div
              className="font-mono"
              style={{
                padding: 24,
                textAlign: "center",
                fontSize: 11,
                color: "var(--text-muted)",
                letterSpacing: "0.04em",
              }}
            >
              {"loading\u2026"}
            </div>
          ) : (
            <DataGrid
              columns={columns}
              rows={rows}
              getKey={(r) => r.id}
              renderCells={(r) => [
                <span
                  key="t"
                  style={{ fontSize: 10.5, color: "var(--text-muted)" }}
                >
                  {new Date(r.called_at).toLocaleTimeString()}
                </span>,
                <span
                  key="s"
                  style={{ fontSize: 10.5, color: "var(--text-primary)" }}
                >
                  {r.server_id}
                </span>,
                <span
                  key="a"
                  style={{
                    fontSize: 10.5,
                    color: "var(--text-primary)",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {r.action}
                </span>,
                <MonoBadge
                  key="st"
                  tone={
                    r.status === "ready"
                      ? "ok"
                      : r.status === "error"
                        ? "critical"
                        : "warn"
                  }
                >
                  {r.status}
                </MonoBadge>,
                <span
                  key="h"
                  style={{ fontSize: 10.5, color: "var(--text-primary)" }}
                >
                  {r.http_status ?? "\u2014"}
                </span>,
                <span
                  key="l"
                  style={{ fontSize: 10.5, color: "var(--text-muted)" }}
                >
                  {r.latency_ms != null ? `${r.latency_ms}ms` : "\u2014"}
                </span>,
                <span
                  key="e"
                  title={r.error_excerpt ?? ""}
                  style={{
                    fontSize: 10.5,
                    color: "var(--accent)",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {r.error_excerpt ?? ""}
                </span>,
              ]}
              empty={
                <div
                  className="font-mono"
                  style={{
                    padding: 34,
                    textAlign: "center",
                    fontSize: 11.5,
                    color: "var(--text-muted)",
                    letterSpacing: "0.04em",
                  }}
                >
                  no mcp calls have been logged yet. run an analyze, rank,
                  or upload to populate the log.
                </div>
              }
            />
          )}
        </WindowPanel>
      )}
    </div>
  );
}
