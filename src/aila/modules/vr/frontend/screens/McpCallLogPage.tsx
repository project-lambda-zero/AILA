import { useState } from "react";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";

import { useMcpCalls } from "../queries";

/** Operator audit trail of every MCP call AILA forwarded.
 *
 * One row per delegated forward() through audit_mcp_bridge or
 * ida_bridge. Auto-refreshes every 3 seconds so an operator running
 * an analyze, rank, or fuzz session sees the calls land in near-real
 * time. Drives the answer to "where are the MCP logs anyway?" — they
 * are *here*, not buried in worker stdout. */
export function McpCallLogPage() {
  const [serverFilter, setServerFilter] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const { data, isLoading, isError } = useMcpCalls({
    serverId: serverFilter || undefined,
    status: statusFilter || undefined,
  });
  const rows = data?.data ?? [];

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-bold font-mono text-foreground">
          MCP Call Log
        </h1>
        <p className="text-sm text-text-muted mt-1">
          Live audit trail of every call AILA forwards to an MCP server.
          Refreshes every 3 seconds.
        </p>
      </div>

      <div className="flex flex-wrap gap-2 items-center">
        <label className="text-xs text-text-muted">Server:</label>
        <select
          value={serverFilter}
          onChange={(e) => setServerFilter(e.target.value)}
          className="px-2 py-1 text-xs rounded-md bg-surface border border-border-default"
        >
          <option value="">all</option>
          <option value="audit_mcp">audit-mcp</option>
          <option value="ida_headless">ida-headless</option>
        </select>
        <label className="text-xs text-text-muted ml-3">Status:</label>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="px-2 py-1 text-xs rounded-md bg-surface border border-border-default"
        >
          <option value="">all</option>
          <option value="ready">ready</option>
          <option value="pending">pending</option>
          <option value="error">error</option>
        </select>
        <span className="text-xs text-text-muted ml-auto">
          {rows.length} row{rows.length === 1 ? "" : "s"}
        </span>
      </div>

      {isLoading && <AilaCard><p className="text-sm text-text-muted">Loading…</p></AilaCard>}
      {isError && (
        <AilaCard className="border-border-danger">
          <p className="text-sm text-text-danger">Failed to load call log.</p>
        </AilaCard>
      )}
      {!isLoading && rows.length === 0 && (
        <AilaCard>
          <p className="text-sm text-text-muted text-center py-4">
            No MCP calls have been logged yet. Run an analyze, rank, or upload
            to populate the log.
          </p>
        </AilaCard>
      )}

      {rows.length > 0 && (
        <AilaCard>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border-default text-left text-text-muted">
                  <th className="px-2 py-1 font-semibold">When</th>
                  <th className="px-2 py-1 font-semibold">Server</th>
                  <th className="px-2 py-1 font-semibold">Action</th>
                  <th className="px-2 py-1 font-semibold">Status</th>
                  <th className="px-2 py-1 font-semibold text-right">HTTP</th>
                  <th className="px-2 py-1 font-semibold text-right">Latency</th>
                  <th className="px-2 py-1 font-semibold">Error</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr
                    key={r.id}
                    className="border-b border-border-default last:border-b-0"
                  >
                    <td className="px-2 py-1 font-mono text-text-muted whitespace-nowrap">
                      {new Date(r.called_at).toLocaleTimeString()}
                    </td>
                    <td className="px-2 py-1 font-mono text-foreground">
                      {r.server_id}
                    </td>
                    <td className="px-2 py-1 font-mono text-foreground">
                      {r.action}
                    </td>
                    <td className="px-2 py-1">
                      <AilaBadge
                        severity={
                          r.status === "ready"
                            ? "low"
                            : r.status === "error"
                              ? "critical"
                              : "medium"
                        }
                        size="sm"
                      >
                        {r.status}
                      </AilaBadge>
                    </td>
                    <td className="px-2 py-1 font-mono text-right text-foreground">
                      {r.http_status ?? "—"}
                    </td>
                    <td className="px-2 py-1 font-mono text-right text-text-muted">
                      {r.latency_ms != null ? `${r.latency_ms}ms` : "—"}
                    </td>
                    <td className="px-2 py-1 font-mono text-text-danger truncate max-w-[28ch]" title={r.error_excerpt ?? ""}>
                      {r.error_excerpt ?? ""}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </AilaCard>
      )}
    </div>
  );
}
