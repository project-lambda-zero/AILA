import { useQuery } from "@tanstack/react-query";
import type { JSX } from "react";

import { apiFetch } from "../../api/client";
import { asRecord } from "../../api/parse";
import { css } from "../css";
import { StatusBadge } from "./badges";

/** Shape of GET /platform/mcp/instances/{id}/tools (apiFetch unwraps the
 * envelope so the returned body is the McpInstanceToolsResponse itself). */
interface ToolsBody {
  tools: unknown[];
  schema_hash: string;
  approved_hash: string | null;
  drift: boolean;
}

/** Row-detail body for `admin:mcp-instances`: fetches the live tool schema
 * from the bridge and renders it against the pinned `approved_hash` so the
 * operator can see drift without hitting the bridge by hand. Mirrors the
 * bespoke-detail pattern used by admin:automation-actions. */
export function McpInstanceToolsDetail({
  row,
}: {
  row: Record<string, unknown>;
}): JSX.Element {
  const instanceId = String(row["id"] ?? "");
  const approvalState = String(row["approval_state"] ?? "");
  const q = useQuery<ToolsBody>({
    queryKey: ["mcp-instance-tools", instanceId],
    queryFn: () => apiFetch<ToolsBody>(`/platform/mcp/instances/${encodeURIComponent(instanceId)}/tools`),
    enabled: instanceId !== "",
    retry: false,
    refetchOnWindowFocus: false,
  });
  const body = q.data;
  const tools: Record<string, unknown>[] = body && Array.isArray(body.tools)
    ? body.tools.map((t) => asRecord(t) ?? {})
    : [];
  const driftTone: "warn" | "ok" | "muted" = body?.drift
    ? "warn"
    : body?.approved_hash
      ? "ok"
      : "muted";
  const driftLabel = body?.drift
    ? "drift"
    : body?.approved_hash
      ? "in sync"
      : "unapproved";
  return (
    <div style={css("display:flex;flex-direction:column;gap:12px;")}>
      <div style={css("display:grid;grid-template-columns:120px 1fr;gap:5px 12px;font-size:11.5px;align-items:center;")}>
        <span style={css("color:var(--text-faint);")}>instance</span>
        <span style={css("color:var(--text-primary);font-family:var(--font-mono);word-break:break-all;")}>{instanceId}</span>
        <span style={css("color:var(--text-faint);")}>approval</span>
        <span style={css("color:var(--text-primary);")}>{approvalState}</span>
        <span style={css("color:var(--text-faint);")}>schema hash</span>
        <span style={css("color:var(--text-primary);font-family:var(--font-mono);word-break:break-all;")}>{body?.schema_hash ?? "\u2014"}</span>
        <span style={css("color:var(--text-faint);")}>approved hash</span>
        <span style={css("color:var(--text-primary);font-family:var(--font-mono);word-break:break-all;")}>{body?.approved_hash ?? "\u2014"}</span>
        <span style={css("color:var(--text-faint);")}>drift</span>
        <span>
          <StatusBadge value={driftLabel} tone={driftTone} />
        </span>
      </div>
      {q.isLoading ? (
        <div style={css("font-family:var(--font-mono);font-size:11px;color:var(--text-faint);")}>loading live tool schema...</div>
      ) : null}
      {q.error ? (
        <div style={css("font-family:var(--font-mono);font-size:11px;color:#ffb85f;")}>failed to load tools: {(q.error as Error).message}</div>
      ) : null}
      {body ? (
        <div style={css("display:flex;flex-direction:column;gap:6px;")}>
          <div style={css("font-family:var(--font-mono);font-size:9px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-faint);")}>tools ({tools.length})</div>
          <div style={css("display:flex;flex-direction:column;gap:4px;")}>
            {tools.length === 0 ? (
              <div style={css("font-family:var(--font-mono);font-size:11px;color:var(--text-faint);")}>the bridge returned no tools</div>
            ) : (
              tools.map((t, i) => {
                const name = String(t["name"] ?? `tool-${i}`);
                const desc = String(t["description"] ?? "");
                return (
                  <div key={name + ":" + i} style={css("border:1px solid var(--border-soft);border-radius:2px;padding:6px 8px;display:flex;flex-direction:column;gap:2px;")}>
                    <div style={css("font-family:var(--font-mono);font-size:11px;color:var(--text-primary);")}>{name}</div>
                    {desc ? (
                      <div style={css("font-size:10.5px;color:var(--text-muted);line-height:1.4;")}>{desc}</div>
                    ) : null}
                  </div>
                );
              })
            )}
          </div>
        </div>
      ) : null}
    </div>
  );
}
