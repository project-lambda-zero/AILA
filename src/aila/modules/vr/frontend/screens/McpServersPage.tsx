import { useState } from "react";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { useUpdateMcpServer } from "../mutations";
import { useMcpServers } from "../queries";
import type { McpServerSummary } from "../types";

/** Operator-facing MCP server registry.
 *
 * AILA does no analysis itself — it orchestrates external MCP servers
 * (one per workstation). This page surfaces:
 *
 *  - which servers are registered (audit-mcp, ida-headless-mcp)
 *  - the URL each one currently resolves to and where that URL came
 *    from (env / config / default)
 *  - live reachability + tool count + probe latency
 *  - a retarget form that persists to ConfigRegistry so the operator
 *    can swap workstations without editing env vars
 */
export function McpServersPage() {
  const { data: result, isLoading, isError } = useMcpServers();
  const servers = result?.data ?? [];

  if (isLoading) return <LoadingSkeleton size="lg" width="full" />;
  if (isError) {
    return (
      <AilaCard className="border-border-danger" techBorder glow><p className="text-sm text-text-danger">Failed to load MCP servers.</p></AilaCard>
    );
  }

  return (
    <div className="space-y-4">

      {servers.map((s) => (
        <ServerCard key={s.id} server={s} />
      ))}
    </div>
  );
}

function ServerCard({ server }: { server: McpServerSummary }) {
  const [editing, setEditing] = useState(false);
  const [draftUrl, setDraftUrl] = useState(server.base_url);
  const update = useUpdateMcpServer();
  const [showTools, setShowTools] = useState(false);

  const reachable = server.status === "reachable";

  return (
    <AilaCard className={!reachable ? "border-border-danger" : undefined} techBorder glow><div className="flex items-start justify-between gap-3 flex-wrap">
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 flex-wrap">
          <h2 className="text-sm font-semibold text-foreground font-mono">
            {server.name}
          </h2>
          <AilaBadge
            severity={reachable ? "low" : "critical"}
            size="sm"
          >
            {reachable ? "Reachable" : "Unreachable"}
          </AilaBadge>
          {reachable && server.latency_ms !== null && (
            <AilaBadge severity="info" size="sm">
              {server.latency_ms} ms
            </AilaBadge>
          )}
          {reachable && (
            <AilaBadge severity="info" size="sm">
              {server.tool_count} tools
            </AilaBadge>
          )}
          <AilaBadge
            severity={server.base_url_source === "default" ? "info" : "medium"}
            size="sm"
          >
            source: {server.base_url_source}
          </AilaBadge>
        </div>
        <p className="text-xs text-text-muted mt-1">{server.description}</p>
      </div>
    </div>
    
    <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
      <div>
        <dt className="text-text-muted">Base URL</dt>
        <dd className="font-mono break-all">{server.base_url}</dd>
      </div>
      <div>
        <dt className="text-text-muted">Last probed</dt>
        <dd className="font-mono">
          {new Date(server.last_probed_at).toLocaleTimeString()}
        </dd>
      </div>
      <div>
        <dt className="text-text-muted">Env var</dt>
        <dd className="font-mono">{server.env_var}</dd>
      </div>
      <div>
        <dt className="text-text-muted">Config key</dt>
        <dd className="font-mono">vr.{server.config_key}</dd>
      </div>
    </div>
    
    {server.error && (
      <div className="mt-3 p-2 bg-surface-danger/10 border border-border-danger rounded text-xs text-text-danger font-mono break-all">
        {server.error}
      </div>
    )}
    
    <div className="mt-3 flex items-center gap-2 flex-wrap">
      {!editing ? (
        <button
          type="button"
          onClick={() => {
            setDraftUrl(server.base_url);
            setEditing(true);
          }}
          className="px-3 py-1.5 text-xs font-medium rounded-md bg-surface border border-border-default hover:bg-surface-hover"
        >
          Retarget
        </button>
      ) : (
        <form
          className="flex items-center gap-2 flex-1 min-w-0"
          onSubmit={(e) => {
            e.preventDefault();
            update.mutate(
              { serverId: server.id, baseUrl: draftUrl.trim() },
              {
                onSuccess: () => setEditing(false),
              },
            );
          }}
        >
          <input
            type="url"
            value={draftUrl}
            onChange={(e) => setDraftUrl(e.target.value)}
            placeholder="https://workstation.local:18822"
            aria-label="MCP server URL"
            className="flex-1 px-3 py-1.5 text-xs font-mono rounded-md bg-surface border border-border-default focus:outline-none focus:border-accent"
          />
          <button
            type="submit"
            disabled={update.isPending || !draftUrl.trim()}
            className="px-3 py-1.5 text-xs font-medium rounded-md bg-accent text-white hover:bg-accent/90 disabled:opacity-50"
          >
            {update.isPending ? "Saving…" : "Save"}
          </button>
          <button
            type="button"
            onClick={() => setEditing(false)}
            className="px-3 py-1.5 text-xs font-medium rounded-md bg-surface border border-border-default hover:bg-surface-hover"
          >
            Cancel
          </button>
        </form>
      )}
      {server.base_url !== server.default_url && (
        <button
          type="button"
          onClick={() =>
            update.mutate({ serverId: server.id, baseUrl: server.default_url })
          }
          disabled={update.isPending}
          className="px-3 py-1.5 text-xs font-medium rounded-md bg-surface border border-border-default hover:bg-surface-hover disabled:opacity-50"
          title={`Reset to ${server.default_url}`}
        >
          Reset to default
        </button>
      )}
      {reachable && server.tool_count > 0 && (
        <button
          type="button"
          onClick={() => setShowTools((v) => !v)}
          className="px-3 py-1.5 text-xs font-medium rounded-md bg-surface border border-border-default hover:bg-surface-hover"
        >
          {showTools ? "Hide tools" : `Show ${server.tool_count} tools`}
        </button>
      )}
    </div>
    
    {showTools && reachable && (
      <div className="mt-3 grid grid-cols-2 md:grid-cols-4 gap-1 text-xs font-mono text-text-muted max-h-64 overflow-y-auto">
        {server.tools.map((t) => (
          <div key={t} className="truncate">
            {t}
          </div>
        ))}
      </div>
    )}</AilaCard>
  );
}
