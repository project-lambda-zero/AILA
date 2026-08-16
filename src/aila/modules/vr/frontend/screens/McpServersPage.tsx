import { useState, type CSSProperties } from "react";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { MonoBadge, SectionHeader } from "@/components/aila/mock";

import { useUpdateMcpServer } from "../mutations";
import { useMcpServers } from "../queries";
import type { McpServerSummary } from "../types";

/** Operator-facing MCP server registry.
 *
 * AILA does no analysis itself -- it orchestrates external MCP servers
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

  return (
    <div className="flex flex-col" style={{ gap: 14 }}>
      <SectionHeader icon="\u25c8" title="mcp servers" />

      {isLoading ? (
        <LoadingSkeleton size="lg" width="full" />
      ) : isError ? (
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
            failed to load mcp servers.
          </div>
        </WindowPanel>
      ) : servers.length === 0 ? (
        <WindowPanel title="registry" tone="muted">
          <div
            className="font-mono"
            style={{
              padding: 24,
              textAlign: "center",
              fontSize: 11.5,
              color: "var(--text-muted)",
              letterSpacing: "0.04em",
            }}
          >
            no mcp servers registered.
          </div>
        </WindowPanel>
      ) : (
        servers.map((s) => <ServerCard key={s.id} server={s} />)
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// One WindowPanel per server. Title bar carries the ID; body has the brief
// rows + retarget/reset/tools controls. Tone flips to accent on unreachable.
// ---------------------------------------------------------------------------

const CTRL: CSSProperties = {
  height: 26,
  padding: "0 8px",
  fontSize: 10,
  letterSpacing: "0.04em",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  fontFamily: "var(--font-mono)",
};

function actionButton({
  primary = false,
  disabled = false,
}: {
  primary?: boolean;
  disabled?: boolean;
}): CSSProperties {
  return {
    height: 26,
    padding: "0 12px",
    fontSize: 10,
    letterSpacing: "0.08em",
    background: primary ? "var(--accent)" : "var(--surface-sunk)",
    border: `1px solid ${primary ? "var(--accent)" : "var(--border-soft)"}`,
    color: primary ? "var(--text-on-accent)" : "var(--text-primary)",
    borderRadius: 3,
    cursor: disabled ? "not-allowed" : "pointer",
    opacity: disabled ? 0.5 : 1,
    fontFamily: "var(--font-mono)",
    textTransform: "uppercase",
  };
}

function BriefRow({
  label,
  children,
}: {
  label: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 3,
        padding: "8px 0",
        borderBottom: "1px solid var(--border-faint)",
      }}
    >
      <span
        className="font-mono uppercase"
        style={{
          fontSize: 9,
          letterSpacing: "0.14em",
          color: "var(--text-faint)",
        }}
      >
        {label}
      </span>
      <span
        className="font-mono"
        style={{
          fontSize: 11,
          color: "var(--text-primary)",
          minHeight: 14,
          overflowWrap: "anywhere",
        }}
      >
        {children}
      </span>
    </div>
  );
}

function ServerCard({ server }: { server: McpServerSummary }) {
  const [editing, setEditing] = useState(false);
  const [draftUrl, setDraftUrl] = useState(server.base_url);
  const update = useUpdateMcpServer();
  const [showTools, setShowTools] = useState(false);

  const reachable = server.status === "reachable";

  const headerActions = (
    <div
      className="flex items-center"
      style={{ gap: 6, flexWrap: "wrap" }}
    >
      <MonoBadge tone={reachable ? "ok" : "critical"}>
        {reachable ? "reachable" : "unreachable"}
      </MonoBadge>
      {reachable && server.latency_ms !== null && (
        <MonoBadge tone="info">{server.latency_ms} ms</MonoBadge>
      )}
      {reachable && (
        <MonoBadge tone="info">{server.tool_count} tools</MonoBadge>
      )}
      <MonoBadge tone={server.base_url_source === "default" ? "info" : "warn"}>
        src: {server.base_url_source}
      </MonoBadge>
    </div>
  );

  return (
    <WindowPanel
      title={server.name}
      tone={reachable ? "info" : "accent"}
      actions={headerActions}
    >
      <p
        className="font-mono"
        style={{
          fontSize: 10.5,
          lineHeight: 1.5,
          color: "var(--text-muted)",
          letterSpacing: "0.02em",
          marginTop: 0,
        }}
      >
        {server.description}
      </p>

      <div
        className="grid"
        style={{
          gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
          gap: "0 16px",
          marginTop: 8,
        }}
      >
        <BriefRow label="base url">{server.base_url}</BriefRow>
        <BriefRow label="last probed">
          {new Date(server.last_probed_at).toLocaleTimeString()}
        </BriefRow>
        <BriefRow label="env var">{server.env_var}</BriefRow>
        <BriefRow label="config key">vr.{server.config_key}</BriefRow>
      </div>

      {server.error && (
        <div
          className="font-mono"
          style={{
            marginTop: 10,
            padding: 8,
            fontSize: 10.5,
            color: "var(--accent)",
            background: "var(--surface-sunk)",
            border: "1px solid var(--accent)",
            borderRadius: 3,
            overflowWrap: "anywhere",
          }}
        >
          {server.error}
        </div>
      )}

      <div
        className="flex items-center"
        style={{ gap: 6, flexWrap: "wrap", marginTop: 12 }}
      >
        {!editing ? (
          <button
            type="button"
            onClick={() => {
              setDraftUrl(server.base_url);
              setEditing(true);
            }}
            style={actionButton({})}
          >
            retarget
          </button>
        ) : (
          <form
            className="flex items-center"
            style={{ gap: 6, flex: 1, minWidth: 0 }}
            onSubmit={(e) => {
              e.preventDefault();
              update.mutate(
                { serverId: server.id, baseUrl: draftUrl.trim() },
                { onSuccess: () => setEditing(false) },
              );
            }}
          >
            <input
              type="url"
              value={draftUrl}
              onChange={(e) => setDraftUrl(e.target.value)}
              placeholder="https://workstation.local:18822"
              aria-label="MCP server URL"
              style={{ ...CTRL, flex: 1, minWidth: 0 }}
            />
            <button
              type="submit"
              disabled={update.isPending || !draftUrl.trim()}
              style={actionButton({
                primary: true,
                disabled: update.isPending || !draftUrl.trim(),
              })}
            >
              {update.isPending ? "saving\u2026" : "save"}
            </button>
            <button
              type="button"
              onClick={() => setEditing(false)}
              style={actionButton({})}
            >
              cancel
            </button>
          </form>
        )}
        {server.base_url !== server.default_url && (
          <button
            type="button"
            onClick={() =>
              update.mutate({
                serverId: server.id,
                baseUrl: server.default_url,
              })
            }
            disabled={update.isPending}
            style={actionButton({ disabled: update.isPending })}
            title={`Reset to ${server.default_url}`}
          >
            reset to default
          </button>
        )}
        {reachable && server.tool_count > 0 && (
          <button
            type="button"
            onClick={() => setShowTools((v) => !v)}
            style={actionButton({})}
          >
            {showTools ? "hide tools" : `show ${server.tool_count} tools`}
          </button>
        )}
      </div>

      {showTools && reachable && (
        <div
          className="grid font-mono"
          style={{
            marginTop: 10,
            gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))",
            gap: 4,
            padding: 8,
            fontSize: 10.5,
            color: "var(--text-muted)",
            background: "var(--surface-sunk)",
            border: "1px solid var(--border-faint)",
            borderRadius: 3,
            maxHeight: 260,
            overflowY: "auto",
          }}
        >
          {server.tools.map((t) => (
            <div
              key={t}
              style={{
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {t}
            </div>
          ))}
        </div>
      )}
    </WindowPanel>
  );
}
