/**
 * PlatformInfraPage -- god-tier control surfaces for platform infra.
 *
 * Two concerns (Segmented switcher in the SectionHeader):
 *   MCP Registry -- CRUD + approve/revoke + drift over
 *     /platform/mcp/instances
 *   Specialists  -- CRUD + seed defaults over /agents/specialists
 *
 * Rebuilt to the AILA mock: SectionHeader top, WindowPanels for content,
 * DataGrid for the instance / specialist lists, MonoBadge for approval /
 * drift / enabled state. Dialogs are replaced by a lightweight ModalShell
 * that reuses WindowPanel.
 *
 * The route is admin-gated in `src/app/router.tsx`; the page returns bare
 * content and the shell renders the title bar (CLAUDE.md #16).
 */
import { Fragment, useMemo, useState, type CSSProperties, type ReactNode } from "react";

import { Trash } from "@phosphor-icons/react/dist/csr/Trash";
import { CheckCircle } from "@phosphor-icons/react/dist/csr/CheckCircle";
import { Prohibit } from "@phosphor-icons/react/dist/csr/Prohibit";
import { CaretDown } from "@phosphor-icons/react/dist/csr/CaretDown";
import { CaretRight } from "@phosphor-icons/react/dist/csr/CaretRight";
import { Plus } from "@phosphor-icons/react/dist/csr/Plus";
import { ArrowsCounterClockwise } from "@phosphor-icons/react/dist/csr/ArrowsCounterClockwise";
import { Plant } from "@phosphor-icons/react/dist/csr/Plant";
import { X } from "@phosphor-icons/react/dist/csr/X";

import { SectionHeader, Segmented, MonoBadge, DataGrid } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { FeatureBoundary } from "@app/FeatureBoundary";

import {
  SPECIALIST_MODULE_IDS,
  useApproveMcpInstance,
  useCreateMcpInstance,
  useDeleteMcpInstance,
  useDeleteSpecialist,
  useMcpInstances,
  useMcpInstanceTools,
  usePatchMcpInstance,
  useRevokeMcpInstance,
  useSeedSpecialists,
  useSpecialists,
  useUpsertSpecialist,
  type McpInstance,
  type McpInstanceCreateRequest,
  type SpecialistAgent,
  type SpecialistAgentCreateRequest,
  type SpecialistModuleId,
} from "./platformInfraQueries";

// ---------------------------------------------------------------------------
// Shared inline styles
// ---------------------------------------------------------------------------

const BUTTON_STYLE: CSSProperties = {
  height: 24, padding: "0 9px", fontSize: 9, fontFamily: "var(--font-mono)",
  letterSpacing: "0.08em", textTransform: "uppercase",
  background: "var(--surface-sunk)", border: "1px solid var(--border-soft)",
  color: "var(--text-primary)", borderRadius: 3, cursor: "pointer",
  display: "inline-flex", alignItems: "center", gap: 5,
};

const PRIMARY_BUTTON_STYLE: CSSProperties = {
  ...BUTTON_STYLE,
  background: "var(--accent)", border: "1px solid var(--accent)",
  color: "var(--text-on-accent)",
};

const WARN_BUTTON_STYLE: CSSProperties = {
  ...BUTTON_STYLE,
  background: "color-mix(in srgb, var(--status-warn) 14%, transparent)",
  border: "1px solid var(--status-warn)", color: "var(--status-warn)",
};

const INPUT_STYLE: CSSProperties = {
  height: 26, padding: "0 8px", fontSize: 11, fontFamily: "var(--font-mono)",
  background: "var(--surface-sunk)", border: "1px solid var(--border-soft)",
  color: "var(--text-primary)", borderRadius: 3, width: "100%",
};

const TEXTAREA_STYLE: CSSProperties = {
  padding: "6px 8px", fontSize: 11, fontFamily: "var(--font-mono)",
  background: "var(--surface-sunk)", border: "1px solid var(--border-soft)",
  color: "var(--text-primary)", borderRadius: 3, resize: "vertical", width: "100%",
};

const LABEL_STYLE: CSSProperties = {
  fontFamily: "var(--font-mono)", fontSize: 9, letterSpacing: "0.14em",
  color: "var(--text-faint)", textTransform: "uppercase",
};

const ERROR_BOX_STYLE: CSSProperties = {
  border: "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
  background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
  color: "var(--status-warn)",
  padding: "6px 10px", fontSize: 11, borderRadius: 3, fontFamily: "var(--font-mono)",
};

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "--";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

function shortHash(hash: string | null | undefined): string {
  if (!hash) return "--";
  return hash.length > 12 ? `${hash.slice(0, 12)}\u2026` : hash;
}

type ApprovalTone = "critical" | "medium" | "low" | "muted";

function approvalTone(state: string): ApprovalTone {
  const normalized = state.toLowerCase();
  if (normalized === "approved") return "low";
  if (normalized === "pending") return "medium";
  if (normalized === "revoked") return "critical";
  return "muted";
}

function isDrift(row: McpInstance): boolean {
  return (
    row.schema_hash !== null
    && row.approved_hash !== null
    && row.schema_hash !== row.approved_hash
  );
}

// ---------------------------------------------------------------------------
// Modal shell (replaces shadcn Dialog)
// ---------------------------------------------------------------------------

interface ModalShellProps {
  open: boolean;
  onClose: () => void;
  title: string;
  tone?: "accent" | "warn" | "muted" | "ok" | "info";
  width?: number;
  children: ReactNode;
}

function ModalShell({ open, onClose, title, tone = "accent", width = 460, children }: ModalShellProps) {
  if (!open) return null;
  return (
    <div
      role="dialog"
      aria-modal="true"
      onClick={onClose}
      style={{
        position: "fixed", inset: 0, zIndex: 60, padding: 16,
        background: "color-mix(in srgb, var(--surface-page) 80%, transparent)",
        display: "flex", alignItems: "center", justifyContent: "center",
      }}
    >
      <div onClick={(e) => e.stopPropagation()} style={{ width: "100%", maxWidth: width }}>
        <WindowPanel
          title={title}
          tone={tone}
          actions={
            <button
              type="button"
              onClick={onClose}
              aria-label="Close"
              style={{
                width: 20, height: 20, background: "transparent", border: 0,
                color: "var(--text-muted)", cursor: "pointer",
                display: "inline-flex", alignItems: "center", justifyContent: "center",
              }}
            >
              <X size={12} aria-hidden />
            </button>
          }
        >
          {children}
        </WindowPanel>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// MCP: New-instance modal
// ---------------------------------------------------------------------------

interface NewMcpDialogProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (body: McpInstanceCreateRequest) => Promise<unknown>;
  isPending: boolean;
}

function NewMcpDialog({ open, onClose, onSubmit, isPending }: NewMcpDialogProps) {
  const [name, setName] = useState("");
  const [transport, setTransport] = useState("http");
  const [endpoint, setEndpoint] = useState("");
  const [moduleScope, setModuleScope] = useState("");
  const [capabilityTags, setCapabilityTags] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [error, setError] = useState<string | null>(null);

  function reset() {
    setName(""); setTransport("http"); setEndpoint("");
    setModuleScope(""); setCapabilityTags(""); setEnabled(true); setError(null);
  }
  function handleClose() { reset(); onClose(); }

  async function handleSubmit() {
    setError(null);
    const trimmedName = name.trim();
    const trimmedEndpoint = endpoint.trim();
    if (!trimmedName || !trimmedEndpoint) {
      setError("name and endpoint are required");
      return;
    }
    const tags = capabilityTags.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
    try {
      await onSubmit({
        name: trimmedName,
        transport: transport.trim() || "http",
        endpoint: trimmedEndpoint,
        capability_tags: tags,
        enabled,
        module_scope: moduleScope.trim() ? moduleScope.trim() : null,
      });
      reset();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create instance");
    }
  }

  return (
    <ModalShell open={open} onClose={handleClose} title="new mcp instance">
      <div className="flex flex-col" style={{ gap: 10 }}>
        <div className="flex flex-col" style={{ gap: 4 }}>
          <label style={LABEL_STYLE}>NAME</label>
          <input aria-label="MCP instance name" value={name} onChange={(e) => setName(e.target.value)} style={INPUT_STYLE} />
        </div>
        <div className="flex flex-col" style={{ gap: 4 }}>
          <label style={LABEL_STYLE}>TRANSPORT (HTTP | STDIO)</label>
          <input aria-label="Transport (http or stdio)" value={transport} onChange={(e) => setTransport(e.target.value)} style={INPUT_STYLE} />
        </div>
        <div className="flex flex-col" style={{ gap: 4 }}>
          <label style={LABEL_STYLE}>ENDPOINT (URL FOR HTTP, COMMAND FOR STDIO)</label>
          <input aria-label="Endpoint URL or command" value={endpoint} onChange={(e) => setEndpoint(e.target.value)} style={INPUT_STYLE} />
        </div>
        <div className="flex flex-col" style={{ gap: 4 }}>
          <label style={LABEL_STYLE}>MODULE SCOPE (OPTIONAL)</label>
          <input aria-label="Module scope (optional)" value={moduleScope} onChange={(e) => setModuleScope(e.target.value)} style={INPUT_STYLE} />
        </div>
        <div className="flex flex-col" style={{ gap: 4 }}>
          <label style={LABEL_STYLE}>CAPABILITY TAGS (COMMA-SEPARATED)</label>
          <input aria-label="Capability tags (comma-separated)" value={capabilityTags} onChange={(e) => setCapabilityTags(e.target.value)} style={INPUT_STYLE} />
        </div>
        <label className="inline-flex items-center font-mono" style={{ gap: 8, fontSize: 11, color: "var(--text-primary)" }}>
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
            style={{ width: 12, height: 12, accentColor: "var(--accent)" }}
          />
          Enabled at creation
        </label>
        {error && <div style={ERROR_BOX_STYLE}>{error}</div>}
        <div className="flex" style={{ gap: 8, paddingTop: 4 }}>
          <button type="button" style={{ ...PRIMARY_BUTTON_STYLE, flex: 1 }} onClick={() => void handleSubmit()} disabled={isPending}>
            {isPending ? "CREATING\u2026" : "CREATE"}
          </button>
          <button type="button" style={BUTTON_STYLE} onClick={handleClose}>CANCEL</button>
        </div>
      </div>
    </ModalShell>
  );
}

// ---------------------------------------------------------------------------
// MCP: Revoke reason dialog
// ---------------------------------------------------------------------------

interface RevokeDialogProps {
  instance: McpInstance | null;
  onClose: () => void;
  onConfirm: (reason: string) => Promise<unknown>;
  isPending: boolean;
}

function RevokeDialog({ instance, onClose, onConfirm, isPending }: RevokeDialogProps) {
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);

  function handleClose() { setReason(""); setError(null); onClose(); }

  async function handleConfirm() {
    setError(null);
    const trimmed = reason.trim();
    if (trimmed.length === 0) {
      setError("A reason is required to revoke trust.");
      return;
    }
    try {
      await onConfirm(trimmed);
      setReason("");
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to revoke");
    }
  }

  return (
    <ModalShell open={instance !== null} onClose={handleClose} title="revoke mcp trust" tone="warn">
      <div className="flex flex-col" style={{ gap: 10 }}>
        {instance && (
          <p className="font-mono" style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.55 }}>
            Revoking trust for <span style={{ color: "var(--text-primary)" }}>{instance.name}</span>.
            The server is marked untrusted until re-approved.
          </p>
        )}
        <div className="flex flex-col" style={{ gap: 4 }}>
          <label style={LABEL_STYLE}>REASON (REQUIRED, AUDITED)</label>
          <textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={4} style={TEXTAREA_STYLE} />
        </div>
        {error && <div style={ERROR_BOX_STYLE}>{error}</div>}
        <div className="flex" style={{ gap: 8, paddingTop: 4 }}>
          <button type="button" style={{ ...WARN_BUTTON_STYLE, flex: 1 }} onClick={() => void handleConfirm()} disabled={isPending}>
            {isPending ? "REVOKING\u2026" : "REVOKE"}
          </button>
          <button type="button" style={BUTTON_STYLE} onClick={handleClose}>CANCEL</button>
        </div>
      </div>
    </ModalShell>
  );
}

// ---------------------------------------------------------------------------
// MCP: Delete confirmation
// ---------------------------------------------------------------------------

interface DeleteMcpDialogProps {
  instance: McpInstance | null;
  onClose: () => void;
  onConfirm: () => Promise<unknown>;
  isPending: boolean;
}

function DeleteMcpDialog({ instance, onClose, onConfirm, isPending }: DeleteMcpDialogProps) {
  const [error, setError] = useState<string | null>(null);

  async function handleConfirm() {
    setError(null);
    try {
      await onConfirm();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete");
    }
  }

  return (
    <ModalShell
      open={instance !== null}
      onClose={() => { setError(null); onClose(); }}
      title="delete mcp instance"
      tone="warn"
      width={400}
    >
      <div className="flex flex-col" style={{ gap: 10 }}>
        {instance && (
          <p className="font-mono" style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.55 }}>
            Permanently remove <span style={{ color: "var(--text-primary)" }}>{instance.name}</span> from
            the catalog. Existing approvals cannot be recovered.
          </p>
        )}
        {error && <div style={ERROR_BOX_STYLE}>{error}</div>}
        <div className="flex" style={{ gap: 8, paddingTop: 4 }}>
          <button type="button" style={{ ...WARN_BUTTON_STYLE, flex: 1 }} onClick={() => void handleConfirm()} disabled={isPending}>
            {isPending ? "DELETING\u2026" : "DELETE"}
          </button>
          <button
            type="button"
            style={BUTTON_STYLE}
            onClick={() => { setError(null); onClose(); }}
          >
            CANCEL
          </button>
        </div>
      </div>
    </ModalShell>
  );
}

// ---------------------------------------------------------------------------
// MCP: Tools panel (expanded row content)
// ---------------------------------------------------------------------------

function McpToolsPanel({ instanceId }: { instanceId: string }) {
  const toolsQuery = useMcpInstanceTools(instanceId);
  const data = toolsQuery.data;
  const drift = data?.drift ?? false;

  return (
    <div
      className="flex flex-col"
      style={{
        gap: 10, padding: 12,
        background: "var(--surface-sunk)",
        borderTop: "1px solid var(--border-faint)",
      }}
    >
      <div className="flex flex-wrap items-center" style={{ gap: 10 }}>
        <span style={LABEL_STYLE}>SCHEMA_HASH</span>
        <code className="font-mono" style={{ fontSize: 10.5, color: "var(--text-primary)", padding: "2px 6px", background: "var(--surface-card)", borderRadius: 2 }}>
          {data ? shortHash(data.schema_hash) : "--"}
        </code>
        <span style={LABEL_STYLE}>APPROVED_HASH</span>
        <code className="font-mono" style={{ fontSize: 10.5, color: "var(--text-primary)", padding: "2px 6px", background: "var(--surface-card)", borderRadius: 2 }}>
          {data ? shortHash(data.approved_hash) : "--"}
        </code>
        {data && drift && <MonoBadge tone="critical">DRIFT</MonoBadge>}
        {data && !drift && data.approved_hash && <MonoBadge tone="ok">In sync</MonoBadge>}
      </div>

      {toolsQuery.isLoading && <LoadingSkeletonGroup lines={2} />}
      {toolsQuery.isError && (
        <div style={ERROR_BOX_STYLE}>
          Failed to load tools: {(toolsQuery.error as Error).message}
        </div>
      )}
      {data && data.tools.length === 0 && (
        <p className="font-mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>Server exposes no tools.</p>
      )}
      {data && data.tools.length > 0 && (
        <DataGrid<Record<string, unknown>>
          columns={[
            { label: "NAME", width: "200px" },
            { label: "DESCRIPTION", width: "1fr" },
          ]}
          rows={data.tools as Record<string, unknown>[]}
          getKey={(tool, idx) => (typeof tool["name"] === "string" ? (tool["name"] as string) : `tool_${idx}`)}
          renderCells={(tool) => {
            const name = typeof tool["name"] === "string" ? (tool["name"] as string) : "";
            const description = typeof tool["description"] === "string" ? (tool["description"] as string) : "";
            return [
              <span className="font-mono" style={{ fontSize: 10.5, color: "var(--text-primary)" }}>{name || "--"}</span>,
              <span className="font-mono truncate" style={{ fontSize: 10.5, color: "var(--text-muted)" }}>{description || "--"}</span>,
            ];
          }}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// MCP: Concern body
// ---------------------------------------------------------------------------

function McpRegistryConcern() {
  const instancesQuery = useMcpInstances(true);
  const createMutation = useCreateMcpInstance();
  const patchMutation = usePatchMcpInstance();
  const deleteMutation = useDeleteMcpInstance();
  const approveMutation = useApproveMcpInstance();
  const revokeMutation = useRevokeMcpInstance();

  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [newOpen, setNewOpen] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState<McpInstance | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<McpInstance | null>(null);

  const rows = instancesQuery.data ?? [];

  return (
    <div className="flex flex-col" style={{ gap: 12 }}>
      <WindowPanel
        title="mcp server catalog"
        actions={
          <div className="flex items-center" style={{ gap: 6 }}>
            <button
              type="button"
              style={BUTTON_STYLE}
              onClick={() => void instancesQuery.refetch()}
              disabled={instancesQuery.isFetching}
            >
              <ArrowsCounterClockwise size={11} aria-hidden />
              REFRESH
            </button>
            <button
              type="button"
              style={PRIMARY_BUTTON_STYLE}
              onClick={() => setNewOpen(true)}
            >
              <Plus size={11} aria-hidden />
              NEW INSTANCE
            </button>
          </div>
        }
        flush
      >
        {instancesQuery.isLoading && <div style={{ padding: 14 }}><LoadingSkeletonGroup lines={4} /></div>}
        {instancesQuery.isError && (
          <div style={{ ...ERROR_BOX_STYLE, margin: 12 }}>
            Failed to load MCP instances: {(instancesQuery.error as Error).message}
          </div>
        )}
        {!instancesQuery.isLoading && !instancesQuery.isError && rows.length === 0 && (
          <div
            className="font-mono"
            style={{ padding: 32, textAlign: "center", fontSize: 11, color: "var(--text-muted)", lineHeight: 1.6 }}
          >
            No MCP instances.
            <br />
            Register the first MCP server to expose its tools to the platform.
          </div>
        )}
        {!instancesQuery.isLoading && rows.length > 0 && (
          <div
            className="grid font-mono uppercase"
            style={{
              gridTemplateColumns: "24px 1fr 90px 1.4fr 130px 150px 68px 140px 180px",
              gap: 10, padding: "8px 12px",
              background: "var(--surface-sunk)", borderBottom: "1px solid var(--border-soft)",
              fontSize: 9, letterSpacing: "0.14em", color: "var(--text-faint)",
            }}
          >
            <span />
            <span>NAME</span>
            <span>TRANSPORT</span>
            <span>ENDPOINT</span>
            <span>MODULE SCOPE</span>
            <span>APPROVAL</span>
            <span>ENABLED</span>
            <span>TAGS</span>
            <span>ACTIONS</span>
          </div>
        )}
        {!instancesQuery.isLoading && rows.length > 0 && (
          <div>
            {rows.map((row) => {
              const drift = isDrift(row);
              const expanded = expandedId === row.id;
              return (
                <Fragment key={row.id}>
                  <div
                    className="grid font-mono"
                    style={{
                      gridTemplateColumns: "24px 1fr 90px 1.4fr 130px 150px 68px 140px 180px",
                      gap: 10, padding: "8px 12px", alignItems: "center",
                      borderBottom: "1px solid var(--border-faint)",
                      background: "var(--surface-card)",
                      fontSize: 11,
                    }}
                  >
                    <button
                      type="button"
                      onClick={() => setExpandedId(expanded ? null : row.id)}
                      aria-label={expanded ? "Collapse tools" : "Expand tools"}
                      style={{
                        width: 20, height: 20, background: "transparent", border: 0,
                        color: "var(--text-muted)", cursor: "pointer",
                        display: "inline-flex", alignItems: "center", justifyContent: "center",
                      }}
                    >
                      {expanded ? <CaretDown size={11} /> : <CaretRight size={11} />}
                    </button>
                    <span style={{ color: "var(--text-primary)" }}>{row.name}</span>
                    <span style={{ color: "var(--text-muted)" }}>{row.transport}</span>
                    <span className="truncate" style={{ color: "var(--text-muted)" }} title={row.endpoint}>{row.endpoint}</span>
                    <span style={{ color: "var(--text-muted)" }}>{row.module_scope ?? "--"}</span>
                    <span className="inline-flex items-center" style={{ gap: 6 }}>
                      <MonoBadge tone={approvalTone(row.approval_state)}>{row.approval_state}</MonoBadge>
                      {drift && <MonoBadge tone="critical">DRIFT</MonoBadge>}
                    </span>
                    <input
                      type="checkbox"
                      checked={row.enabled}
                      disabled={patchMutation.isPending}
                      onChange={(e) =>
                        patchMutation.mutate({ id: row.id, patch: { enabled: e.target.checked } })
                      }
                      style={{ width: 12, height: 12, accentColor: "var(--accent)" }}
                      aria-label={`Toggle ${row.name}`}
                    />
                    <div className="flex flex-wrap" style={{ gap: 4 }}>
                      {row.capability_tags.length === 0 && <span style={{ color: "var(--text-faint)" }}>--</span>}
                      {row.capability_tags.map((tag) => (
                        <span
                          key={tag}
                          className="font-mono"
                          style={{
                            padding: "1px 6px", fontSize: 9.5, borderRadius: 2,
                            background: "var(--surface-sunk)", color: "var(--text-muted)",
                          }}
                        >
                          {tag}
                        </span>
                      ))}
                    </div>
                    <div className="flex flex-wrap" style={{ gap: 4 }}>
                      <button
                        type="button"
                        style={BUTTON_STYLE}
                        disabled={approveMutation.isPending}
                        onClick={() => approveMutation.mutate(row.id)}
                        title="Pin current schema and approve"
                      >
                        <CheckCircle size={10} aria-hidden />
                        APPROVE
                      </button>
                      <button
                        type="button"
                        style={BUTTON_STYLE}
                        onClick={() => setRevokeTarget(row)}
                        title="Revoke trust"
                      >
                        <Prohibit size={10} aria-hidden />
                        REVOKE
                      </button>
                      <button
                        type="button"
                        style={BUTTON_STYLE}
                        onClick={() => setDeleteTarget(row)}
                        title="Delete instance"
                        aria-label="Delete instance"
                      >
                        <Trash size={10} aria-hidden />
                      </button>
                    </div>
                  </div>
                  {expanded && <McpToolsPanel instanceId={row.id} />}
                </Fragment>
              );
            })}
          </div>
        )}

        {(patchMutation.isError || approveMutation.isError) && (
          <div style={{ ...ERROR_BOX_STYLE, margin: 12 }}>
            {(patchMutation.error ?? approveMutation.error) instanceof Error
              ? ((patchMutation.error ?? approveMutation.error) as Error).message
              : "Mutation failed"}
          </div>
        )}
      </WindowPanel>

      <NewMcpDialog
        open={newOpen}
        onClose={() => setNewOpen(false)}
        onSubmit={(body) => createMutation.mutateAsync(body)}
        isPending={createMutation.isPending}
      />
      <RevokeDialog
        instance={revokeTarget}
        onClose={() => setRevokeTarget(null)}
        onConfirm={(reason) => revokeMutation.mutateAsync({ id: revokeTarget!.id, reason })}
        isPending={revokeMutation.isPending}
      />
      <DeleteMcpDialog
        instance={deleteTarget}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() => deleteMutation.mutateAsync(deleteTarget!.id)}
        isPending={deleteMutation.isPending}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Specialists: create dialog
// ---------------------------------------------------------------------------

interface NewSpecialistDialogProps {
  moduleId: string;
  open: boolean;
  onClose: () => void;
  onSubmit: (body: SpecialistAgentCreateRequest) => Promise<unknown>;
  isPending: boolean;
}

function NewSpecialistDialog({ moduleId, open, onClose, onSubmit, isPending }: NewSpecialistDialogProps) {
  const [name, setName] = useState("");
  const [capability, setCapability] = useState("");
  const [strategy, setStrategy] = useState("");
  const [description, setDescription] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [error, setError] = useState<string | null>(null);

  function reset() {
    setName(""); setCapability(""); setStrategy("");
    setDescription(""); setEnabled(true); setError(null);
  }
  function handleClose() { reset(); onClose(); }

  async function handleSubmit() {
    setError(null);
    const trimmedName = name.trim();
    const trimmedCapability = capability.trim();
    if (!trimmedName || !trimmedCapability) {
      setError("name and capability are required");
      return;
    }
    try {
      await onSubmit({
        module_id: moduleId,
        name: trimmedName,
        capability: trimmedCapability,
        strategy_family: strategy.trim() ? strategy.trim() : null,
        description: description.trim(),
        enabled,
      });
      reset();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create specialist");
    }
  }

  return (
    <ModalShell open={open} onClose={handleClose} title={`new specialist (${moduleId})`}>
      <div className="flex flex-col" style={{ gap: 10 }}>
        <div className="flex flex-col" style={{ gap: 4 }}>
          <label style={LABEL_STYLE}>NAME (PERSONA VOICE)</label>
          <input aria-label="Specialist name (persona voice)" value={name} onChange={(e) => setName(e.target.value)} style={INPUT_STYLE} />
        </div>
        <div className="flex flex-col" style={{ gap: 4 }}>
          <label style={LABEL_STYLE}>CAPABILITY (MATCHES PHASESPEC.CAPABILITY)</label>
          <input aria-label="Capability (dispatch PhaseSpec.capability)" value={capability} onChange={(e) => setCapability(e.target.value)} style={INPUT_STYLE} />
        </div>
        <div className="flex flex-col" style={{ gap: 4 }}>
          <label style={LABEL_STYLE}>STRATEGY FAMILY (OPTIONAL)</label>
          <input aria-label="Strategy family (optional)" value={strategy} onChange={(e) => setStrategy(e.target.value)} style={INPUT_STYLE} />
        </div>
        <div className="flex flex-col" style={{ gap: 4 }}>
          <label style={LABEL_STYLE}>DESCRIPTION</label>
          <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={3} style={TEXTAREA_STYLE} />
        </div>
        <label className="inline-flex items-center font-mono" style={{ gap: 8, fontSize: 11, color: "var(--text-primary)" }}>
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
            style={{ width: 12, height: 12, accentColor: "var(--accent)" }}
          />
          Enabled
        </label>
        {error && <div style={ERROR_BOX_STYLE}>{error}</div>}
        <div className="flex" style={{ gap: 8, paddingTop: 4 }}>
          <button type="button" style={{ ...PRIMARY_BUTTON_STYLE, flex: 1 }} onClick={() => void handleSubmit()} disabled={isPending}>
            {isPending ? "SAVING\u2026" : "SAVE"}
          </button>
          <button type="button" style={BUTTON_STYLE} onClick={handleClose}>CANCEL</button>
        </div>
      </div>
    </ModalShell>
  );
}

// ---------------------------------------------------------------------------
// Specialists: delete confirm
// ---------------------------------------------------------------------------

interface DeleteSpecialistDialogProps {
  target: SpecialistAgent | null;
  onClose: () => void;
  onConfirm: () => Promise<unknown>;
  isPending: boolean;
}

function DeleteSpecialistDialog({ target, onClose, onConfirm, isPending }: DeleteSpecialistDialogProps) {
  const [error, setError] = useState<string | null>(null);

  async function handleConfirm() {
    setError(null);
    try {
      await onConfirm();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete");
    }
  }

  return (
    <ModalShell
      open={target !== null}
      onClose={() => { setError(null); onClose(); }}
      title="delete specialist"
      tone="warn"
      width={400}
    >
      <div className="flex flex-col" style={{ gap: 10 }}>
        {target && (
          <p className="font-mono" style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.55 }}>
            Remove <span style={{ color: "var(--text-primary)" }}>{target.name}</span> from
            module <span style={{ color: "var(--text-primary)" }}>{target.module_id}</span>?
          </p>
        )}
        {error && <div style={ERROR_BOX_STYLE}>{error}</div>}
        <div className="flex" style={{ gap: 8, paddingTop: 4 }}>
          <button type="button" style={{ ...WARN_BUTTON_STYLE, flex: 1 }} onClick={() => void handleConfirm()} disabled={isPending}>
            {isPending ? "DELETING\u2026" : "DELETE"}
          </button>
          <button
            type="button"
            style={BUTTON_STYLE}
            onClick={() => { setError(null); onClose(); }}
          >
            CANCEL
          </button>
        </div>
      </div>
    </ModalShell>
  );
}

// ---------------------------------------------------------------------------
// Specialists: concern body
// ---------------------------------------------------------------------------

function SpecialistsConcern() {
  const [moduleId, setModuleId] = useState<SpecialistModuleId>("vr");
  const [newOpen, setNewOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<SpecialistAgent | null>(null);

  const specialistsQuery = useSpecialists(moduleId);
  const upsertMutation = useUpsertSpecialist();
  const seedMutation = useSeedSpecialists();
  const deleteMutation = useDeleteSpecialist();

  const rows = specialistsQuery.data ?? [];
  const sortedRows = useMemo(() => [...rows].sort((a, b) => a.name.localeCompare(b.name)), [rows]);

  return (
    <div className="flex flex-col" style={{ gap: 12 }}>
      <div className="flex flex-wrap items-center justify-between" style={{ gap: 10 }}>
        <div className="flex items-center" style={{ gap: 8 }}>
          <span style={LABEL_STYLE}>MODULE</span>
          <Segmented<SpecialistModuleId>
            options={SPECIALIST_MODULE_IDS.map((id) => ({ value: id, label: id.toUpperCase() }))}
            value={moduleId}
            onChange={setModuleId}
          />
        </div>
        <div className="flex items-center" style={{ gap: 6 }}>
          <button
            type="button"
            style={BUTTON_STYLE}
            onClick={() => void specialistsQuery.refetch()}
            disabled={specialistsQuery.isFetching}
          >
            <ArrowsCounterClockwise size={11} aria-hidden />
            REFRESH
          </button>
          <button
            type="button"
            style={BUTTON_STYLE}
            onClick={() => seedMutation.mutate(moduleId)}
            disabled={seedMutation.isPending}
            title={`Seed built-in defaults for ${moduleId}`}
          >
            <Plant size={11} aria-hidden />
            {seedMutation.isPending ? "SEEDING\u2026" : "SEED DEFAULTS"}
          </button>
          <button
            type="button"
            style={PRIMARY_BUTTON_STYLE}
            onClick={() => setNewOpen(true)}
          >
            <Plus size={11} aria-hidden />
            NEW SPECIALIST
          </button>
        </div>
      </div>

      {seedMutation.isSuccess && seedMutation.data && (
        <div
          className="font-mono"
          style={{
            border: "1px solid color-mix(in srgb, var(--status-ok) 40%, transparent)",
            background: "color-mix(in srgb, var(--status-ok) 10%, transparent)",
            color: "var(--status-ok)",
            padding: "6px 12px", fontSize: 11, borderRadius: 3,
          }}
        >
          Seeded {seedMutation.data.data.inserted} default specialist
          {seedMutation.data.data.inserted === 1 ? "" : "s"} for {moduleId}.
        </div>
      )}
      {seedMutation.isError && (
        <div style={ERROR_BOX_STYLE}>
          Seed failed: {(seedMutation.error as Error).message}
        </div>
      )}

      <WindowPanel title={`specialists : ${moduleId}`} flush>
        {specialistsQuery.isLoading && <div style={{ padding: 14 }}><LoadingSkeletonGroup lines={4} /></div>}
        {specialistsQuery.isError && (
          <div style={{ ...ERROR_BOX_STYLE, margin: 12 }}>
            Failed to load specialists: {(specialistsQuery.error as Error).message}
          </div>
        )}
        {!specialistsQuery.isLoading && !specialistsQuery.isError && sortedRows.length === 0 && (
          <div
            className="font-mono"
            style={{ padding: 32, textAlign: "center", fontSize: 11, color: "var(--text-muted)", lineHeight: 1.6 }}
          >
            No specialists.
            <br />
            Seed the built-in defaults for {moduleId} or add one manually.
          </div>
        )}
        {!specialistsQuery.isLoading && sortedRows.length > 0 && (
          <DataGrid<SpecialistAgent>
            columns={[
              { label: "NAME", width: "180px" },
              { label: "CAPABILITY", width: "1fr" },
              { label: "STRATEGY", width: "160px" },
              { label: "TEAM", width: "110px" },
              { label: "STATE", width: "80px" },
              { label: "UPDATED", width: "150px" },
              { label: "", width: "56px", align: "right" },
            ]}
            rows={sortedRows}
            getKey={(row) => row.id}
            renderCells={(row) => [
              <div className="flex flex-col" style={{ gap: 2 }}>
                <span className="font-mono" style={{ fontSize: 11, color: "var(--text-primary)" }}>{row.name}</span>
                {row.description && (
                  <span className="font-mono truncate" style={{ fontSize: 10, color: "var(--text-faint)" }}>
                    {row.description}
                  </span>
                )}
              </div>,
              <code className="font-mono" style={{ fontSize: 10.5, color: "var(--text-primary)" }}>{row.capability}</code>,
              <code className="font-mono" style={{ fontSize: 10.5, color: "var(--text-muted)" }}>{row.strategy_family ?? "--"}</code>,
              <span className="font-mono" style={{ fontSize: 10.5, color: "var(--text-muted)" }}>{row.team_id ?? "global"}</span>,
              <MonoBadge tone={row.enabled ? "ok" : "muted"}>
                {row.enabled ? "enabled" : "disabled"}
              </MonoBadge>,
              <span className="font-mono" style={{ fontSize: 10, color: "var(--text-muted)" }}>{formatTimestamp(row.updated_at)}</span>,
              <button
                type="button"
                style={BUTTON_STYLE}
                onClick={() => setDeleteTarget(row)}
                aria-label={`Delete ${row.name}`}
                title="Delete specialist"
              >
                <Trash size={10} aria-hidden />
              </button>,
            ]}
          />
        )}
      </WindowPanel>

      <NewSpecialistDialog
        moduleId={moduleId}
        open={newOpen}
        onClose={() => setNewOpen(false)}
        onSubmit={(body) => upsertMutation.mutateAsync(body)}
        isPending={upsertMutation.isPending}
      />
      <DeleteSpecialistDialog
        target={deleteTarget}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() =>
          deleteMutation.mutateAsync({
            moduleId: deleteTarget!.module_id,
            name: deleteTarget!.name,
          })
        }
        isPending={deleteMutation.isPending}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

type Concern = "mcp" | "specialists";

export function PlatformInfraPage() {
  const [tab, setTab] = useState<Concern>("mcp");
  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <SectionHeader
        icon={"\u25b3"}
        title="infra"
        actions={
          <Segmented<Concern>
            options={[
              { value: "mcp", label: "MCP REGISTRY" },
              { value: "specialists", label: "SPECIALISTS" },
            ]}
            value={tab}
            onChange={setTab}
          />
        }
      />

      {tab === "mcp" && (
        <FeatureBoundary label="MCP Registry" resetKeys={[tab]}>
          <McpRegistryConcern />
        </FeatureBoundary>
      )}
      {tab === "specialists" && (
        <FeatureBoundary label="Specialists" resetKeys={[tab]}>
          <SpecialistsConcern />
        </FeatureBoundary>
      )}
    </div>
  );
}
