/**
 * PlatformInfraPage -- god-tier control surfaces for platform infra.
 *
 * Two tabs:
 *   MCP Registry -- CRUD + approve/revoke + drift over
 *     /platform/mcp/instances (see aila/api/routers/mcp_instances.py)
 *   Specialists  -- CRUD + seed defaults over /agents/specialists
 *     (see aila/api/routers/specialist_agents.py)
 *
 * The route is admin-gated in `src/app/router.tsx` via
 * `protectPage("Platform Infra", PlatformInfraPage, "admin")`; the page
 * returns bare content and the shell renders the title bar (CLAUDE.md #16).
 */
import { Fragment, useMemo, useState } from "react";

import { Trash } from "@phosphor-icons/react/dist/csr/Trash";
import { CheckCircle } from "@phosphor-icons/react/dist/csr/CheckCircle";
import { Prohibit } from "@phosphor-icons/react/dist/csr/Prohibit";
import { CaretDown } from "@phosphor-icons/react/dist/csr/CaretDown";
import { CaretRight } from "@phosphor-icons/react/dist/csr/CaretRight";
import { Plus } from "@phosphor-icons/react/dist/csr/Plus";
import { ArrowsCounterClockwise } from "@phosphor-icons/react/dist/csr/ArrowsCounterClockwise";
import { Plant } from "@phosphor-icons/react/dist/csr/Plant";

import { AilaCard } from "@/components/aila/AilaCard";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { EmptyState } from "@/components/aila/EmptyState";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

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
  return hash.length > 12 ? `${hash.slice(0, 12)}...` : hash;
}

type ApprovalSeverity = "critical" | "medium" | "low" | "neutral";

function approvalSeverity(state: string): ApprovalSeverity {
  const normalized = state.toLowerCase();
  if (normalized === "approved") return "low";
  if (normalized === "pending") return "medium";
  if (normalized === "revoked") return "critical";
  return "neutral";
}

function isDrift(row: McpInstance): boolean {
  return (
    row.schema_hash !== null &&
    row.approved_hash !== null &&
    row.schema_hash !== row.approved_hash
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
    setName("");
    setTransport("http");
    setEndpoint("");
    setModuleScope("");
    setCapabilityTags("");
    setEnabled(true);
    setError(null);
  }

  function handleClose() {
    reset();
    onClose();
  }

  async function handleSubmit() {
    setError(null);
    const trimmedName = name.trim();
    const trimmedEndpoint = endpoint.trim();
    if (!trimmedName || !trimmedEndpoint) {
      setError("name and endpoint are required");
      return;
    }
    const tags = capabilityTags
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
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
    <Dialog open={open} onOpenChange={(v) => { if (!v) handleClose(); }}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="font-mono text-text">New MCP instance</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-3">
          <label className="font-mono text-xs text-text-muted flex flex-col gap-1">
            Name
            <Input aria-label="MCP instance name" value={name} onChange={(e) => setName(e.target.value)} className="font-mono text-sm" />
          </label>
          <label className="font-mono text-xs text-text-muted flex flex-col gap-1">
            Transport (http | stdio)
            <Input aria-label="Transport (http or stdio)" value={transport} onChange={(e) => setTransport(e.target.value)} className="font-mono text-sm" />
          </label>
          <label className="font-mono text-xs text-text-muted flex flex-col gap-1">
            Endpoint (URL for http, command for stdio)
            <Input aria-label="Endpoint URL or command" value={endpoint} onChange={(e) => setEndpoint(e.target.value)} className="font-mono text-sm" />
          </label>
          <label className="font-mono text-xs text-text-muted flex flex-col gap-1">
            Module scope (optional)
            <Input aria-label="Module scope (optional)" value={moduleScope} onChange={(e) => setModuleScope(e.target.value)} className="font-mono text-sm" />
          </label>
          <label className="font-mono text-xs text-text-muted flex flex-col gap-1">
            Capability tags (comma-separated)
            <Input aria-label="Capability tags (comma-separated)" value={capabilityTags} onChange={(e) => setCapabilityTags(e.target.value)} className="font-mono text-sm" />
          </label>
          {/* Single-toggle checkbox: WCAG 1.3.1 fieldset/legend applies to related-option groups, not to individual on/off toggles labelled via wrapping <label>. */}
          <label className="font-mono text-xs text-text-muted inline-flex items-center gap-2">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              className="h-3.5 w-3.5"
            />
            Enabled at creation
          </label>
          {error && (
            <div className="rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
              {error}
            </div>
          )}
          <div className="flex gap-2 pt-1">
            <Button type="button" size="sm" className="flex-1" onClick={handleSubmit} disabled={isPending}>
              {isPending ? "Creating..." : "Create"}
            </Button>
            <Button type="button" size="sm" variant="outline" onClick={handleClose}>
              Cancel
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
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

  function handleClose() {
    setReason("");
    setError(null);
    onClose();
  }

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
    <Dialog open={instance !== null} onOpenChange={(v) => { if (!v) handleClose(); }}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="font-mono text-text">
            Revoke MCP trust
          </DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-3">
          {instance && (
            <p className="font-mono text-xs text-text-muted">
              Revoking trust for <span className="text-text">{instance.name}</span>.
              The server is marked untrusted until re-approved.
            </p>
          )}
          <label className="font-mono text-xs text-text-muted flex flex-col gap-1">
            Reason (required, audited)
            <Textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              rows={4}
              className="font-mono text-sm"
            />
          </label>
          {error && (
            <div className="rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
              {error}
            </div>
          )}
          <div className="flex gap-2 pt-1">
            <Button type="button" size="sm" className="flex-1" onClick={handleConfirm} disabled={isPending}>
              {isPending ? "Revoking..." : "Revoke"}
            </Button>
            <Button type="button" size="sm" variant="outline" onClick={handleClose}>
              Cancel
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
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
    <Dialog open={instance !== null} onOpenChange={(v) => { if (!v) { setError(null); onClose(); } }}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle className="font-mono text-text">Delete MCP instance</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-3">
          {instance && (
            <p className="font-mono text-xs text-text-muted">
              Permanently remove <span className="text-text">{instance.name}</span> from
              the catalog. Existing approvals cannot be recovered.
            </p>
          )}
          {error && (
            <div className="rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
              {error}
            </div>
          )}
          <div className="flex gap-2 pt-1">
            <Button type="button" size="sm" className="flex-1" onClick={handleConfirm} disabled={isPending}>
              {isPending ? "Deleting..." : "Delete"}
            </Button>
            <Button type="button" size="sm" variant="outline" onClick={() => { setError(null); onClose(); }}>
              Cancel
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// MCP: Tools panel (expanded row)
// ---------------------------------------------------------------------------

interface McpToolsPanelProps {
  instanceId: string;
}

function McpToolsPanel({ instanceId }: McpToolsPanelProps) {
  const toolsQuery = useMcpInstanceTools(instanceId);
  const data = toolsQuery.data;
  const drift = data?.drift ?? false;

  return (
    <div className="border-t border-border bg-elevated/40 px-4 py-3 flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-3">
        <span className="font-mono text-xs text-text-muted">schema_hash:</span>
        <code className="font-mono text-xs text-text bg-base px-1.5 py-0.5 rounded-[2px]">
          {data ? shortHash(data.schema_hash) : "--"}
        </code>
        <span className="font-mono text-xs text-text-muted">approved_hash:</span>
        <code className="font-mono text-xs text-text bg-base px-1.5 py-0.5 rounded-[2px]">
          {data ? shortHash(data.approved_hash) : "--"}
        </code>
        {data && drift && (
          <AilaBadge severity="critical" size="sm">DRIFT</AilaBadge>
        )}
        {data && !drift && data.approved_hash && (
          <AilaBadge severity="low" size="sm">In sync</AilaBadge>
        )}
      </div>

      {toolsQuery.isLoading && <LoadingSkeletonGroup lines={2} />}
      {toolsQuery.isError && (
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
          Failed to load tools: {(toolsQuery.error as Error).message}
        </div>
      )}
      {data && data.tools.length === 0 && (
        <p className="font-mono text-xs text-text-muted">Server exposes no tools.</p>
      )}
      {data && data.tools.length > 0 && (
        <div className="overflow-x-auto">
          <table aria-label="MCP instances" className="w-full">
            <thead>
              <tr className="border-b border-border">
                <th className="py-1.5 px-2 text-left font-mono text-xs text-text-muted">Name</th>
                <th className="py-1.5 px-2 text-left font-mono text-xs text-text-muted">Description</th>
              </tr>
            </thead>
            <tbody>
              {data.tools.map((tool, idx) => {
                const name = typeof tool["name"] === "string" ? (tool["name"] as string) : `tool_${idx}`;
                const description = typeof tool["description"] === "string"
                  ? (tool["description"] as string)
                  : "";
                return (
                  <tr key={`${name}-${idx}`} className="border-b border-border last:border-0 font-mono text-xs">
                    <td className="py-1.5 px-2 text-text">{name}</td>
                    <td className="py-1.5 px-2 text-text-muted max-w-[520px]">{description || "--"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// MCP: Tab body
// ---------------------------------------------------------------------------

function McpRegistryTab() {
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
    <div className="flex flex-col gap-4">
      <AilaCard variant="default" padding="md" techBorder glow>
        <div className="flex items-center justify-between mb-3">
          <h2 className="font-mono text-xs font-semibold uppercase tracking-wider text-text-muted">
            MCP Server Catalog
          </h2>
          <div className="flex gap-2">
            <Button
              size="xs"
              variant="outline"
              onClick={() => void instancesQuery.refetch()}
              disabled={instancesQuery.isFetching}
            >
              <ArrowsCounterClockwise className="h-3 w-3" />
              Refresh
            </Button>
            <Button size="xs" onClick={() => setNewOpen(true)}>
              <Plus className="h-3 w-3" />
              New instance
            </Button>
          </div>
        </div>

        {instancesQuery.isLoading && <LoadingSkeletonGroup lines={4} />}
        {instancesQuery.isError && (
          <div className="rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
            Failed to load MCP instances: {(instancesQuery.error as Error).message}
          </div>
        )}
        {!instancesQuery.isLoading && !instancesQuery.isError && rows.length === 0 && (
          <EmptyState
            title="No MCP instances"
            description="Register the first MCP server to expose its tools to the platform."
          />
        )}
        {!instancesQuery.isLoading && rows.length > 0 && (
          <div className="overflow-x-auto">
            <table aria-label="MCP capability audit" className="w-full">
              <thead>
                <tr className="border-b border-border">
                  <th className="w-6"></th>
                  <th className="py-2 px-3 text-left font-mono text-xs text-text-muted">Name</th>
                  <th className="py-2 px-3 text-left font-mono text-xs text-text-muted">Transport</th>
                  <th className="py-2 px-3 text-left font-mono text-xs text-text-muted">Endpoint</th>
                  <th className="py-2 px-3 text-left font-mono text-xs text-text-muted hidden md:table-cell">Module scope</th>
                  <th className="py-2 px-3 text-left font-mono text-xs text-text-muted">Approval</th>
                  <th className="py-2 px-3 text-left font-mono text-xs text-text-muted">Enabled</th>
                  <th className="py-2 px-3 text-left font-mono text-xs text-text-muted hidden lg:table-cell">Tags</th>
                  <th className="py-2 px-3 text-left font-mono text-xs text-text-muted">Actions</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => {
                  const drift = isDrift(row);
                  const expanded = expandedId === row.id;
                  return (
                    <Fragment key={row.id}>
                      <tr
                        className="border-b border-border last:border-0 font-mono text-xs hover:bg-elevated"
                      >
                        <td className="py-2 px-1 align-top">
                          <button
                            type="button"
                            onClick={() => setExpandedId(expanded ? null : row.id)}
                            className="p-0.5 text-text-muted hover:text-text"
                            aria-label={expanded ? "Collapse tools" : "Expand tools"}
                          >
                            {expanded ? <CaretDown className="h-3 w-3" /> : <CaretRight className="h-3 w-3" />}
                          </button>
                        </td>
                        <td className="py-2 px-3 text-text">{row.name}</td>
                        <td className="py-2 px-3 text-text-muted">{row.transport}</td>
                        <td className="py-2 px-3 text-text-muted max-w-[240px] truncate" title={row.endpoint}>
                          {row.endpoint}
                        </td>
                        <td className="py-2 px-3 text-text-muted hidden md:table-cell">{row.module_scope ?? "--"}</td>
                        <td className="py-2 px-3">
                          <div className="flex items-center gap-1.5">
                            <AilaBadge severity={approvalSeverity(row.approval_state)} size="sm">
                              {row.approval_state}
                            </AilaBadge>
                            {drift && <AilaBadge severity="critical" size="sm">DRIFT</AilaBadge>}
                          </div>
                        </td>
                        <td className="py-2 px-3">
                          <input
                            type="checkbox"
                            checked={row.enabled}
                            disabled={patchMutation.isPending}
                            onChange={(e) =>
                              patchMutation.mutate({ id: row.id, patch: { enabled: e.target.checked } })
                            }
                            className="h-3.5 w-3.5"
                            aria-label={`Toggle ${row.name}`}
                          />
                        </td>
                        <td className="py-2 px-3 hidden lg:table-cell">
                          <div className="flex flex-wrap gap-1 max-w-[220px]">
                            {row.capability_tags.length === 0 && (
                              <span className="text-text-muted">--</span>
                            )}
                            {row.capability_tags.map((tag) => (
                              <span
                                key={tag}
                                className="bg-base px-1.5 py-0.5 rounded-[2px] text-text-muted"
                              >
                                {tag}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td className="py-2 px-3">
                          <div className="flex flex-wrap gap-1">
                            <Button
                              size="xs"
                              variant="outline"
                              disabled={approveMutation.isPending}
                              onClick={() => approveMutation.mutate(row.id)}
                              title="Pin current schema and approve"
                            >
                              <CheckCircle className="h-3 w-3" />
                              Approve
                            </Button>
                            <Button
                              size="xs"
                              variant="outline"
                              onClick={() => setRevokeTarget(row)}
                              title="Revoke trust"
                            >
                              <Prohibit className="h-3 w-3" />
                              Revoke
                            </Button>
                            <Button
                              size="xs"
                              variant="outline"
                              onClick={() => setDeleteTarget(row)}
                              title="Delete instance"
                            >
                              <Trash className="h-3 w-3" />
                            </Button>
                          </div>
                        </td>
                      </tr>
                      {expanded && (
                        <tr className="bg-elevated/40">
                          <td colSpan={9} className="p-0">
                            <McpToolsPanel instanceId={row.id} />
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {(patchMutation.isError || approveMutation.isError) && (
          <div className="mt-3 rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
            {(patchMutation.error ?? approveMutation.error) instanceof Error
              ? ((patchMutation.error ?? approveMutation.error) as Error).message
              : "Mutation failed"}
          </div>
        )}
      </AilaCard>

      <NewMcpDialog
        open={newOpen}
        onClose={() => setNewOpen(false)}
        onSubmit={(body) => createMutation.mutateAsync(body)}
        isPending={createMutation.isPending}
      />

      <RevokeDialog
        instance={revokeTarget}
        onClose={() => setRevokeTarget(null)}
        onConfirm={(reason) =>
          revokeMutation.mutateAsync({ id: revokeTarget!.id, reason })
        }
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
    setName("");
    setCapability("");
    setStrategy("");
    setDescription("");
    setEnabled(true);
    setError(null);
  }

  function handleClose() {
    reset();
    onClose();
  }

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
    <Dialog open={open} onOpenChange={(v) => { if (!v) handleClose(); }}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="font-mono text-text">
            New specialist ({moduleId})
          </DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-3">
          <label className="font-mono text-xs text-text-muted flex flex-col gap-1">
            Name (persona voice)
            <Input aria-label="Specialist name (persona voice)" value={name} onChange={(e) => setName(e.target.value)} className="font-mono text-sm" />
          </label>
          <label className="font-mono text-xs text-text-muted flex flex-col gap-1">
            Capability (matches dispatch PhaseSpec.capability)
            <Input aria-label="Capability (dispatch PhaseSpec.capability)" value={capability} onChange={(e) => setCapability(e.target.value)} className="font-mono text-sm" />
          </label>
          <label className="font-mono text-xs text-text-muted flex flex-col gap-1">
            Strategy family (optional)
            <Input aria-label="Strategy family (optional)" value={strategy} onChange={(e) => setStrategy(e.target.value)} className="font-mono text-sm" />
          </label>
          <label className="font-mono text-xs text-text-muted flex flex-col gap-1">
            Description
            <Textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
              className="font-mono text-sm"
            />
          </label>
          <label className="font-mono text-xs text-text-muted inline-flex items-center gap-2">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              className="h-3.5 w-3.5"
            />
            Enabled
          </label>
          {error && (
            <div className="rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
              {error}
            </div>
          )}
          <div className="flex gap-2 pt-1">
            <Button type="button" size="sm" className="flex-1" onClick={handleSubmit} disabled={isPending}>
              {isPending ? "Saving..." : "Save"}
            </Button>
            <Button type="button" size="sm" variant="outline" onClick={handleClose}>
              Cancel
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
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
    <Dialog open={target !== null} onOpenChange={(v) => { if (!v) { setError(null); onClose(); } }}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle className="font-mono text-text">Delete specialist</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-3">
          {target && (
            <p className="font-mono text-xs text-text-muted">
              Remove <span className="text-text">{target.name}</span> from
              module <span className="text-text">{target.module_id}</span>?
            </p>
          )}
          {error && (
            <div className="rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
              {error}
            </div>
          )}
          <div className="flex gap-2 pt-1">
            <Button type="button" size="sm" className="flex-1" onClick={handleConfirm} disabled={isPending}>
              {isPending ? "Deleting..." : "Delete"}
            </Button>
            <Button type="button" size="sm" variant="outline" onClick={() => { setError(null); onClose(); }}>
              Cancel
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Specialists: tab body
// ---------------------------------------------------------------------------

function SpecialistsTab() {
  const [moduleId, setModuleId] = useState<SpecialistModuleId>("vr");
  const [newOpen, setNewOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<SpecialistAgent | null>(null);

  const specialistsQuery = useSpecialists(moduleId);
  const upsertMutation = useUpsertSpecialist();
  const seedMutation = useSeedSpecialists();
  const deleteMutation = useDeleteSpecialist();

  const rows = specialistsQuery.data ?? [];

  const sortedRows = useMemo(
    () => [...rows].sort((a, b) => a.name.localeCompare(b.name)),
    [rows],
  );

  return (
    <div className="flex flex-col gap-4">
      <AilaCard variant="default" padding="md" techBorder glow>
        <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs uppercase tracking-wider text-text-muted">
              Module
            </span>
            <div className="flex gap-1 rounded-[4px] border border-border p-0.5">
              {SPECIALIST_MODULE_IDS.map((id) => (
                <button
                  key={id}
                  type="button"
                  onClick={() => setModuleId(id)}
                  className={
                    "font-mono text-xs px-2 py-1 rounded-[2px] " +
                    (moduleId === id
                      ? "bg-accent text-accent-foreground"
                      : "text-text-muted hover:text-text")
                  }
                >
                  {id}
                </button>
              ))}
            </div>
          </div>
          <div className="flex gap-2">
            <Button
              size="xs"
              variant="outline"
              onClick={() => void specialistsQuery.refetch()}
              disabled={specialistsQuery.isFetching}
            >
              <ArrowsCounterClockwise className="h-3 w-3" />
              Refresh
            </Button>
            <Button
              size="xs"
              variant="outline"
              onClick={() => seedMutation.mutate(moduleId)}
              disabled={seedMutation.isPending}
              title={`Seed built-in defaults for ${moduleId}`}
            >
              <Plant className="h-3 w-3" />
              {seedMutation.isPending ? "Seeding..." : "Seed defaults"}
            </Button>
            <Button size="xs" onClick={() => setNewOpen(true)}>
              <Plus className="h-3 w-3" />
              New specialist
            </Button>
          </div>
        </div>

        {seedMutation.isSuccess && seedMutation.data && (
          <div className="mb-3 rounded-[4px] border border-low/40 bg-low/10 px-3 py-2 font-mono text-xs text-low">
            Seeded {seedMutation.data.data.inserted} default specialist
            {seedMutation.data.data.inserted === 1 ? "" : "s"} for {moduleId}.
          </div>
        )}
        {seedMutation.isError && (
          <div className="mb-3 rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
            Seed failed: {(seedMutation.error as Error).message}
          </div>
        )}

        {specialistsQuery.isLoading && <LoadingSkeletonGroup lines={4} />}
        {specialistsQuery.isError && (
          <div className="rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
            Failed to load specialists: {(specialistsQuery.error as Error).message}
          </div>
        )}
        {!specialistsQuery.isLoading && !specialistsQuery.isError && sortedRows.length === 0 && (
          <EmptyState
            title="No specialists"
            description={`Seed the built-in defaults for ${moduleId} or add one manually.`}
          />
        )}
        {!specialistsQuery.isLoading && sortedRows.length > 0 && (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {sortedRows.map((row) => (
              <div
                key={row.id}
                className="rounded-[4px] border border-border bg-base p-3 flex flex-col gap-2"
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <h3 className="font-mono text-sm font-semibold text-text">{row.name}</h3>
                    <AilaBadge severity={row.enabled ? "low" : "neutral"} size="sm">
                      {row.enabled ? "enabled" : "disabled"}
                    </AilaBadge>
                  </div>
                  <Button
                    size="xs"
                    variant="outline"
                    onClick={() => setDeleteTarget(row)}
                    title="Delete specialist"
                  >
                    <Trash className="h-3 w-3" />
                  </Button>
                </div>
                <div className="flex flex-col gap-1 font-mono text-xs">
                  <div className="flex gap-1.5">
                    <span className="text-text-muted">capability:</span>
                    <code className="text-text bg-elevated px-1 rounded-[2px]">
                      {row.capability}
                    </code>
                  </div>
                  {row.strategy_family && (
                    <div className="flex gap-1.5">
                      <span className="text-text-muted">strategy:</span>
                      <code className="text-text bg-elevated px-1 rounded-[2px]">
                        {row.strategy_family}
                      </code>
                    </div>
                  )}
                  <div className="flex gap-1.5">
                    <span className="text-text-muted">team_id:</span>
                    <span className="text-text">{row.team_id ?? "global"}</span>
                  </div>
                </div>
                {row.description && (
                  <p className="font-mono text-xs text-text-muted line-clamp-3">
                    {row.description}
                  </p>
                )}
                <p className="font-mono text-[10px] text-text-muted">
                  updated {formatTimestamp(row.updated_at)}
                </p>
              </div>
            ))}
          </div>
        )}
      </AilaCard>

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

export function PlatformInfraPage() {
  const [tab, setTab] = useState<string>("mcp");
  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      <Tabs value={tab} onValueChange={setTab} className="flex flex-col gap-4">
        <TabsList variant="line">
          <TabsTrigger value="mcp">MCP Registry</TabsTrigger>
          <TabsTrigger value="specialists">Specialists</TabsTrigger>
        </TabsList>
        <TabsContent value="mcp">
          <McpRegistryTab />
        </TabsContent>
        <TabsContent value="specialists">
          <SpecialistsTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
