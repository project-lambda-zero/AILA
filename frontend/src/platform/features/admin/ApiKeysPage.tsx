/**
 * ApiKeysPage — admin API key management with create and revoke.
 *
 * ADM-02: Lists all API keys (including revoked history). Admins can:
 * - Create a new key (label + role) via Dialog — raw key shown once.
 * - Revoke an active key via confirmation Dialog.
 *
 * Uses real backend: GET/POST/DELETE /auth/keys.
 * No mock data — revoked_at presence determines key status.
 */
import { useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { type ColumnDef } from "@tanstack/react-table";
import { Key, Plus, Copy, Check } from "@phosphor-icons/react";

import { AilaCard } from "@/components/aila/AilaCard";
import { AilaTable } from "@/components/aila/AilaTable";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { EmptyState } from "@/components/aila/EmptyState";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { authorizedRequestJson } from "@platform/api/http";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ApiKeyListItem {
  key_id: string;
  key_prefix: string;
  role: string;
  label: string;
  created_by: string;
  created_at: string;
  revoked_at: string | null;
}

interface ApiKeyListResponse {
  keys: ApiKeyListItem[];
}

interface ApiKeyCreateRequest {
  role: "admin" | "operator" | "reader";
  label: string;
}

interface ApiKeyCreateResponse {
  key_id: string;
  raw_key: string;
  key_prefix: string;
  role: string;
  label: string;
  created_at: string;
}

interface ApiKeyRevokeResponse {
  key_id: string;
  revoked: boolean;
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function roleSeverity(
  role: string,
): "critical" | "medium" | "neutral" {
  if (role === "admin") return "critical";
  if (role === "operator") return "medium";
  return "neutral";
}

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

// ---------------------------------------------------------------------------
// Copy button for raw key
// ---------------------------------------------------------------------------

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <Button
      type="button"
      size="sm"
      variant="outline"
      className="gap-1.5"
      onClick={handleCopy}
    >
      {copied ? (
        <>
          <Check className="h-3.5 w-3.5 text-mint" />
          Copied
        </>
      ) : (
        <>
          <Copy className="h-3.5 w-3.5" />
          Copy
        </>
      )}
    </Button>
  );
}

// ---------------------------------------------------------------------------
// Create key dialog
// ---------------------------------------------------------------------------

const DEFAULT_CREATE_FORM: ApiKeyCreateRequest = {
  role: "reader",
  label: "",
};

function CreateKeyDialog({
  onCreate,
  isPending,
}: {
  onCreate: (req: ApiKeyCreateRequest) => Promise<ApiKeyCreateResponse>;
  isPending: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<ApiKeyCreateRequest>(DEFAULT_CREATE_FORM);
  const [createdKey, setCreatedKey] = useState<ApiKeyCreateResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  function handleClose() {
    setOpen(false);
    // Reset after close animation
    setTimeout(() => {
      setForm(DEFAULT_CREATE_FORM);
      setCreatedKey(null);
      setError(null);
    }, 200);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const result = await onCreate(form);
      setCreatedKey(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create key");
    }
  }

  return (
    <>
      <Button size="sm" className="gap-1.5" onClick={() => setOpen(true)}>
        <Plus className="h-4 w-4" />
        Create API Key
      </Button>

      <Dialog open={open} onOpenChange={(v) => { if (!v) handleClose(); }}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="font-mono text-text">
            {createdKey ? "Key Created" : "Create API Key"}
          </DialogTitle>
        </DialogHeader>

        {createdKey ? (
          // Success view — show raw key once
          <div className="flex flex-col gap-4">
            <div className="rounded-[4px] border border-accent/40 bg-accent/10 px-4 py-3">
              <p className="font-mono text-xs text-accent font-semibold mb-1">
                Copy this key now — it will not be shown again.
              </p>
              <p className="font-mono text-xs text-text-muted">
                Store it securely. Once dismissed, the raw key cannot be recovered.
              </p>
            </div>

            <div className="flex flex-col gap-2">
              <label className="font-mono text-xs text-text-muted">Raw API Key</label>
              <div className="flex items-center gap-2">
                <code className="flex-1 rounded-[2px] border border-border bg-base px-2.5 py-1.5 font-mono text-xs text-text break-all">
                  {createdKey.raw_key}
                </code>
                <CopyButton value={createdKey.raw_key} />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="flex flex-col gap-0.5">
                <p className="font-mono text-xs text-text-muted">Prefix</p>
                <p className="font-mono text-xs text-text">{createdKey.key_prefix}</p>
              </div>
              <div className="flex flex-col gap-0.5">
                <p className="font-mono text-xs text-text-muted">Role</p>
                <AilaBadge severity={roleSeverity(createdKey.role)} size="sm">
                  {createdKey.role}
                </AilaBadge>
              </div>
              <div className="flex flex-col gap-0.5">
                <p className="font-mono text-xs text-text-muted">Label</p>
                <p className="font-mono text-xs text-text">{createdKey.label || "—"}</p>
              </div>
            </div>

            <Button type="button" onClick={handleClose} className="w-full">
              Done
            </Button>
          </div>
        ) : (
          // Create form
          <form className="flex flex-col gap-4" onSubmit={handleSubmit}>
            <div className="flex flex-col gap-1">
              <label className="font-mono text-xs text-text-muted" htmlFor="ck-label">
                Label
              </label>
              <Input
                id="ck-label"
                value={form.label}
                onChange={(e) => setForm((f) => ({ ...f, label: e.target.value }))}
                placeholder="CI deploy key"
                className="font-mono text-sm"
              />
            </div>

            <div className="flex flex-col gap-1">
              <label className="font-mono text-xs text-text-muted" htmlFor="ck-role">
                Role
              </label>
              <select
                id="ck-role"
                value={form.role}
                onChange={(e) =>
                  setForm((f) => ({
                    ...f,
                    role: e.target.value as ApiKeyCreateRequest["role"],
                  }))
                }
                className="rounded-[2px] border border-border bg-base font-mono text-sm text-text px-2.5 py-1.5 outline-none focus:border-border-hover transition-colors duration-100"
              >
                <option value="reader">reader</option>
                <option value="operator">operator</option>
                <option value="admin">admin</option>
              </select>
            </div>

            {error && (
              <div className="rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
                {error}
              </div>
            )}

            <div className="flex gap-2">
              <Button type="submit" size="sm" disabled={isPending} className="flex-1">
                {isPending ? "Creating…" : "Create Key"}
              </Button>
              <Button
                type="button"
                size="sm"
                variant="outline"
                onClick={handleClose}
              >
                Cancel
              </Button>
            </div>
          </form>
        )}
      </DialogContent>
      </Dialog>
    </>
  );
}

// ---------------------------------------------------------------------------
// Revoke confirmation dialog
// ---------------------------------------------------------------------------

function RevokeKeyDialog({
  keyItem,
  onRevoke,
  isPending,
}: {
  keyItem: ApiKeyListItem;
  onRevoke: (keyId: string) => Promise<ApiKeyRevokeResponse>;
  isPending: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleConfirm() {
    setError(null);
    try {
      await onRevoke(keyItem.key_id);
      setOpen(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to revoke key");
    }
  }

  return (
    <>
      <Button
        size="sm"
        variant="outline"
        className="text-destructive border-destructive/40 hover:bg-destructive/10 hover:border-destructive"
        disabled={keyItem.revoked_at !== null}
        onClick={() => setOpen(true)}
      >
        Revoke
      </Button>

      <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle className="font-mono text-text">Revoke API Key</DialogTitle>
        </DialogHeader>

        <div className="flex flex-col gap-4">
          <div className="rounded-[4px] border border-destructive/40 bg-destructive/10 px-4 py-3">
            <p className="font-mono text-xs text-destructive font-semibold mb-1">
              This action is irreversible.
            </p>
            <p className="font-mono text-xs text-text-muted">
              Revoking key <span className="text-text font-semibold">{keyItem.key_prefix}</span>
              {" "}will immediately invalidate all JWTs issued for this key.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-2">
            <div className="flex flex-col gap-0.5">
              <p className="font-mono text-xs text-text-muted">Prefix</p>
              <p className="font-mono text-xs text-text">{keyItem.key_prefix}</p>
            </div>
            <div className="flex flex-col gap-0.5">
              <p className="font-mono text-xs text-text-muted">Role</p>
              <AilaBadge severity={roleSeverity(keyItem.role)} size="sm">
                {keyItem.role}
              </AilaBadge>
            </div>
            <div className="flex flex-col gap-0.5">
              <p className="font-mono text-xs text-text-muted">Label</p>
              <p className="font-mono text-xs text-text">{keyItem.label || "—"}</p>
            </div>
          </div>

          {error && (
            <div className="rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
              {error}
            </div>
          )}

          <div className="flex gap-2">
            <Button
              type="button"
              size="sm"
              className="flex-1 bg-destructive hover:bg-destructive/90 text-white"
              onClick={handleConfirm}
              disabled={isPending}
            >
              {isPending ? "Revoking…" : "Confirm Revoke"}
            </Button>
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => setOpen(false)}
            >
              Cancel
            </Button>
          </div>
        </div>
      </DialogContent>
      </Dialog>
    </>
  );
}

// ---------------------------------------------------------------------------
// Column definitions (declared at module level to avoid re-creation)
// ---------------------------------------------------------------------------

function buildColumns(
  onRevoke: (keyId: string) => Promise<ApiKeyRevokeResponse>,
  isRevokePending: boolean,
): ColumnDef<ApiKeyListItem>[] {
  return [
    {
      id: "key_prefix",
      header: "Prefix",
      accessorKey: "key_prefix",
      cell: ({ getValue }) => (
        <code className="font-mono text-xs text-text">{String(getValue())}</code>
      ),
    },
    {
      id: "role",
      header: "Role",
      accessorKey: "role",
      cell: ({ getValue }) => {
        const r = String(getValue());
        return (
          <AilaBadge severity={roleSeverity(r)} size="sm">
            {r}
          </AilaBadge>
        );
      },
    },
    {
      id: "label",
      header: "Label",
      accessorKey: "label",
      cell: ({ getValue }) => (
        <span className="font-mono text-xs text-text">{String(getValue()) || "—"}</span>
      ),
    },
    {
      id: "created_by",
      header: "Created By",
      accessorKey: "created_by",
      cell: ({ getValue }) => (
        <span className="font-mono text-xs text-text-muted">{String(getValue())}</span>
      ),
    },
    {
      id: "created_at",
      header: "Created",
      accessorKey: "created_at",
      cell: ({ getValue }) => (
        <span className="font-mono text-xs text-text-muted whitespace-nowrap">
          {formatTimestamp(getValue() as string)}
        </span>
      ),
    },
    {
      id: "status",
      header: "Status",
      accessorKey: "revoked_at",
      cell: ({ getValue }) => {
        const revokedAt = getValue() as string | null;
        return revokedAt ? (
          <AilaBadge severity="neutral" size="sm">Revoked</AilaBadge>
        ) : (
          <AilaBadge severity="info" size="sm">Active</AilaBadge>
        );
      },
    },
    {
      id: "actions",
      header: "Actions",
      enableSorting: false,
      cell: ({ row }) => (
        <RevokeKeyDialog
          keyItem={row.original}
          onRevoke={onRevoke}
          isPending={isRevokePending}
        />
      ),
    },
  ];
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function ApiKeysPage() {
  const queryClient = useQueryClient();

  const keysQuery = useQuery({
    queryKey: ["platform", "api-keys"],
    queryFn: () =>
      authorizedRequestJson<ApiKeyListResponse>("/auth/keys?active_only=false"),
  });

  const createMutation = useMutation({
    mutationFn: (req: ApiKeyCreateRequest) =>
      authorizedRequestJson<ApiKeyCreateResponse>("/auth/keys", {
        method: "POST",
        body: req,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "api-keys"] });
    },
  });

  const revokeMutation = useMutation({
    mutationFn: (keyId: string) =>
      authorizedRequestJson<ApiKeyRevokeResponse>(`/auth/keys/${keyId}`, {
        method: "DELETE",
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "api-keys"] });
    },
  });

  const keys = keysQuery.data?.keys ?? [];

  const { totalKeys, activeKeys, revokedKeys } = useMemo(() => {
    const total = keys.length;
    const revoked = keys.filter((k) => k.revoked_at !== null).length;
    return { totalKeys: total, activeKeys: total - revoked, revokedKeys: revoked };
  }, [keys]);

  const columns = buildColumns(
    (keyId) => revokeMutation.mutateAsync(keyId),
    revokeMutation.isPending,
  );

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      {/* Page header */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="font-mono text-xl font-semibold text-text flex items-center gap-2">
            <Key className="h-5 w-5 text-accent" />
            API Keys
          </h1>
          <p className="font-mono text-sm text-text-muted mt-0.5">
            Manage platform API keys. Raw keys are shown only at creation time.
          </p>
        </div>

        <CreateKeyDialog
          onCreate={(req) => createMutation.mutateAsync(req)}
          isPending={createMutation.isPending}
        />
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Total Keys
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {keysQuery.isLoading ? "—" : totalKeys}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">All time</p></AilaCard>

        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Active Keys
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {keysQuery.isLoading ? "—" : activeKeys}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">
          Not revoked
        </p></AilaCard>

        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Revoked Keys
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {keysQuery.isLoading ? "—" : revokedKeys}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">
          Invalidated
        </p></AilaCard>
      </div>

      {/* Error banner */}
      {keysQuery.isError && (
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-sm text-destructive">
          Failed to load API keys: {(keysQuery.error as Error).message}
        </div>
      )}

      {/* Loading skeleton */}
      {keysQuery.isLoading && (
        <AilaCard variant="default" padding="md" techBorder glow><LoadingSkeletonGroup lines={6} /></AilaCard>
      )}

      {/* Empty state */}
      {!keysQuery.isLoading && !keysQuery.isError && keys.length === 0 && (
        <EmptyState
          icon={<Key className="h-10 w-10" />}
          title="No API keys"
          description="Create an API key to allow programmatic access to the platform."
        />
      )}

      {/* Keys table */}
      {!keysQuery.isLoading && keys.length > 0 && (
        <AilaTable
          data={keys}
          columns={columns}
          pageSize={25}
          enableSorting
          enableFiltering={false}
        >
          <AilaTable.Header />
          <AilaTable.Body emptyState="No keys found." />
          <AilaTable.Pagination pageSizeOptions={[10, 25, 50]} />
        </AilaTable>
      )}
    </div>
  );
}
