/**
 * OidcProvidersPage — admin-only multi-provider OIDC management (Phase 177).
 *
 * Supports Microsoft (tenant_id), Google (hardcoded issuer), and generic
 * OIDC (operator-supplied issuer_url). Backend enforces rbac; this page
 * provides CRUD via /auth/oidc/providers.
 *
 * Client secrets are write-only: entered at create/update time, never
 * returned in any GET response.
 */
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type ColumnDef } from "@tanstack/react-table";
import { Key } from "@phosphor-icons/react/dist/csr/Key";
import { Plus } from "@phosphor-icons/react/dist/csr/Plus";
import { PencilSimple } from "@phosphor-icons/react/dist/csr/PencilSimple";
import { Trash } from "@phosphor-icons/react/dist/csr/Trash";

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

type ProviderType = "microsoft" | "google" | "generic";

interface OidcProvider {
  id: string;
  provider_name: string;
  provider_type: ProviderType;
  display_name: string | null;
  tenant_id: string | null;
  issuer_url: string | null;
  client_id: string;
  scopes: string[];
  is_enabled: boolean;
  created_at: string;
}

interface DataEnvelope<T> {
  data: T;
  error: string | null;
  meta: Record<string, unknown>;
}

interface CreateRequest {
  provider_name: string;
  provider_type: ProviderType;
  display_name?: string;
  tenant_id?: string;
  issuer_url?: string;
  client_id: string;
  client_secret: string;
  scopes?: string[];
  is_enabled: boolean;
}

interface UpdateRequest {
  provider_name?: string;
  provider_type?: ProviderType;
  display_name?: string;
  tenant_id?: string;
  issuer_url?: string;
  client_id?: string;
  client_secret?: string;
  scopes?: string[];
  is_enabled?: boolean;
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function providerSeverity(pt: ProviderType): "info" | "medium" | "neutral" {
  if (pt === "microsoft") return "info";
  if (pt === "google") return "medium";
  return "neutral";
}

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

// ---------------------------------------------------------------------------
// Create/Edit dialog (shared shape)
// ---------------------------------------------------------------------------

interface ProviderFormState {
  provider_name: string;
  provider_type: ProviderType;
  display_name: string;
  tenant_id: string;
  issuer_url: string;
  client_id: string;
  client_secret: string;
  scopes: string;
  is_enabled: boolean;
}

const DEFAULT_FORM: ProviderFormState = {
  provider_name: "",
  provider_type: "microsoft",
  display_name: "",
  tenant_id: "",
  issuer_url: "",
  client_id: "",
  client_secret: "",
  scopes: "openid,email,profile",
  is_enabled: true,
};

function toCreateRequest(form: ProviderFormState): CreateRequest {
  const scopes = form.scopes
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  const body: CreateRequest = {
    provider_name: form.provider_name,
    provider_type: form.provider_type,
    client_id: form.client_id,
    client_secret: form.client_secret,
    is_enabled: form.is_enabled,
  };
  if (form.display_name) body.display_name = form.display_name;
  if (form.provider_type === "microsoft" && form.tenant_id) {
    body.tenant_id = form.tenant_id;
  }
  if (form.provider_type === "generic" && form.issuer_url) {
    body.issuer_url = form.issuer_url;
  }
  if (scopes.length > 0) body.scopes = scopes;
  return body;
}

function toUpdateRequest(
  form: ProviderFormState,
  original: OidcProvider,
): UpdateRequest {
  const scopes = form.scopes
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  const diff: UpdateRequest = {};
  if (form.provider_name !== original.provider_name) diff.provider_name = form.provider_name;
  if (form.provider_type !== original.provider_type) diff.provider_type = form.provider_type;
  if ((form.display_name || null) !== original.display_name) diff.display_name = form.display_name;
  if ((form.tenant_id || null) !== original.tenant_id) diff.tenant_id = form.tenant_id;
  if ((form.issuer_url || null) !== original.issuer_url) diff.issuer_url = form.issuer_url;
  if (form.client_id !== original.client_id) diff.client_id = form.client_id;
  if (form.client_secret) diff.client_secret = form.client_secret;
  if (scopes.join(",") !== original.scopes.join(",")) diff.scopes = scopes;
  if (form.is_enabled !== original.is_enabled) diff.is_enabled = form.is_enabled;
  return diff;
}

function ProviderFormFields({
  form,
  setForm,
}: {
  form: ProviderFormState;
  setForm: (updater: (f: ProviderFormState) => ProviderFormState) => void;
}) {
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-col gap-1">
        <label className="font-mono text-xs text-text-muted" htmlFor="op-name">
          Internal name *
        </label>
        <Input
          id="op-name"
          value={form.provider_name}
          onChange={(e) => setForm((f) => ({ ...f, provider_name: e.target.value }))}
          placeholder="acme-okta"
          className="font-mono text-sm"
        />
      </div>

      <div className="flex flex-col gap-1">
        <label className="font-mono text-xs text-text-muted" htmlFor="op-type">
          Provider type *
        </label>
        <select
          id="op-type"
          value={form.provider_type}
          onChange={(e) =>
            setForm((f) => ({ ...f, provider_type: e.target.value as ProviderType }))
          }
          className="rounded-[2px] border border-border bg-base font-mono text-sm text-text px-2.5 py-1.5 outline-none focus:border-border-hover transition-colors duration-100"
        >
          <option value="microsoft">Microsoft (Azure AD)</option>
          <option value="google">Google</option>
          <option value="generic">Generic OIDC</option>
        </select>
      </div>

      <div className="flex flex-col gap-1">
        <label className="font-mono text-xs text-text-muted" htmlFor="op-display">
          Display name
        </label>
        <Input
          id="op-display"
          value={form.display_name}
          onChange={(e) => setForm((f) => ({ ...f, display_name: e.target.value }))}
          placeholder="Sign in with Okta"
          className="font-mono text-sm"
        />
      </div>

      {form.provider_type === "microsoft" && (
        <div className="flex flex-col gap-1">
          <label className="font-mono text-xs text-text-muted" htmlFor="op-tenant">
            Tenant id *
          </label>
          <Input
            id="op-tenant"
            value={form.tenant_id}
            onChange={(e) => setForm((f) => ({ ...f, tenant_id: e.target.value }))}
            placeholder="00000000-0000-0000-0000-000000000000"
            className="font-mono text-sm"
          />
        </div>
      )}

      {form.provider_type === "generic" && (
        <div className="flex flex-col gap-1">
          <label className="font-mono text-xs text-text-muted" htmlFor="op-issuer">
            Issuer URL *
          </label>
          <Input
            id="op-issuer"
            value={form.issuer_url}
            onChange={(e) => setForm((f) => ({ ...f, issuer_url: e.target.value }))}
            placeholder="https://idp.example.com/oidc"
            className="font-mono text-sm"
          />
        </div>
      )}

      <div className="flex flex-col gap-1">
        <label className="font-mono text-xs text-text-muted" htmlFor="op-client-id">
          Client id *
        </label>
        <Input
          id="op-client-id"
          value={form.client_id}
          onChange={(e) => setForm((f) => ({ ...f, client_id: e.target.value }))}
          className="font-mono text-sm"
        />
      </div>

      <div className="flex flex-col gap-1">
        <label className="font-mono text-xs text-text-muted" htmlFor="op-client-secret">
          Client secret {form.provider_type ? "(leave blank to keep current)" : "*"}
        </label>
        <Input
          id="op-client-secret"
          type="password"
          value={form.client_secret}
          onChange={(e) => setForm((f) => ({ ...f, client_secret: e.target.value }))}
          className="font-mono text-sm"
        />
      </div>

      <div className="flex flex-col gap-1">
        <label className="font-mono text-xs text-text-muted" htmlFor="op-scopes">
          Scopes (comma separated)
        </label>
        <Input
          id="op-scopes"
          value={form.scopes}
          onChange={(e) => setForm((f) => ({ ...f, scopes: e.target.value }))}
          className="font-mono text-sm"
        />
      </div>

      <label className="inline-flex items-center gap-2 font-mono text-xs text-text">
        <input
          type="checkbox"
          checked={form.is_enabled}
          onChange={(e) => setForm((f) => ({ ...f, is_enabled: e.target.checked }))}
        />
        Enabled
      </label>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Create dialog
// ---------------------------------------------------------------------------

function CreateProviderDialog({
  onCreate,
  isPending,
}: {
  onCreate: (req: CreateRequest) => Promise<unknown>;
  isPending: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<ProviderFormState>(DEFAULT_FORM);
  const [error, setError] = useState<string | null>(null);

  function handleClose() {
    setOpen(false);
    setTimeout(() => {
      setForm(DEFAULT_FORM);
      setError(null);
    }, 200);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await onCreate(toCreateRequest(form));
      handleClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create provider");
    }
  }

  return (
    <>
      <Button size="sm" className="gap-1.5" onClick={() => setOpen(true)}>
        <Plus className="h-4 w-4" />
        Add provider
      </Button>
      <Dialog open={open} onOpenChange={(v) => { if (!v) handleClose(); }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="font-mono text-text">Add OIDC provider</DialogTitle>
          </DialogHeader>
          <form className="flex flex-col gap-4" onSubmit={handleSubmit}>
            <ProviderFormFields form={form} setForm={setForm} />
            {error && (
              <div className="rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
                {error}
              </div>
            )}
            <div className="flex gap-2">
              <Button type="submit" size="sm" disabled={isPending} className="flex-1">
                {isPending ? "Creating…" : "Create"}
              </Button>
              <Button type="button" size="sm" variant="outline" onClick={handleClose}>
                Cancel
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </>
  );
}

// ---------------------------------------------------------------------------
// Edit dialog
// ---------------------------------------------------------------------------

function EditProviderDialog({
  provider,
  onUpdate,
  isPending,
}: {
  provider: OidcProvider;
  onUpdate: (id: string, req: UpdateRequest) => Promise<unknown>;
  isPending: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<ProviderFormState>(() => ({
    provider_name: provider.provider_name,
    provider_type: provider.provider_type,
    display_name: provider.display_name ?? "",
    tenant_id: provider.tenant_id ?? "",
    issuer_url: provider.issuer_url ?? "",
    client_id: provider.client_id,
    client_secret: "",
    scopes: provider.scopes.join(","),
    is_enabled: provider.is_enabled,
  }));
  const [error, setError] = useState<string | null>(null);

  function handleClose() {
    setOpen(false);
    setTimeout(() => setError(null), 200);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await onUpdate(provider.id, toUpdateRequest(form, provider));
      handleClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update provider");
    }
  }

  return (
    <>
      <Button
        type="button"
        size="sm"
        variant="outline"
        className="gap-1.5"
        onClick={() => setOpen(true)}
      >
        <PencilSimple className="h-3.5 w-3.5" />
        Edit
      </Button>
      <Dialog open={open} onOpenChange={(v) => { if (!v) handleClose(); }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="font-mono text-text">Edit OIDC provider</DialogTitle>
          </DialogHeader>
          <form className="flex flex-col gap-4" onSubmit={handleSubmit}>
            <ProviderFormFields form={form} setForm={setForm} />
            {error && (
              <div className="rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
                {error}
              </div>
            )}
            <div className="flex gap-2">
              <Button type="submit" size="sm" disabled={isPending} className="flex-1">
                {isPending ? "Saving…" : "Save"}
              </Button>
              <Button type="button" size="sm" variant="outline" onClick={handleClose}>
                Cancel
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </>
  );
}

// ---------------------------------------------------------------------------
// Delete dialog
// ---------------------------------------------------------------------------

function DeleteProviderDialog({
  provider,
  onDelete,
  isPending,
}: {
  provider: OidcProvider;
  onDelete: (id: string) => Promise<unknown>;
  isPending: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleConfirm() {
    setError(null);
    try {
      await onDelete(provider.id);
      setOpen(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete provider");
    }
  }

  return (
    <>
      <Button
        type="button"
        size="sm"
        variant="outline"
        className="gap-1.5 text-destructive border-destructive/40 hover:bg-destructive/10 hover:border-destructive"
        onClick={() => setOpen(true)}
      >
        <Trash className="h-3.5 w-3.5" />
        Delete
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-sm">
          <DialogHeader>
            <DialogTitle className="font-mono text-text">Delete OIDC provider</DialogTitle>
          </DialogHeader>
          <div className="flex flex-col gap-4">
            <div className="rounded-[4px] border border-destructive/40 bg-destructive/10 px-4 py-3">
              <p className="font-mono text-xs text-destructive font-semibold mb-1">
                This action is irreversible.
              </p>
              <p className="font-mono text-xs text-text-muted">
                Deleting <span className="text-text font-semibold">{provider.provider_name}</span>
                {" "}removes the provider and its stored client secret. Existing
                sessions are unaffected; new sign-ins via this provider will fail.
              </p>
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
                {isPending ? "Deleting…" : "Confirm delete"}
              </Button>
              <Button type="button" size="sm" variant="outline" onClick={() => setOpen(false)}>
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
// Columns
// ---------------------------------------------------------------------------

function buildColumns(
  onUpdate: (id: string, req: UpdateRequest) => Promise<unknown>,
  onDelete: (id: string) => Promise<unknown>,
  isUpdating: boolean,
  isDeleting: boolean,
): ColumnDef<OidcProvider>[] {
  return [
    {
      id: "name",
      header: "Name",
      accessorKey: "provider_name",
      cell: ({ row }) => (
        <div className="flex flex-col">
          <span className="font-mono text-sm text-text">{row.original.provider_name}</span>
          {row.original.display_name && (
            <span className="font-mono text-xs text-text-muted">{row.original.display_name}</span>
          )}
        </div>
      ),
    },
    {
      id: "provider_type",
      header: "Type",
      accessorKey: "provider_type",
      cell: ({ getValue }) => {
        const pt = getValue() as ProviderType;
        return (
          <AilaBadge severity={providerSeverity(pt)} size="sm">
            {pt}
          </AilaBadge>
        );
      },
    },
    {
      id: "client_id",
      header: "Client id",
      accessorKey: "client_id",
      cell: ({ getValue }) => (
        <code className="font-mono text-xs text-text-muted break-all">
          {String(getValue())}
        </code>
      ),
    },
    {
      id: "is_enabled",
      header: "Status",
      accessorKey: "is_enabled",
      cell: ({ getValue }) =>
        getValue() ? (
          <AilaBadge severity="info" size="sm">Enabled</AilaBadge>
        ) : (
          <AilaBadge severity="neutral" size="sm">Disabled</AilaBadge>
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
      id: "actions",
      header: "Actions",
      enableSorting: false,
      cell: ({ row }) => (
        <div className="flex gap-1.5">
          <EditProviderDialog
            provider={row.original}
            onUpdate={onUpdate}
            isPending={isUpdating}
          />
          <DeleteProviderDialog
            provider={row.original}
            onDelete={onDelete}
            isPending={isDeleting}
          />
        </div>
      ),
    },
  ];
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function OidcProvidersPage() {
  const queryClient = useQueryClient();

  const providersQuery = useQuery({
    queryKey: ["platform", "oidc-providers"],
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<OidcProvider[]>>("/auth/oidc/providers"),
  });

  const createMutation = useMutation({
    mutationFn: (req: CreateRequest) =>
      authorizedRequestJson<DataEnvelope<OidcProvider>>("/auth/oidc/providers", {
        method: "POST",
        body: req,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "oidc-providers"] });
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, req }: { id: string; req: UpdateRequest }) =>
      authorizedRequestJson<DataEnvelope<OidcProvider>>(`/auth/oidc/providers/${id}`, {
        method: "PUT",
        body: req,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "oidc-providers"] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      authorizedRequestJson<DataEnvelope<{ deleted: string }>>(
        `/auth/oidc/providers/${id}`,
        { method: "DELETE" },
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "oidc-providers"] });
    },
  });

  const providers = providersQuery.data?.data ?? [];

  const { totalProviders, enabledProviders } = useMemo(() => {
    const total = providers.length;
    const enabled = providers.filter((p) => p.is_enabled).length;
    return { totalProviders: total, enabledProviders: enabled };
  }, [providers]);

  const columns = buildColumns(
    (id, req) => updateMutation.mutateAsync({ id, req }),
    (id) => deleteMutation.mutateAsync(id),
    updateMutation.isPending,
    deleteMutation.isPending,
  );

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <CreateProviderDialog
          onCreate={(req) => createMutation.mutateAsync(req)}
          isPending={createMutation.isPending}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Total providers
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {providersQuery.isLoading ? "—" : totalProviders}
        </p></AilaCard>
        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Enabled
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {providersQuery.isLoading ? "—" : enabledProviders}
        </p></AilaCard>
      </div>

      {providersQuery.isError && (
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-sm text-destructive">
          Failed to load OIDC providers: {(providersQuery.error as Error).message}
        </div>
      )}

      {providersQuery.isLoading && (
        <AilaCard variant="default" padding="md" techBorder glow><LoadingSkeletonGroup lines={6} /></AilaCard>
      )}

      {!providersQuery.isLoading && !providersQuery.isError && providers.length === 0 && (
        <EmptyState
          icon={<Key className="h-10 w-10" />}
          title="No OIDC providers configured"
          description="Add a Microsoft, Google, or generic OIDC provider to enable single sign-on."
        />
      )}

      {!providersQuery.isLoading && providers.length > 0 && (
        <AilaTable
          data={providers}
          columns={columns}
          pageSize={25}
          enableSorting
          enableFiltering={false}
        >
          <AilaTable.Header />
          <AilaTable.Body emptyState="No providers found." />
          <AilaTable.Pagination pageSizeOptions={[10, 25, 50]} />
        </AilaTable>
      )}
    </div>
  );
}
