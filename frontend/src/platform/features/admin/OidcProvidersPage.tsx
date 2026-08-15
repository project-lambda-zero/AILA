/**
 * OidcProvidersPage -- admin-only multi-provider OIDC management (Phase 177).
 *
 * Supports Microsoft (tenant_id), Google (hardcoded issuer), and generic
 * OIDC (operator-supplied issuer_url). Backend enforces rbac; this page
 * provides CRUD via /auth/oidc/providers.
 *
 * Client secrets are write-only: entered at create/update time, never
 * returned in any GET response.
 *
 * Presentation rebuilt to the AILA mock language. Data hooks, mutations,
 * and testids preserved.
 */
import * as React from "react";
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { SectionHeader, DataGrid, MonoBadge, FilterChip } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
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
// Local mock styles
// ---------------------------------------------------------------------------

const btnBase: React.CSSProperties = {
  height: 26,
  fontSize: 9.5,
  letterSpacing: "0.08em",
  padding: "0 11px",
  borderRadius: 3,
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  cursor: "pointer",
  textTransform: "uppercase",
  fontFamily: "var(--font-mono)",
};

const primaryBtn: React.CSSProperties = {
  ...btnBase,
  background: "var(--accent)",
  color: "var(--text-on-accent)",
  borderColor: "var(--accent)",
};

const dangerBtn: React.CSSProperties = {
  ...btnBase,
  color: "var(--status-warn)",
  borderColor: "color-mix(in srgb, var(--status-warn) 40%, transparent)",
};

const inputStyle: React.CSSProperties = {
  height: 28,
  padding: "0 8px",
  fontSize: 11,
  fontFamily: "var(--font-mono)",
  color: "var(--text-primary)",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  outline: "none",
  width: "100%",
};

const labelStyle: React.CSSProperties = {
  fontFamily: "var(--font-mono)",
  fontSize: 9,
  letterSpacing: "0.12em",
  textTransform: "uppercase",
  color: "var(--text-faint)",
};

function ErrorLine({ children }: { children: React.ReactNode }) {
  return (
    <div
      className="font-mono"
      style={{
        border: "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
        background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
        color: "var(--status-warn)",
        padding: "8px 12px",
        fontSize: 11,
        borderRadius: 3,
      }}
    >
      {children}
    </div>
  );
}

function ModalFrame({
  open,
  onClose,
  title,
  children,
  width = 500,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
  width?: number;
}) {
  if (!open) return null;
  return (
    <div
      className="flex items-center justify-center"
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 60,
        background: "color-mix(in srgb, var(--surface-page) 80%, transparent)",
      }}
      onClick={onClose}
      role="presentation"
    >
      <div onClick={(e) => e.stopPropagation()} style={{ width, maxWidth: "94vw" }}>
        <WindowPanel
          title={title}
          tone="accent"
          actions={
            <button
              type="button"
              aria-label="Close"
              onClick={onClose}
              className="font-mono"
              style={{
                width: 20,
                height: 20,
                border: 0,
                background: "transparent",
                color: "var(--text-muted)",
                cursor: "pointer",
                fontSize: 13,
                lineHeight: 1,
              }}
            >
              {"\u2715"}
            </button>
          }
        >
          <div style={{ maxHeight: "70vh", overflowY: "auto" }}>{children}</div>
        </WindowPanel>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function providerTone(pt: ProviderType): string {
  if (pt === "microsoft") return "info";
  if (pt === "google") return "medium";
  return "muted";
}

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "--";
  return new Date(value).toLocaleString();
}

// ---------------------------------------------------------------------------
// Form state
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
  const scopes = form.scopes.split(",").map((s) => s.trim()).filter(Boolean);
  const body: CreateRequest = {
    provider_name: form.provider_name,
    provider_type: form.provider_type,
    client_id: form.client_id,
    client_secret: form.client_secret,
    is_enabled: form.is_enabled,
  };
  if (form.display_name) body.display_name = form.display_name;
  if (form.provider_type === "microsoft" && form.tenant_id) body.tenant_id = form.tenant_id;
  if (form.provider_type === "generic" && form.issuer_url) body.issuer_url = form.issuer_url;
  if (scopes.length > 0) body.scopes = scopes;
  return body;
}

function toUpdateRequest(form: ProviderFormState, original: OidcProvider): UpdateRequest {
  const scopes = form.scopes.split(",").map((s) => s.trim()).filter(Boolean);
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
    <div className="flex flex-col" style={{ gap: 10 }}>
      <div className="flex flex-col" style={{ gap: 4 }}>
        <label style={labelStyle} htmlFor="op-name">internal name</label>
        <input
          id="op-name"
          style={inputStyle}
          value={form.provider_name}
          onChange={(e) => setForm((f) => ({ ...f, provider_name: e.target.value }))}
          placeholder="acme-okta"
        />
      </div>
      <div className="flex flex-col" style={{ gap: 4 }}>
        <label style={labelStyle} htmlFor="op-type">provider type</label>
        <select
          id="op-type"
          style={inputStyle}
          value={form.provider_type}
          onChange={(e) => setForm((f) => ({ ...f, provider_type: e.target.value as ProviderType }))}
        >
          <option value="microsoft">Microsoft (Azure AD)</option>
          <option value="google">Google</option>
          <option value="generic">Generic OIDC</option>
        </select>
      </div>
      <div className="flex flex-col" style={{ gap: 4 }}>
        <label style={labelStyle} htmlFor="op-display">display name</label>
        <input
          id="op-display"
          style={inputStyle}
          value={form.display_name}
          onChange={(e) => setForm((f) => ({ ...f, display_name: e.target.value }))}
          placeholder="Sign in with Okta"
        />
      </div>
      {form.provider_type === "microsoft" && (
        <div className="flex flex-col" style={{ gap: 4 }}>
          <label style={labelStyle} htmlFor="op-tenant">tenant id</label>
          <input
            id="op-tenant"
            style={inputStyle}
            value={form.tenant_id}
            onChange={(e) => setForm((f) => ({ ...f, tenant_id: e.target.value }))}
            placeholder="00000000-0000-0000-0000-000000000000"
          />
        </div>
      )}
      {form.provider_type === "generic" && (
        <div className="flex flex-col" style={{ gap: 4 }}>
          <label style={labelStyle} htmlFor="op-issuer">issuer url</label>
          <input
            id="op-issuer"
            style={inputStyle}
            value={form.issuer_url}
            onChange={(e) => setForm((f) => ({ ...f, issuer_url: e.target.value }))}
            placeholder="https://idp.example.com/oidc"
          />
        </div>
      )}
      <div className="flex flex-col" style={{ gap: 4 }}>
        <label style={labelStyle} htmlFor="op-client-id">client id</label>
        <input
          id="op-client-id"
          style={inputStyle}
          value={form.client_id}
          onChange={(e) => setForm((f) => ({ ...f, client_id: e.target.value }))}
        />
      </div>
      <div className="flex flex-col" style={{ gap: 4 }}>
        <label style={labelStyle} htmlFor="op-client-secret">
          client secret (leave blank to keep)
        </label>
        <input
          id="op-client-secret"
          type="password"
          style={inputStyle}
          value={form.client_secret}
          onChange={(e) => setForm((f) => ({ ...f, client_secret: e.target.value }))}
        />
      </div>
      <div className="flex flex-col" style={{ gap: 4 }}>
        <label style={labelStyle} htmlFor="op-scopes">scopes (comma separated)</label>
        <input
          id="op-scopes"
          style={inputStyle}
          value={form.scopes}
          onChange={(e) => setForm((f) => ({ ...f, scopes: e.target.value }))}
        />
      </div>
      <label
        className="inline-flex items-center font-mono"
        style={{ gap: 8, fontSize: 11, color: "var(--text-primary)" }}
      >
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
// Create modal
// ---------------------------------------------------------------------------

function CreateProviderButton({
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
      <button type="button" style={primaryBtn} onClick={() => setOpen(true)}>
        {"\u002b"} Add provider
      </button>

      <ModalFrame open={open} onClose={handleClose} title="new oidc provider">
        <form className="flex flex-col" style={{ gap: 12 }} onSubmit={handleSubmit}>
          <ProviderFormFields form={form} setForm={setForm} />
          {error && <ErrorLine>{error}</ErrorLine>}
          <div className="flex" style={{ gap: 8, marginTop: 4 }}>
            <button
              type="submit"
              style={{ ...primaryBtn, flex: 1 }}
              disabled={isPending}
            >
              {isPending ? "Creating..." : "Create"}
            </button>
            <button type="button" style={btnBase} onClick={handleClose}>
              Cancel
            </button>
          </div>
        </form>
      </ModalFrame>
    </>
  );
}

// ---------------------------------------------------------------------------
// Edit modal
// ---------------------------------------------------------------------------

function EditProviderButton({
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
      <button type="button" style={btnBase} onClick={() => setOpen(true)}>
        Edit
      </button>

      <ModalFrame open={open} onClose={handleClose} title="edit oidc provider">
        <form className="flex flex-col" style={{ gap: 12 }} onSubmit={handleSubmit}>
          <ProviderFormFields form={form} setForm={setForm} />
          {error && <ErrorLine>{error}</ErrorLine>}
          <div className="flex" style={{ gap: 8, marginTop: 4 }}>
            <button
              type="submit"
              style={{ ...primaryBtn, flex: 1 }}
              disabled={isPending}
            >
              {isPending ? "Saving..." : "Save"}
            </button>
            <button type="button" style={btnBase} onClick={handleClose}>
              Cancel
            </button>
          </div>
        </form>
      </ModalFrame>
    </>
  );
}

// ---------------------------------------------------------------------------
// Delete modal
// ---------------------------------------------------------------------------

function DeleteProviderButton({
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
      <button type="button" style={dangerBtn} onClick={() => setOpen(true)}>
        Delete
      </button>

      <ModalFrame
        open={open}
        onClose={() => setOpen(false)}
        title="delete oidc provider"
        width={420}
      >
        <div className="flex flex-col" style={{ gap: 12 }}>
          <p className="font-mono" style={{ fontSize: 11, color: "var(--text-primary)" }}>
            Deleting{" "}
            <span style={{ color: "var(--accent)" }}>{provider.provider_name}</span>{" "}
            removes the provider and its stored client secret. Existing sessions
            are unaffected; new sign-ins via this provider will fail.
          </p>
          {error && <ErrorLine>{error}</ErrorLine>}
          <div className="flex" style={{ gap: 8 }}>
            <button
              type="button"
              style={{
                ...primaryBtn,
                flex: 1,
                background: "var(--status-warn)",
                borderColor: "var(--status-warn)",
              }}
              onClick={handleConfirm}
              disabled={isPending}
            >
              {isPending ? "Deleting..." : "Confirm delete"}
            </button>
            <button type="button" style={btnBase} onClick={() => setOpen(false)}>
              Cancel
            </button>
          </div>
        </div>
      </ModalFrame>
    </>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

type EnabledFilter = "all" | "enabled" | "disabled";

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

  const [enabledFilter, setEnabledFilter] = useState<EnabledFilter>("all");

  const { totalProviders, enabledProviders, byType } = useMemo(() => {
    const total = providers.length;
    const enabled = providers.filter((p) => p.is_enabled).length;
    const t: Record<string, number> = { microsoft: 0, google: 0, generic: 0 };
    for (const p of providers) t[p.provider_type] = (t[p.provider_type] ?? 0) + 1;
    return { totalProviders: total, enabledProviders: enabled, byType: t };
  }, [providers]);

  const filtered = useMemo(() => {
    return providers.filter((p) => {
      if (enabledFilter === "enabled" && !p.is_enabled) return false;
      if (enabledFilter === "disabled" && p.is_enabled) return false;
      return true;
    });
  }, [providers, enabledFilter]);

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <SectionHeader
        icon={"\u25ce"}
        title="oidc providers"
        actions={
          <CreateProviderButton
            onCreate={(req) => createMutation.mutateAsync(req)}
            isPending={createMutation.isPending}
          />
        }
      />

      {/* Metric strip */}
      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
        <WindowPanel title="providers">
          <span className="font-mono" style={{ fontSize: 26, color: "var(--accent)" }}>
            {totalProviders}
          </span>
        </WindowPanel>
        <WindowPanel title="enabled">
          <span className="font-mono" style={{ fontSize: 26, color: "var(--status-ok)" }}>
            {enabledProviders}
          </span>
        </WindowPanel>
        <WindowPanel title="by type">
          <div
            className="font-mono"
            style={{ fontSize: 10.5, color: "var(--text-primary)", lineHeight: 1.7 }}
          >
            microsoft {byType.microsoft ?? 0} · google {byType.google ?? 0} · generic {byType.generic ?? 0}
          </div>
        </WindowPanel>
      </div>

      {/* Filter row */}
      <div className="flex items-center flex-wrap" style={{ gap: 8 }}>
        <FilterChip
          active={enabledFilter === "all"}
          onClick={() => setEnabledFilter("all")}
        >
          ALL
        </FilterChip>
        <FilterChip
          active={enabledFilter === "enabled"}
          color="var(--status-ok)"
          onClick={() => setEnabledFilter("enabled")}
        >
          ENABLED
        </FilterChip>
        <FilterChip
          active={enabledFilter === "disabled"}
          color="var(--text-faint)"
          onClick={() => setEnabledFilter("disabled")}
        >
          DISABLED
        </FilterChip>
      </div>

      {providersQuery.isError && (
        <ErrorLine>
          Failed to load OIDC providers: {(providersQuery.error as Error).message}
        </ErrorLine>
      )}

      {providersQuery.isLoading ? (
        <WindowPanel title="providers" status="LOADING" tone="muted">
          <LoadingSkeletonGroup lines={6} />
        </WindowPanel>
      ) : providers.length === 0 ? (
        <WindowPanel title="providers" tone="muted">
          <div
            className="flex flex-col items-center"
            style={{ padding: "42px 12px", gap: 10 }}
          >
            <span
              className="font-mono"
              style={{ fontSize: 15, color: "var(--text-primary)", letterSpacing: "0.04em" }}
            >
              No OIDC providers configured
            </span>
            <span
              className="font-mono"
              style={{ fontSize: 11, color: "var(--text-muted)", textAlign: "center", maxWidth: 420 }}
            >
              Add a Microsoft, Google, or generic OIDC provider to enable single sign-on.
            </span>
          </div>
        </WindowPanel>
      ) : (
        <WindowPanel title="providers" flush>
          <DataGrid
            columns={[
              { label: "NAME", width: "1fr" },
              { label: "TYPE", width: "110px" },
              { label: "CLIENT ID", width: "1.4fr" },
              { label: "STATUS", width: "110px" },
              { label: "CREATED", width: "170px" },
              { label: "ACTIONS", width: "160px", align: "right" },
            ]}
            rows={filtered}
            getKey={(p) => p.id}
            renderCells={(p) => [
              <div key="n" className="flex flex-col">
                <span
                  className="font-mono"
                  style={{ fontSize: 11.5, color: "var(--text-primary)" }}
                >
                  {p.provider_name}
                </span>
                {p.display_name && (
                  <span
                    className="font-mono"
                    style={{ fontSize: 10, color: "var(--text-faint)" }}
                  >
                    {p.display_name}
                  </span>
                )}
              </div>,
              <MonoBadge key="t" tone={providerTone(p.provider_type)}>
                {p.provider_type}
              </MonoBadge>,
              <code
                key="c"
                className="font-mono truncate"
                style={{ fontSize: 10, color: "var(--text-muted)" }}
              >
                {p.client_id}
              </code>,
              p.is_enabled ? (
                <MonoBadge key="s" tone="ok">Enabled</MonoBadge>
              ) : (
                <MonoBadge key="s" tone="muted">Disabled</MonoBadge>
              ),
              <span
                key="cr"
                className="font-mono"
                style={{ fontSize: 10, color: "var(--text-faint)", whiteSpace: "nowrap" }}
              >
                {formatTimestamp(p.created_at)}
              </span>,
              <div key="a" className="flex" style={{ gap: 6, justifyContent: "flex-end" }}>
                <EditProviderButton
                  provider={p}
                  onUpdate={(id, req) => updateMutation.mutateAsync({ id, req })}
                  isPending={updateMutation.isPending}
                />
                <DeleteProviderButton
                  provider={p}
                  onDelete={(id) => deleteMutation.mutateAsync(id)}
                  isPending={deleteMutation.isPending}
                />
              </div>,
            ]}
          />
        </WindowPanel>
      )}
    </div>
  );
}
