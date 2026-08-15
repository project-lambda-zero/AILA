/**
 * ApiKeysPage -- admin API key management with create and revoke.
 *
 * ADM-02: Lists all API keys (including revoked history). Admins can:
 *  - Create a new key (label + role) -- raw key revealed once in a modal.
 *  - Revoke an active key via confirmation modal.
 *
 * Uses real backend: GET/POST/DELETE /auth/keys.
 * Presentation rebuilt to the AILA mock language. Data hooks, mutations,
 * and testids preserved.
 */
import * as React from "react";
import { useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";

import { SectionHeader, DataGrid, MonoBadge, FilterChip } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
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
  width = 460,
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
          {children}
        </WindowPanel>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function roleTone(role: string): string {
  if (role === "admin") return "critical";
  if (role === "operator") return "medium";
  return "muted";
}

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "--";
  return new Date(value).toLocaleString();
}

// ---------------------------------------------------------------------------
// Copy button
// ---------------------------------------------------------------------------

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // clipboard may be unavailable; swallow.
    }
  }

  return (
    <button type="button" style={btnBase} onClick={handleCopy}>
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Create key modal
// ---------------------------------------------------------------------------

const DEFAULT_CREATE_FORM: ApiKeyCreateRequest = {
  role: "reader",
  label: "",
};

function CreateKeyButton({
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
      <button type="button" style={primaryBtn} onClick={() => setOpen(true)}>
        {"\u002b"} Create API Key
      </button>

      <ModalFrame
        open={open}
        onClose={handleClose}
        title={createdKey ? "reveal key (one time)" : "new api key"}
      >
        {createdKey ? (
          <div className="flex flex-col" style={{ gap: 12 }}>
            <div
              className="font-mono"
              style={{
                border: "1px solid color-mix(in srgb, var(--accent) 45%, transparent)",
                background: "color-mix(in srgb, var(--accent) 10%, transparent)",
                color: "var(--accent)",
                padding: "8px 12px",
                fontSize: 11,
                borderRadius: 3,
              }}
            >
              copy this key now -- it will not be shown again.
            </div>

            <div className="flex flex-col" style={{ gap: 4 }}>
              <span style={labelStyle}>raw api key</span>
              <div className="flex items-center" style={{ gap: 8 }}>
                <code
                  className="font-mono"
                  style={{
                    flex: 1,
                    padding: "6px 8px",
                    fontSize: 11,
                    color: "var(--text-primary)",
                    background: "var(--surface-sunk)",
                    border: "1px solid var(--border-soft)",
                    borderRadius: 3,
                    wordBreak: "break-all",
                  }}
                >
                  {createdKey.raw_key}
                </code>
                <CopyButton value={createdKey.raw_key} />
              </div>
            </div>

            <div className="grid" style={{ gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
              <div className="flex flex-col" style={{ gap: 3 }}>
                <span style={labelStyle}>prefix</span>
                <span
                  className="font-mono"
                  style={{ fontSize: 11, color: "var(--text-primary)" }}
                >
                  {createdKey.key_prefix}
                </span>
              </div>
              <div className="flex flex-col" style={{ gap: 3 }}>
                <span style={labelStyle}>role</span>
                <MonoBadge tone={roleTone(createdKey.role)}>{createdKey.role}</MonoBadge>
              </div>
              <div className="flex flex-col" style={{ gap: 3 }}>
                <span style={labelStyle}>label</span>
                <span
                  className="font-mono"
                  style={{ fontSize: 11, color: "var(--text-primary)" }}
                >
                  {createdKey.label || "--"}
                </span>
              </div>
            </div>

            <button
              type="button"
              style={{ ...primaryBtn, width: "100%" }}
              onClick={handleClose}
            >
              Done
            </button>
          </div>
        ) : (
          <form className="flex flex-col" style={{ gap: 12 }} onSubmit={handleSubmit}>
            <div className="flex flex-col" style={{ gap: 4 }}>
              <label style={labelStyle} htmlFor="ck-label">label</label>
              <input
                id="ck-label"
                style={inputStyle}
                value={form.label}
                onChange={(e) => setForm((f) => ({ ...f, label: e.target.value }))}
                placeholder="CI deploy key"
              />
            </div>
            <div className="flex flex-col" style={{ gap: 4 }}>
              <label style={labelStyle} htmlFor="ck-role">role</label>
              <select
                id="ck-role"
                style={inputStyle}
                value={form.role}
                onChange={(e) =>
                  setForm((f) => ({ ...f, role: e.target.value as ApiKeyCreateRequest["role"] }))
                }
              >
                <option value="reader">reader</option>
                <option value="operator">operator</option>
                <option value="admin">admin</option>
              </select>
            </div>
            {error && <ErrorLine>{error}</ErrorLine>}
            <div className="flex" style={{ gap: 8, marginTop: 4 }}>
              <button
                type="submit"
                style={{ ...primaryBtn, flex: 1 }}
                disabled={isPending}
              >
                {isPending ? "Creating..." : "Create Key"}
              </button>
              <button type="button" style={btnBase} onClick={handleClose}>
                Cancel
              </button>
            </div>
          </form>
        )}
      </ModalFrame>
    </>
  );
}

// ---------------------------------------------------------------------------
// Revoke modal
// ---------------------------------------------------------------------------

function RevokeKeyButton({
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
      <button
        type="button"
        style={dangerBtn}
        disabled={keyItem.revoked_at !== null}
        onClick={() => setOpen(true)}
      >
        Revoke
      </button>

      <ModalFrame
        open={open}
        onClose={() => setOpen(false)}
        title="revoke api key"
        width={420}
      >
        <div className="flex flex-col" style={{ gap: 12 }}>
          <p className="font-mono" style={{ fontSize: 11, color: "var(--text-primary)" }}>
            Revoking key{" "}
            <span style={{ color: "var(--accent)" }}>{keyItem.key_prefix}</span>{" "}
            will immediately invalidate all JWTs issued for this key.
          </p>

          <div className="grid" style={{ gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
            <div className="flex flex-col" style={{ gap: 3 }}>
              <span style={labelStyle}>prefix</span>
              <span
                className="font-mono"
                style={{ fontSize: 11, color: "var(--text-primary)" }}
              >
                {keyItem.key_prefix}
              </span>
            </div>
            <div className="flex flex-col" style={{ gap: 3 }}>
              <span style={labelStyle}>role</span>
              <MonoBadge tone={roleTone(keyItem.role)}>{keyItem.role}</MonoBadge>
            </div>
            <div className="flex flex-col" style={{ gap: 3 }}>
              <span style={labelStyle}>label</span>
              <span
                className="font-mono"
                style={{ fontSize: 11, color: "var(--text-primary)" }}
              >
                {keyItem.label || "--"}
              </span>
            </div>
          </div>

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
              {isPending ? "Revoking..." : "Confirm Revoke"}
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

type StatusFilter = "all" | "active" | "revoked";

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

  const [status, setStatus] = useState<StatusFilter>("all");

  const { totalKeys, activeKeys, revokedKeys } = useMemo(() => {
    const total = keys.length;
    const revoked = keys.filter((k) => k.revoked_at !== null).length;
    return { totalKeys: total, activeKeys: total - revoked, revokedKeys: revoked };
  }, [keys]);

  const filtered = useMemo(() => {
    return keys.filter((k) => {
      const isRevoked = k.revoked_at !== null;
      if (status === "active" && isRevoked) return false;
      if (status === "revoked" && !isRevoked) return false;
      return true;
    });
  }, [keys, status]);

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <SectionHeader
        icon={"\u25ce"}
        title="api keys"
        actions={
          <CreateKeyButton
            onCreate={(req) => createMutation.mutateAsync(req)}
            isPending={createMutation.isPending}
          />
        }
      />

      {/* Metric strip */}
      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
        <WindowPanel title="total keys">
          <span className="font-mono" style={{ fontSize: 26, color: "var(--accent)" }}>
            {totalKeys}
          </span>
        </WindowPanel>
        <WindowPanel title="active">
          <span className="font-mono" style={{ fontSize: 26, color: "var(--status-ok)" }}>
            {activeKeys}
          </span>
        </WindowPanel>
        <WindowPanel title="revoked">
          <span className="font-mono" style={{ fontSize: 26, color: "var(--text-faint)" }}>
            {revokedKeys}
          </span>
        </WindowPanel>
      </div>

      {/* Filter row */}
      <div className="flex items-center flex-wrap" style={{ gap: 8 }}>
        <FilterChip active={status === "all"} onClick={() => setStatus("all")}>
          ALL ({totalKeys})
        </FilterChip>
        <FilterChip
          active={status === "active"}
          color="var(--status-ok)"
          onClick={() => setStatus("active")}
        >
          ACTIVE ({activeKeys})
        </FilterChip>
        <FilterChip
          active={status === "revoked"}
          color="var(--text-faint)"
          onClick={() => setStatus("revoked")}
        >
          REVOKED ({revokedKeys})
        </FilterChip>
      </div>

      {keysQuery.isError && (
        <ErrorLine>
          Failed to load API keys: {(keysQuery.error as Error).message}
        </ErrorLine>
      )}

      {keysQuery.isLoading ? (
        <WindowPanel title="keys" status="LOADING" tone="muted">
          <LoadingSkeletonGroup lines={6} />
        </WindowPanel>
      ) : keys.length === 0 ? (
        <WindowPanel title="keys" tone="muted">
          <div
            className="flex flex-col items-center"
            style={{ padding: "42px 12px", gap: 10 }}
          >
            <span
              className="font-mono"
              style={{ fontSize: 15, color: "var(--text-primary)", letterSpacing: "0.04em" }}
            >
              No API keys
            </span>
            <span
              className="font-mono"
              style={{ fontSize: 11, color: "var(--text-muted)", textAlign: "center", maxWidth: 420 }}
            >
              Create an API key to allow programmatic access to the platform.
            </span>
          </div>
        </WindowPanel>
      ) : (
        <WindowPanel title="keys" flush>
          <DataGrid
            columns={[
              { label: "LABEL", width: "1fr" },
              { label: "PREFIX", width: "140px" },
              { label: "OWNER", width: "160px" },
              { label: "ROLE", width: "100px" },
              { label: "CREATED", width: "170px" },
              { label: "STATUS", width: "110px" },
              { label: "ACTIONS", width: "110px", align: "right" },
            ]}
            rows={filtered}
            getKey={(k) => k.key_id}
            renderCells={(k) => [
              <span
                key="l"
                className="font-mono"
                style={{ fontSize: 11.5, color: "var(--text-primary)" }}
              >
                {k.label || "--"}
              </span>,
              <code
                key="p"
                className="font-mono"
                style={{ fontSize: 10.5, color: "var(--accent)" }}
              >
                {k.key_prefix}
              </code>,
              <span
                key="o"
                className="font-mono truncate"
                style={{ fontSize: 10, color: "var(--text-muted)" }}
              >
                {k.created_by}
              </span>,
              <MonoBadge key="r" tone={roleTone(k.role)}>{k.role}</MonoBadge>,
              <span
                key="c"
                className="font-mono"
                style={{ fontSize: 10, color: "var(--text-faint)", whiteSpace: "nowrap" }}
              >
                {formatTimestamp(k.created_at)}
              </span>,
              k.revoked_at ? (
                <MonoBadge key="s" tone="muted">Revoked</MonoBadge>
              ) : (
                <MonoBadge key="s" tone="ok">Active</MonoBadge>
              ),
              <RevokeKeyButton
                key="a"
                keyItem={k}
                onRevoke={(id) => revokeMutation.mutateAsync(id)}
                isPending={revokeMutation.isPending}
              />,
            ]}
          />
        </WindowPanel>
      )}
    </div>
  );
}
