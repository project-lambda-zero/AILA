/**
 * UsersPage -- admin user management with invite and deactivate.
 *
 * ADM-03: Lists all user accounts. Admins can:
 * - Invite a new user (username, password, email, role) via a WindowPanel modal.
 * - Deactivate an active user via confirmation.
 *
 * Uses real backend: GET/POST/PATCH /users.
 * Presentation rebuilt to the AILA mock language (SectionHeader + WindowPanel
 * + DataGrid + MonoBadge + FilterChip). Data hooks, mutations, testids, and
 * handler wiring are unchanged.
 */
import * as React from "react";
import { useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";

import { SectionHeader, DataGrid, MonoBadge, FilterChip, StatBar } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { authorizedRequestJson } from "@platform/api/http";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface UserListItem {
  id: string;
  username: string;
  email: string | null;
  role: string;
  group_id: string | null;
  is_active: boolean;
  created_at: string;
  last_login_at: string | null;
}

interface UserListEnvelope {
  data: UserListItem[];
  meta: { total: number; offset: number; limit: number };
}

interface UserCreateRequest {
  username: string;
  password: string;
  email: string;
  role: "admin" | "operator" | "reader";
  group_id?: string;
}

interface UserCreateEnvelope {
  data: UserListItem;
}

interface UserUpdateEnvelope {
  data: UserListItem;
}

// ---------------------------------------------------------------------------
// Mock-language style primitives (local; kit is compose-only).
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
      <div
        onClick={(e) => e.stopPropagation()}
        style={{ width, maxWidth: "94vw" }}
      >
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
// Invite user modal
// ---------------------------------------------------------------------------

const DEFAULT_INVITE_FORM: UserCreateRequest = {
  username: "",
  password: "",
  email: "",
  role: "operator",
};

function InviteUserButton({
  onInvite,
  isPending,
}: {
  onInvite: (req: UserCreateRequest) => Promise<UserCreateEnvelope>;
  isPending: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<UserCreateRequest>(DEFAULT_INVITE_FORM);
  const [error, setError] = useState<string | null>(null);

  function handleClose() {
    setOpen(false);
    setTimeout(() => {
      setForm(DEFAULT_INVITE_FORM);
      setError(null);
    }, 200);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (form.username.length < 3) {
      setError("Username must be at least 3 characters.");
      return;
    }
    if (form.password.length < 8) {
      setError("Password must be at least 8 characters (NIST 800-63B).");
      return;
    }
    try {
      await onInvite(form);
      handleClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create user");
    }
  }

  return (
    <>
      <button type="button" style={primaryBtn} onClick={() => setOpen(true)}>
        {"\u002b"} Invite User
      </button>

      <ModalFrame open={open} onClose={handleClose} title="new user">
        <form className="flex flex-col" style={{ gap: 12 }} onSubmit={handleSubmit}>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={labelStyle} htmlFor="iu-username">username</label>
            <input
              id="iu-username"
              style={inputStyle}
              value={form.username}
              onChange={(e) => setForm((f) => ({ ...f, username: e.target.value }))}
              placeholder="jane.doe"
              autoComplete="off"
            />
          </div>

          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={labelStyle} htmlFor="iu-email">email</label>
            <input
              id="iu-email"
              type="email"
              style={inputStyle}
              value={form.email}
              onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))}
              placeholder="jane@example.com"
            />
          </div>

          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={labelStyle} htmlFor="iu-password">password</label>
            <input
              id="iu-password"
              type="password"
              style={inputStyle}
              value={form.password}
              onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))}
              placeholder="min 8 chars"
              autoComplete="new-password"
            />
            <p className="font-mono" style={{ fontSize: 9.5, color: "var(--text-faint)" }}>
              NIST 800-63B: min 8 chars, breach-checked.
            </p>
          </div>

          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={labelStyle} htmlFor="iu-role">role</label>
            <select
              id="iu-role"
              style={inputStyle}
              value={form.role}
              onChange={(e) =>
                setForm((f) => ({ ...f, role: e.target.value as UserCreateRequest["role"] }))
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
              {isPending ? "Creating..." : "Create Account"}
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
// Deactivate confirmation
// ---------------------------------------------------------------------------

function DeactivateButton({
  user,
  onDeactivate,
  isPending,
}: {
  user: UserListItem;
  onDeactivate: (userId: string) => Promise<UserUpdateEnvelope>;
  isPending: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleConfirm() {
    setError(null);
    try {
      await onDeactivate(user.id);
      setOpen(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to deactivate user");
    }
  }

  return (
    <>
      <button
        type="button"
        style={dangerBtn}
        disabled={!user.is_active}
        onClick={() => setOpen(true)}
      >
        Deactivate
      </button>

      <ModalFrame
        open={open}
        onClose={() => setOpen(false)}
        title="deactivate user"
        width={420}
      >
        <div className="flex flex-col" style={{ gap: 12 }}>
          <p className="font-mono" style={{ fontSize: 11, color: "var(--text-primary)" }}>
            User{" "}
            <span style={{ color: "var(--accent)" }}>{user.username}</span> will no
            longer be able to log in. The account can be reactivated later.
          </p>

          <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 8 }}>
            <div className="flex flex-col" style={{ gap: 3 }}>
              <span style={labelStyle}>role</span>
              <MonoBadge tone={roleTone(user.role)}>{user.role}</MonoBadge>
            </div>
            <div className="flex flex-col" style={{ gap: 3 }}>
              <span style={labelStyle}>email</span>
              <span className="font-mono" style={{ fontSize: 11, color: "var(--text-primary)" }}>
                {user.email || "--"}
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
              {isPending ? "Deactivating..." : "Confirm Deactivate"}
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

type RoleFilter = "all" | "admin" | "operator" | "reader";

export function UsersPage() {
  const queryClient = useQueryClient();

  const usersQuery = useQuery({
    queryKey: ["platform", "users"],
    queryFn: () =>
      authorizedRequestJson<UserListEnvelope>("/users?offset=0&limit=250"),
  });

  const createMutation = useMutation({
    mutationFn: (req: UserCreateRequest) =>
      authorizedRequestJson<UserCreateEnvelope>("/users", { method: "POST", body: req }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "users"] });
    },
  });

  const deactivateMutation = useMutation({
    mutationFn: (userId: string) =>
      authorizedRequestJson<UserUpdateEnvelope>(`/users/${userId}`, {
        method: "PATCH",
        body: { is_active: false },
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "users"] });
    },
  });

  const users = usersQuery.data?.data ?? [];

  const [roleFilter, setRoleFilter] = useState<RoleFilter>("all");
  const [activeOnly, setActiveOnly] = useState(false);

  const { totalUsers, activeUsers, inactiveUsers, byRole } = useMemo(() => {
    const total = users.length;
    const inactive = users.filter((u) => !u.is_active).length;
    const r = { admin: 0, operator: 0, reader: 0 } as Record<string, number>;
    for (const u of users) r[u.role] = (r[u.role] ?? 0) + 1;
    return {
      totalUsers: total,
      activeUsers: total - inactive,
      inactiveUsers: inactive,
      byRole: r,
    };
  }, [users]);

  const filtered = useMemo(() => {
    return users.filter((u) => {
      if (activeOnly && !u.is_active) return false;
      if (roleFilter !== "all" && u.role !== roleFilter) return false;
      return true;
    });
  }, [users, roleFilter, activeOnly]);

  const roleMax = Math.max(1, byRole.admin ?? 0, byRole.operator ?? 0, byRole.reader ?? 0);

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <SectionHeader
        icon={"\u25ce"}
        title="user directory"
        actions={
          <InviteUserButton
            onInvite={(req) => createMutation.mutateAsync(req)}
            isPending={createMutation.isPending}
          />
        }
      />

      {/* Metric strip */}
      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
        <WindowPanel title="totals">
          <div className="flex items-baseline" style={{ gap: 8 }}>
            <span className="font-mono" style={{ fontSize: 26, color: "var(--accent)" }}>
              {totalUsers}
            </span>
            <span className="font-mono" style={{ fontSize: 10, color: "var(--text-faint)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
              accounts
            </span>
          </div>
        </WindowPanel>
        <WindowPanel title="active">
          <div className="flex items-baseline" style={{ gap: 8 }}>
            <span className="font-mono" style={{ fontSize: 26, color: "var(--status-ok)" }}>
              {activeUsers}
            </span>
            <span className="font-mono" style={{ fontSize: 10, color: "var(--text-faint)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
              can sign in
            </span>
          </div>
        </WindowPanel>
        <WindowPanel title="role distribution">
          <div className="flex flex-col" style={{ gap: 6 }}>
            <StatBar label="ADMIN" color="var(--accent)" value={byRole.admin ?? 0} max={roleMax} />
            <StatBar label="OPERATOR" color="var(--status-info)" value={byRole.operator ?? 0} max={roleMax} />
            <StatBar label="READER" color="var(--status-ok)" value={byRole.reader ?? 0} max={roleMax} />
          </div>
        </WindowPanel>
      </div>

      {/* Filter row */}
      <div className="flex items-center flex-wrap" style={{ gap: 8 }}>
        <FilterChip active={roleFilter === "all"} onClick={() => setRoleFilter("all")}>
          ALL ({totalUsers})
        </FilterChip>
        <FilterChip
          active={roleFilter === "admin"}
          color="var(--accent)"
          onClick={() => setRoleFilter("admin")}
        >
          ADMIN ({byRole.admin ?? 0})
        </FilterChip>
        <FilterChip
          active={roleFilter === "operator"}
          color="var(--status-info)"
          onClick={() => setRoleFilter("operator")}
        >
          OPERATOR ({byRole.operator ?? 0})
        </FilterChip>
        <FilterChip
          active={roleFilter === "reader"}
          color="var(--status-ok)"
          onClick={() => setRoleFilter("reader")}
        >
          READER ({byRole.reader ?? 0})
        </FilterChip>
        <span style={{ flex: 1 }} />
        <FilterChip
          active={activeOnly}
          color="var(--status-ok)"
          onClick={() => setActiveOnly((v) => !v)}
        >
          ACTIVE ONLY
        </FilterChip>
        <span
          className="font-mono uppercase"
          style={{ fontSize: 9, letterSpacing: "0.12em", color: "var(--text-faint)" }}
        >
          {filtered.length} shown / {inactiveUsers} inactive
        </span>
      </div>

      {usersQuery.isError && (
        <ErrorLine>
          Failed to load users: {(usersQuery.error as Error).message}
        </ErrorLine>
      )}

      {usersQuery.isLoading ? (
        <WindowPanel title="users" status="LOADING" tone="muted">
          <LoadingSkeletonGroup lines={6} />
        </WindowPanel>
      ) : (
        <WindowPanel title="users" flush>
          <DataGrid
            columns={[
              { label: "USERNAME", width: "1fr" },
              { label: "EMAIL", width: "1.4fr" },
              { label: "ROLE", width: "100px" },
              { label: "STATUS", width: "90px" },
              { label: "CREATED", width: "160px" },
              { label: "LAST LOGIN", width: "160px" },
              { label: "ACTIONS", width: "130px", align: "right" },
            ]}
            rows={filtered}
            getKey={(u) => u.id}
            empty={
              <div
                className="font-mono"
                style={{
                  padding: 34,
                  textAlign: "center",
                  fontSize: 12,
                  color: "var(--text-muted)",
                }}
              >
                {users.length === 0
                  ? "no users. invite a user to get started."
                  : "no users match the current filters."}
              </div>
            }
            renderCells={(u) => [
              <span
                key="user"
                className="font-mono"
                style={{ fontSize: 11.5, color: "var(--text-primary)" }}
              >
                {u.username}
              </span>,
              <span
                key="email"
                className="font-mono truncate"
                style={{ fontSize: 10.5, color: "var(--text-muted)" }}
              >
                {u.email ?? "--"}
              </span>,
              <MonoBadge key="role" tone={roleTone(u.role)}>{u.role}</MonoBadge>,
              u.is_active ? (
                <MonoBadge key="s" tone="ok">Active</MonoBadge>
              ) : (
                <MonoBadge key="s" tone="muted">Inactive</MonoBadge>
              ),
              <span
                key="c"
                className="font-mono"
                style={{ fontSize: 10, color: "var(--text-faint)", whiteSpace: "nowrap" }}
              >
                {formatTimestamp(u.created_at)}
              </span>,
              <span
                key="l"
                className="font-mono"
                style={{ fontSize: 10, color: "var(--text-faint)", whiteSpace: "nowrap" }}
              >
                {formatTimestamp(u.last_login_at)}
              </span>,
              <DeactivateButton
                key="a"
                user={u}
                onDeactivate={(id) => deactivateMutation.mutateAsync(id)}
                isPending={deactivateMutation.isPending}
              />,
            ]}
          />
        </WindowPanel>
      )}
    </div>
  );
}
