/**
 * UsersPage -- admin user management with invite and deactivate.
 *
 * ADM-03: Lists all user accounts. Admins can:
 * - Invite a new user (username, password, email, role) via Dialog.
 * - Deactivate an active user via confirmation Dialog.
 *
 * Uses real backend: GET/POST/PATCH /users.
 * No mock data -- is_active determines user status.
 */
import { useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { type ColumnDef } from "@tanstack/react-table";
import { Users, UserPlus } from "@phosphor-icons/react";

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
// Utilities
// ---------------------------------------------------------------------------

function roleSeverity(role: string): "critical" | "medium" | "neutral" {
  if (role === "admin") return "critical";
  if (role === "operator") return "medium";
  return "neutral";
}

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "--";
  return new Date(value).toLocaleString();
}

// ---------------------------------------------------------------------------
// Invite user dialog
// ---------------------------------------------------------------------------

const DEFAULT_INVITE_FORM: UserCreateRequest = {
  username: "",
  password: "",
  email: "",
  role: "operator",
};

function InviteUserDialog({
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
      <Button size="sm" className="gap-1.5" onClick={() => setOpen(true)}>
        <UserPlus className="h-4 w-4" />
        Invite User
      </Button>

      <Dialog open={open} onOpenChange={(v) => { if (!v) handleClose(); }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="font-mono text-text">
              Invite User
            </DialogTitle>
          </DialogHeader>

          <form className="flex flex-col gap-4" onSubmit={handleSubmit}>
            <div className="flex flex-col gap-1">
              <label className="font-mono text-xs text-text-muted" htmlFor="iu-username">
                Username
              </label>
              <Input
                id="iu-username"
                value={form.username}
                onChange={(e) => setForm((f) => ({ ...f, username: e.target.value }))}
                placeholder="jane.doe"
                className="font-mono text-sm"
                autoComplete="off"
              />
            </div>

            <div className="flex flex-col gap-1">
              <label className="font-mono text-xs text-text-muted" htmlFor="iu-email">
                Email
              </label>
              <Input
                id="iu-email"
                type="email"
                value={form.email}
                onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))}
                placeholder="jane@example.com"
                className="font-mono text-sm"
              />
            </div>

            <div className="flex flex-col gap-1">
              <label className="font-mono text-xs text-text-muted" htmlFor="iu-password">
                Password
              </label>
              <Input
                id="iu-password"
                type="password"
                value={form.password}
                onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))}
                placeholder="Min 8 characters"
                className="font-mono text-sm"
                autoComplete="new-password"
              />
              <p className="font-mono text-[10px] text-text-muted">
                NIST 800-63B: min 8 chars, checked against breach databases.
              </p>
            </div>

            <div className="flex flex-col gap-1">
              <label className="font-mono text-xs text-text-muted" htmlFor="iu-role">
                Role
              </label>
              <select
                id="iu-role"
                value={form.role}
                onChange={(e) =>
                  setForm((f) => ({
                    ...f,
                    role: e.target.value as UserCreateRequest["role"],
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
                {isPending ? "Creating..." : "Create Account"}
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
        </DialogContent>
      </Dialog>
    </>
  );
}

// ---------------------------------------------------------------------------
// Deactivate confirmation dialog
// ---------------------------------------------------------------------------

function DeactivateUserDialog({
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
      <Button
        size="sm"
        variant="outline"
        className="text-destructive border-destructive/40 hover:bg-destructive/10 hover:border-destructive"
        disabled={!user.is_active}
        onClick={() => setOpen(true)}
      >
        Deactivate
      </Button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-sm">
          <DialogHeader>
            <DialogTitle className="font-mono text-text">Deactivate User</DialogTitle>
          </DialogHeader>

          <div className="flex flex-col gap-4">
            <div className="rounded-[4px] border border-destructive/40 bg-destructive/10 px-4 py-3">
              <p className="font-mono text-xs text-destructive font-semibold mb-1">
                This will soft-delete the user account.
              </p>
              <p className="font-mono text-xs text-text-muted">
                User <span className="text-text font-semibold">{user.username}</span>
                {" "}will no longer be able to log in. The account can be reactivated later.
              </p>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div className="flex flex-col gap-0.5">
                <p className="font-mono text-xs text-text-muted">Username</p>
                <p className="font-mono text-xs text-text">{user.username}</p>
              </div>
              <div className="flex flex-col gap-0.5">
                <p className="font-mono text-xs text-text-muted">Role</p>
                <AilaBadge severity={roleSeverity(user.role)} size="sm">
                  {user.role}
                </AilaBadge>
              </div>
              <div className="flex flex-col gap-0.5">
                <p className="font-mono text-xs text-text-muted">Email</p>
                <p className="font-mono text-xs text-text">{user.email || "--"}</p>
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
                {isPending ? "Deactivating..." : "Confirm Deactivate"}
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
// Column definitions
// ---------------------------------------------------------------------------

function buildColumns(
  onDeactivate: (userId: string) => Promise<UserUpdateEnvelope>,
  isDeactivatePending: boolean,
): ColumnDef<UserListItem>[] {
  return [
    {
      id: "username",
      header: "Username",
      accessorKey: "username",
      cell: ({ getValue }) => (
        <span className="font-mono text-xs font-medium text-text">{String(getValue())}</span>
      ),
    },
    {
      id: "email",
      header: "Email",
      accessorKey: "email",
      cell: ({ getValue }) => (
        <span className="font-mono text-xs text-text-muted">{String(getValue() ?? "--")}</span>
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
      id: "status",
      header: "Status",
      accessorKey: "is_active",
      cell: ({ getValue }) => {
        const active = getValue() as boolean;
        return active ? (
          <AilaBadge severity="info" size="sm">Active</AilaBadge>
        ) : (
          <AilaBadge severity="neutral" size="sm">Inactive</AilaBadge>
        );
      },
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
      id: "last_login_at",
      header: "Last Login",
      accessorKey: "last_login_at",
      cell: ({ getValue }) => (
        <span className="font-mono text-xs text-text-muted whitespace-nowrap">
          {formatTimestamp(getValue() as string | null)}
        </span>
      ),
    },
    {
      id: "actions",
      header: "Actions",
      enableSorting: false,
      cell: ({ row }) => (
        <DeactivateUserDialog
          user={row.original}
          onDeactivate={onDeactivate}
          isPending={isDeactivatePending}
        />
      ),
    },
  ];
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function UsersPage() {
  const queryClient = useQueryClient();

  const usersQuery = useQuery({
    queryKey: ["platform", "users"],
    queryFn: () =>
      authorizedRequestJson<UserListEnvelope>("/users?offset=0&limit=250"),
  });

  const createMutation = useMutation({
    mutationFn: (req: UserCreateRequest) =>
      authorizedRequestJson<UserCreateEnvelope>("/users", {
        method: "POST",
        body: req,
      }),
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

  const { totalUsers, activeUsers, inactiveUsers } = useMemo(() => {
    const total = users.length;
    const inactive = users.filter((u) => !u.is_active).length;
    return { totalUsers: total, activeUsers: total - inactive, inactiveUsers: inactive };
  }, [users]);

  const columns = buildColumns(
    (userId) => deactivateMutation.mutateAsync(userId),
    deactivateMutation.isPending,
  );

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      {/* Page header */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="font-mono text-xl font-semibold text-text flex items-center gap-2">
            <Users className="h-5 w-5 text-accent" />
            Users
          </h1>
          <p className="font-mono text-sm text-text-muted mt-0.5">
            Manage platform user accounts. Admin-invite only registration.
          </p>
        </div>

        <InviteUserDialog
          onInvite={(req) => createMutation.mutateAsync(req)}
          isPending={createMutation.isPending}
        />
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Total Users
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {usersQuery.isLoading ? "--" : totalUsers}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">All accounts</p></AilaCard>

        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Active Users
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {usersQuery.isLoading ? "--" : activeUsers}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">
          Can log in
        </p></AilaCard>

        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Inactive Users
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {usersQuery.isLoading ? "--" : inactiveUsers}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">
          Deactivated
        </p></AilaCard>
      </div>

      {/* Error banner */}
      {usersQuery.isError && (
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-sm text-destructive">
          Failed to load users: {(usersQuery.error as Error).message}
        </div>
      )}

      {/* Loading skeleton */}
      {usersQuery.isLoading && (
        <AilaCard variant="default" padding="md" techBorder glow><LoadingSkeletonGroup lines={6} /></AilaCard>
      )}

      {/* Empty state */}
      {!usersQuery.isLoading && !usersQuery.isError && users.length === 0 && (
        <EmptyState
          icon={<Users className="h-10 w-10" />}
          title="No users"
          description="Invite a user to get started with the platform."
        />
      )}

      {/* Users table */}
      {!usersQuery.isLoading && users.length > 0 && (
        <AilaTable
          data={users}
          columns={columns}
          pageSize={25}
          enableSorting
          enableFiltering={false}
        >
          <AilaTable.Header />
          <AilaTable.Body emptyState="No users found." />
          <AilaTable.Pagination pageSizeOptions={[10, 25, 50]} />
        </AilaTable>
      )}
    </div>
  );
}
