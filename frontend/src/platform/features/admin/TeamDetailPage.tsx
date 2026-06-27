/**
 * TeamDetailPage -- admin-only team detail with member management (Phase 177).
 *
 * Shows a single team with full member list. Admins can:
 *  - Rename / update description.
 *  - Add members by user id with a role.
 *  - Remove members.
 *  - Delete the team (blocked if systems still reference it).
 */
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type ColumnDef } from "@tanstack/react-table";
import { useNavigate, useParams } from "react-router";
import { UserPlus } from "@phosphor-icons/react/dist/csr/UserPlus";
import { Trash } from "@phosphor-icons/react/dist/csr/Trash";
import { PencilSimple } from "@phosphor-icons/react/dist/csr/PencilSimple";
import { ArrowLeft } from "@phosphor-icons/react/dist/csr/ArrowLeft";

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
import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Team {
  id: string;
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
  member_count: number;
}

interface TeamMember {
  id: string;
  user_id: string;
  username: string;
  email: string | null;
  role: string;
  created_at: string;
}

interface TeamDetail {
  team: Team;
  members: TeamMember[];
}

interface DataEnvelope<T> {
  data: T;
  error: string | null;
  meta: Record<string, unknown>;
}

interface UpdateTeamRequest {
  name?: string;
  description?: string;
}

interface AddMemberRequest {
  user_id: string;
  role: "admin" | "operator" | "reader";
}

// ---------------------------------------------------------------------------
// Helpers
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
// Add member dialog
// ---------------------------------------------------------------------------

function AddMemberDialog({
  onAdd,
  isPending,
}: {
  onAdd: (req: AddMemberRequest) => Promise<unknown>;
  isPending: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [userId, setUserId] = useState("");
  const [role, setRole] = useState<AddMemberRequest["role"]>("operator");
  const [error, setError] = useState<string | null>(null);

  function handleClose() {
    setOpen(false);
    setTimeout(() => {
      setUserId("");
      setRole("operator");
      setError(null);
    }, 200);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await onAdd({ user_id: userId, role });
      handleClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add member");
    }
  }

  return (
    <>
      <Button size="sm" className="gap-1.5" onClick={() => setOpen(true)}>
        <UserPlus className="h-4 w-4" />
        Add member
      </Button>
      <Dialog open={open} onOpenChange={(v) => { if (!v) handleClose(); }}>
        <DialogContent className="sm:max-w-sm">
          <DialogHeader>
            <DialogTitle className="font-mono text-text">Add team member</DialogTitle>
          </DialogHeader>
          <form className="flex flex-col gap-4" onSubmit={handleSubmit}>
            <div className="flex flex-col gap-1">
              <label className="font-mono text-xs text-text-muted" htmlFor="am-user">
                User id *
              </label>
              <Input
                id="am-user"
                value={userId}
                onChange={(e) => setUserId(e.target.value)}
                placeholder="00000000-0000-0000-0000-000000000000"
                className="font-mono text-sm"
              />
            </div>
            <div className="flex flex-col gap-1">
              <label className="font-mono text-xs text-text-muted" htmlFor="am-role">
                Role *
              </label>
              <select
                id="am-role"
                value={role}
                onChange={(e) => setRole(e.target.value as AddMemberRequest["role"])}
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
                {isPending ? "Adding…" : "Add member"}
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
// Rename dialog
// ---------------------------------------------------------------------------

function RenameTeamDialog({
  team,
  onUpdate,
  isPending,
}: {
  team: Team;
  onUpdate: (req: UpdateTeamRequest) => Promise<unknown>;
  isPending: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState(team.name);
  const [description, setDescription] = useState(team.description);
  const [error, setError] = useState<string | null>(null);

  function handleClose() {
    setOpen(false);
    setTimeout(() => {
      setName(team.name);
      setDescription(team.description);
      setError(null);
    }, 200);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const diff: UpdateTeamRequest = {};
      if (name !== team.name) diff.name = name;
      if (description !== team.description) diff.description = description;
      if (Object.keys(diff).length === 0) {
        handleClose();
        return;
      }
      await onUpdate(diff);
      handleClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update team");
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
        <DialogContent className="sm:max-w-sm">
          <DialogHeader>
            <DialogTitle className="font-mono text-text">Edit team</DialogTitle>
          </DialogHeader>
          <form className="flex flex-col gap-4" onSubmit={handleSubmit}>
            <div className="flex flex-col gap-1">
              <label className="font-mono text-xs text-text-muted" htmlFor="rt-name">
                Name
              </label>
              <Input
                id="rt-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="font-mono text-sm"
              />
            </div>
            <div className="flex flex-col gap-1">
              <label className="font-mono text-xs text-text-muted" htmlFor="rt-desc">
                Description
              </label>
              <Input
                id="rt-desc"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className="font-mono text-sm"
              />
            </div>
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

function DeleteTeamDialog({
  team,
  onDelete,
  isPending,
}: {
  team: Team;
  onDelete: () => Promise<unknown>;
  isPending: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleConfirm() {
    setError(null);
    try {
      await onDelete();
      setOpen(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete team");
    }
  }

  return (
    <>
      <Button
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
            <DialogTitle className="font-mono text-text">Delete team</DialogTitle>
          </DialogHeader>
          <div className="flex flex-col gap-4">
            <div className="rounded-[4px] border border-destructive/40 bg-destructive/10 px-4 py-3">
              <p className="font-mono text-xs text-destructive font-semibold mb-1">
                This action is irreversible.
              </p>
              <p className="font-mono text-xs text-text-muted">
                Deleting <span className="text-text font-semibold">{team.name}</span>{" "}
                removes all memberships. Backend will reject if any managed
                systems still reference this team.
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
// Remove member button
// ---------------------------------------------------------------------------

function RemoveMemberButton({
  member,
  onRemove,
  isPending,
}: {
  member: TeamMember;
  onRemove: (userId: string) => Promise<unknown>;
  isPending: boolean;
}) {
  async function handleClick() {
    try {
      await onRemove(member.user_id);
    } catch {
      // Parent mutation displays errors via toast / query state.
    }
  }

  return (
    <Button
      type="button"
      size="sm"
      variant="outline"
      className="gap-1.5 text-destructive border-destructive/40 hover:bg-destructive/10 hover:border-destructive"
      disabled={isPending}
      onClick={handleClick}
    >
      <Trash className="h-3.5 w-3.5" />
      Remove
    </Button>
  );
}

// ---------------------------------------------------------------------------
// Columns
// ---------------------------------------------------------------------------

function buildMemberColumns(
  onRemove: (userId: string) => Promise<unknown>,
  isRemoving: boolean,
): ColumnDef<TeamMember>[] {
  return [
    {
      id: "username",
      header: "User",
      accessorKey: "username",
      cell: ({ row }) => (
        <div className="flex flex-col">
          <span className="font-mono text-sm text-text">{row.original.username}</span>
          {row.original.email && (
            <span className="font-mono text-xs text-text-muted">{row.original.email}</span>
          )}
        </div>
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
      id: "created_at",
      header: "Joined",
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
        <RemoveMemberButton
          member={row.original}
          onRemove={onRemove}
          isPending={isRemoving}
        />
      ),
    },
  ];
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function TeamDetailPage() {
  const { id: teamId = "" } = useParams<{ id: string }>();
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const detailQuery = useQuery({
    queryKey: ["platform", "admin-teams", teamId],
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<TeamDetail>>(`/admin/teams/${teamId}`),
    enabled: teamId.length > 0,
  });

  const updateMutation = useMutation({
    mutationFn: (req: UpdateTeamRequest) =>
      authorizedRequestJson<DataEnvelope<Team>>(`/admin/teams/${teamId}`, {
        method: "PUT",
        body: req,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "admin-teams"] });

  useUpdatePageHeader({
    title: detail?.team?.name,
    subtitle: detail?.team?.description || undefined,
    status: null,
  });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () =>
      authorizedRequestJson<DataEnvelope<{ deleted: string }>>(
        `/admin/teams/${teamId}`,
        { method: "DELETE" },
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "admin-teams"] });
      navigate("/admin/teams");
    },
  });

  const addMemberMutation = useMutation({
    mutationFn: (req: AddMemberRequest) =>
      authorizedRequestJson<DataEnvelope<TeamMember>>(
        `/admin/teams/${teamId}/members`,
        { method: "POST", body: req },
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "admin-teams", teamId] });
      void queryClient.invalidateQueries({ queryKey: ["platform", "admin-teams"] });
    },
  });

  const removeMemberMutation = useMutation({
    mutationFn: (userId: string) =>
      authorizedRequestJson<DataEnvelope<{ removed: string }>>(
        `/admin/teams/${teamId}/members/${userId}`,
        { method: "DELETE" },
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "admin-teams", teamId] });
      void queryClient.invalidateQueries({ queryKey: ["platform", "admin-teams"] });
    },
  });

  const detail = detailQuery.data?.data;
  const members = detail?.members ?? [];

  const columns = useMemo(
    () =>
      buildMemberColumns(
        (uid) => removeMemberMutation.mutateAsync(uid),
        removeMemberMutation.isPending,
      ),
    [removeMemberMutation],
  );

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      <div className="flex items-center gap-3">
        <Button
          type="button"
          size="sm"
          variant="outline"
          className="gap-1.5"
          onClick={() => navigate("/admin/teams")}
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          Back
        </Button>
      </div>

      {detailQuery.isLoading && (
        <AilaCard variant="default" padding="md" techBorder glow><LoadingSkeletonGroup lines={6} /></AilaCard>
      )}

      {detailQuery.isError && (
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-sm text-destructive">
          Failed to load team: {(detailQuery.error as Error).message}
        </div>
      )}

      {detail && (
        <>
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex gap-2">
              <RenameTeamDialog
                team={detail.team}
                onUpdate={(req) => updateMutation.mutateAsync(req)}
                isPending={updateMutation.isPending}
              />
              <DeleteTeamDialog
                team={detail.team}
                onDelete={() => deleteMutation.mutateAsync()}
                isPending={deleteMutation.isPending}
              />
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
              Members
            </p>
            <p className="font-mono text-2xl font-semibold text-text mt-1">
              {members.length}
            </p></AilaCard>
            <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
              Created
            </p>
            <p className="font-mono text-sm text-text mt-1">
              {formatTimestamp(detail.team.created_at)}
            </p></AilaCard>
            <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
              Updated
            </p>
            <p className="font-mono text-sm text-text mt-1">
              {formatTimestamp(detail.team.updated_at)}
            </p></AilaCard>
          </div>

          <div className="flex items-center justify-between">
            <h2 className="font-mono text-base font-semibold text-text">Members</h2>
            <AddMemberDialog
              onAdd={(req) => addMemberMutation.mutateAsync(req)}
              isPending={addMemberMutation.isPending}
            />
          </div>

          {members.length === 0 ? (
            <EmptyState
              icon={<UserPlus className="h-10 w-10" />}
              title="No members"
              description="Add a user to this team to grant access to team-scoped resources."
            />
          ) : (
            <AilaTable
              data={members}
              columns={columns}
              pageSize={25}
              enableSorting
              enableFiltering={false}
            >
              <AilaTable.Header />
              <AilaTable.Body emptyState="No members." />
              <AilaTable.Pagination pageSizeOptions={[10, 25, 50]} />
            </AilaTable>
          )}
        </>
      )}
    </div>
  );
}
