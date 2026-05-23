/**
 * TeamsPage — admin-only multi-team management (Phase 177).
 *
 * Lists all teams with member counts. Admins can create new teams and
 * click a row to navigate to the team detail page. Uses the
 * /admin/teams endpoints.
 */
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type ColumnDef } from "@tanstack/react-table";
import { UsersThree, Plus } from "@phosphor-icons/react";
import { useNavigate } from "react-router";

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

interface Team {
  id: string;
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
  member_count: number;
}

interface CrossTeamStatsRow {
  team_id: string;
  team_name: string;
  systems_count: number;
  runs_count: number;
  members_count: number;
}

interface DataEnvelope<T> {
  data: T;
  error: string | null;
  meta: Record<string, unknown>;
}

interface CreateTeamRequest {
  name: string;
  description: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

// ---------------------------------------------------------------------------
// Create dialog
// ---------------------------------------------------------------------------

function CreateTeamDialog({
  onCreate,
  isPending,
}: {
  onCreate: (req: CreateTeamRequest) => Promise<unknown>;
  isPending: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState<string | null>(null);

  function handleClose() {
    setOpen(false);
    setTimeout(() => {
      setName("");
      setDescription("");
      setError(null);
    }, 200);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await onCreate({ name, description });
      handleClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create team");
    }
  }

  return (
    <>
      <Button size="sm" className="gap-1.5" onClick={() => setOpen(true)}>
        <Plus className="h-4 w-4" />
        Create team
      </Button>
      <Dialog open={open} onOpenChange={(v) => { if (!v) handleClose(); }}>
        <DialogContent className="sm:max-w-sm">
          <DialogHeader>
            <DialogTitle className="font-mono text-text">Create team</DialogTitle>
          </DialogHeader>
          <form className="flex flex-col gap-4" onSubmit={handleSubmit}>
            <div className="flex flex-col gap-1">
              <label className="font-mono text-xs text-text-muted" htmlFor="ct-name">
                Name *
              </label>
              <Input
                id="ct-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="security-red"
                className="font-mono text-sm"
              />
            </div>
            <div className="flex flex-col gap-1">
              <label className="font-mono text-xs text-text-muted" htmlFor="ct-desc">
                Description
              </label>
              <Input
                id="ct-desc"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Red team operations"
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
// Columns
// ---------------------------------------------------------------------------

function buildColumns(): ColumnDef<Team>[] {
  return [
    {
      id: "name",
      header: "Name",
      accessorKey: "name",
      cell: ({ getValue }) => (
        <span className="font-mono text-sm text-text">{String(getValue())}</span>
      ),
    },
    {
      id: "description",
      header: "Description",
      accessorKey: "description",
      cell: ({ getValue }) => (
        <span className="font-mono text-xs text-text-muted">
          {String(getValue() || "—")}
        </span>
      ),
    },
    {
      id: "member_count",
      header: "Members",
      accessorKey: "member_count",
      cell: ({ getValue }) => (
        <AilaBadge severity="info" size="sm">{String(getValue())}</AilaBadge>
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
  ];
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function TeamsPage() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const teamsQuery = useQuery({
    queryKey: ["platform", "admin-teams"],
    queryFn: () => authorizedRequestJson<DataEnvelope<Team[]>>("/admin/teams"),
  });

  const crossQuery = useQuery({
    queryKey: ["platform", "admin-teams", "cross-view"],
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<CrossTeamStatsRow[]>>(
        "/admin/teams/cross-view",
      ),
  });

  const createMutation = useMutation({
    mutationFn: (req: CreateTeamRequest) =>
      authorizedRequestJson<DataEnvelope<Team>>("/admin/teams", {
        method: "POST",
        body: req,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "admin-teams"] });
    },
  });

  const teams = teamsQuery.data?.data ?? [];
  const crossRows = crossQuery.data?.data ?? [];
  const columns = useMemo(() => buildColumns(), []);

  const { totalMembers, totalSystems, totalRuns } = useMemo(() => {
    const members = crossRows.reduce((s, r) => s + r.members_count, 0);
    const systems = crossRows.reduce((s, r) => s + r.systems_count, 0);
    const runs = crossRows.reduce((s, r) => s + r.runs_count, 0);
    return { totalMembers: members, totalSystems: systems, totalRuns: runs };
  }, [crossRows]);

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <CreateTeamDialog
          onCreate={(req) => createMutation.mutateAsync(req)}
          isPending={createMutation.isPending}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-4">
        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Teams
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {teamsQuery.isLoading ? "—" : teams.length}
        </p></AilaCard>
        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Members
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {crossQuery.isLoading ? "—" : totalMembers}
        </p></AilaCard>
        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Systems
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {crossQuery.isLoading ? "—" : totalSystems}
        </p></AilaCard>
        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Workflow runs
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {crossQuery.isLoading ? "—" : totalRuns}
        </p></AilaCard>
      </div>

      {teamsQuery.isError && (
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-sm text-destructive">
          Failed to load teams: {(teamsQuery.error as Error).message}
        </div>
      )}

      {teamsQuery.isLoading && (
        <AilaCard variant="default" padding="md" techBorder glow><LoadingSkeletonGroup lines={6} /></AilaCard>
      )}

      {!teamsQuery.isLoading && !teamsQuery.isError && teams.length === 0 && (
        <EmptyState
          icon={<UsersThree className="h-10 w-10" />}
          title="No teams yet"
          description="Create a team to organize members and isolate resources."
        />
      )}

      {!teamsQuery.isLoading && teams.length > 0 && (
        <AilaTable
          data={teams}
          columns={columns}
          pageSize={25}
          enableSorting
          enableFiltering={false}
          onRowClick={(row) => navigate(`/admin/teams/${row.original.id}`)}
        >
          <AilaTable.Header />
          <AilaTable.Body emptyState="No teams found." />
          <AilaTable.Pagination pageSizeOptions={[10, 25, 50]} />
        </AilaTable>
      )}
    </div>
  );
}
