/**
 * AutomationPage — manage cron-driven automation schedules.
 *
 * AUTO-04 / AUTO-05: team-scoped CRUD over the platform AutomationRegistry.
 * Operators pick a registered action, give it a target system + cron, and the
 * worker fires it on the schedule.
 *
 * Endpoints:
 *   GET    /automation/schedules
 *   POST   /automation/schedules
 *   PATCH  /automation/schedules/{id}
 *   DELETE /automation/schedules/{id}
 *   GET    /automation/actions
 */
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type ColumnDef } from "@tanstack/react-table";
import { Robot } from "@phosphor-icons/react/dist/csr/Robot";
import { Plus } from "@phosphor-icons/react/dist/csr/Plus";
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
// Types — mirror src/aila/api/schemas/automation.py
// ---------------------------------------------------------------------------

interface AutomationSchedule {
  id: string;
  action_id: string;
  target_name: string;
  cron_expression: string;
  action_kwargs: Record<string, unknown>;
  enabled: boolean;
  team_id: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
  last_run_at: string | null;
  last_run_result: string | null;
}

interface AutomationAction {
  action_id: string;
  description: string;
  module_id: string;
}

interface AutomationScheduleCreate {
  action_id: string;
  target_name: string;
  cron_expression: string;
  action_kwargs?: Record<string, unknown> | null;
  enabled: boolean;
}

interface AutomationScheduleUpdate {
  cron_expression?: string;
  action_kwargs?: Record<string, unknown>;
  enabled?: boolean;
}

interface DataEnvelope<T> {
  data: T;
  error: string | null;
  meta: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

const DEFAULT_CREATE: AutomationScheduleCreate = {
  action_id: "",
  target_name: "",
  cron_expression: "0 9 * * MON",
  enabled: true,
};

// ---------------------------------------------------------------------------
// Create dialog
// ---------------------------------------------------------------------------

function CreateScheduleDialog({
  actions,
  onCreate,
  isPending,
}: {
  actions: AutomationAction[];
  onCreate: (req: AutomationScheduleCreate) => Promise<unknown>;
  isPending: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<AutomationScheduleCreate>(DEFAULT_CREATE);
  const [error, setError] = useState<string | null>(null);

  function handleClose() {
    setOpen(false);
    setTimeout(() => {
      setForm(DEFAULT_CREATE);
      setError(null);
    }, 200);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!form.action_id) {
      setError("Select an action");
      return;
    }
    if (!form.target_name) {
      setError("Target system is required");
      return;
    }
    try {
      await onCreate(form);
      handleClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create schedule");
    }
  }

  return (
    <>
      <Button
        size="sm"
        className="gap-1.5"
        onClick={() => setOpen(true)}
        disabled={actions.length === 0}
      >
        <Plus className="h-4 w-4" />
        New schedule
      </Button>
      <Dialog open={open} onOpenChange={(v) => { if (!v) handleClose(); }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="font-mono text-text">
              New automation schedule
            </DialogTitle>
          </DialogHeader>
          <form className="flex flex-col gap-4" onSubmit={handleSubmit}>
            <div className="flex flex-col gap-1">
              <label className="font-mono text-xs text-text-muted" htmlFor="ns-action">
                Action *
              </label>
              <select
                id="ns-action"
                value={form.action_id}
                onChange={(e) => setForm((f) => ({ ...f, action_id: e.target.value }))}
                className="rounded-[2px] border border-border bg-base font-mono text-sm text-text px-2.5 py-1.5 outline-none focus:border-border-hover transition-colors duration-100"
              >
                <option value="">— select an action —</option>
                {actions.map((a) => (
                  <option key={a.action_id} value={a.action_id}>
                    {a.action_id} ({a.module_id})
                  </option>
                ))}
              </select>
              {form.action_id && (
                <span className="font-mono text-xs text-text-muted">
                  {actions.find((a) => a.action_id === form.action_id)?.description ?? ""}
                </span>
              )}
            </div>

            <div className="flex flex-col gap-1">
              <label className="font-mono text-xs text-text-muted" htmlFor="ns-target">
                Target system *
              </label>
              <Input
                id="ns-target"
                value={form.target_name}
                onChange={(e) => setForm((f) => ({ ...f, target_name: e.target.value }))}
                placeholder="prod-vm-01"
                className="font-mono text-sm"
              />
            </div>

            <div className="flex flex-col gap-1">
              <label className="font-mono text-xs text-text-muted" htmlFor="ns-cron">
                Cron expression *
              </label>
              <Input
                id="ns-cron"
                value={form.cron_expression}
                onChange={(e) => setForm((f) => ({ ...f, cron_expression: e.target.value }))}
                placeholder="0 9 * * MON"
                className="font-mono text-sm"
              />
              <span className="font-mono text-xs text-text-muted">
                e.g. <code>0 9 * * MON</code> = every Monday at 09:00 UTC
              </span>
            </div>

            <label className="flex items-center gap-2 font-mono text-xs text-text-muted">
              <input
                type="checkbox"
                checked={form.enabled}
                onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))}
              />
              Enabled
            </label>

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
// Row actions — toggle enabled + delete
// ---------------------------------------------------------------------------

function RowActions({
  schedule,
  onToggle,
  onDelete,
}: {
  schedule: AutomationSchedule;
  onToggle: (id: string, enabled: boolean) => Promise<unknown>;
  onDelete: (id: string) => Promise<unknown>;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleToggle() {
    setError(null);
    setBusy(true);
    try {
      await onToggle(schedule.id, !schedule.enabled);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update");
    } finally {
      setBusy(false);
    }
  }

  async function handleDelete() {
    setError(null);
    setBusy(true);
    try {
      await onDelete(schedule.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete");
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col items-end gap-1">
      <div className="flex gap-2">
        <Button
          size="sm"
          variant="outline"
          disabled={busy}
          onClick={handleToggle}
        >
          {schedule.enabled ? "Disable" : "Enable"}
        </Button>
        <Button
          size="sm"
          variant="outline"
          className="text-destructive border-destructive/40 hover:bg-destructive/10 hover:border-destructive gap-1.5"
          disabled={busy}
          onClick={handleDelete}
        >
          <Trash className="h-3.5 w-3.5" />
          Delete
        </Button>
      </div>
      {error && (
        <span className="font-mono text-xs text-destructive">{error}</span>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Columns
// ---------------------------------------------------------------------------

function buildColumns(
  onToggle: (id: string, enabled: boolean) => Promise<unknown>,
  onDelete: (id: string) => Promise<unknown>,
): ColumnDef<AutomationSchedule>[] {
  return [
    {
      id: "action_id",
      header: "Action",
      accessorKey: "action_id",
      cell: ({ getValue }) => (
        <span className="font-mono text-sm text-text">{String(getValue())}</span>
      ),
    },
    {
      id: "target_name",
      header: "Target",
      accessorKey: "target_name",
      cell: ({ getValue }) => (
        <span className="font-mono text-xs text-text-muted">{String(getValue())}</span>
      ),
    },
    {
      id: "cron_expression",
      header: "Cron",
      accessorKey: "cron_expression",
      cell: ({ getValue }) => (
        <code className="font-mono text-xs text-text">{String(getValue())}</code>
      ),
    },
    {
      id: "enabled",
      header: "Status",
      accessorKey: "enabled",
      cell: ({ getValue }) =>
        getValue() ? (
          <AilaBadge severity="info" size="sm">Enabled</AilaBadge>
        ) : (
          <AilaBadge severity="neutral" size="sm">Disabled</AilaBadge>
        ),
    },
    {
      id: "last_run_at",
      header: "Last run",
      accessorKey: "last_run_at",
      cell: ({ getValue }) => (
        <span className="font-mono text-xs text-text-muted whitespace-nowrap">
          {formatTimestamp(getValue() as string | null)}
        </span>
      ),
    },
    {
      id: "last_run_result",
      header: "Result",
      accessorKey: "last_run_result",
      enableSorting: false,
      cell: ({ getValue }) => {
        const v = getValue() as string | null;
        if (!v) return <span className="font-mono text-xs text-text-muted">—</span>;
        return (
          <span
            className="font-mono text-xs text-text-muted line-clamp-1 max-w-[180px]"
            title={v}
          >
            {v}
          </span>
        );
      },
    },
    {
      id: "actions",
      header: "Actions",
      enableSorting: false,
      cell: ({ row }) => (
        <RowActions
          schedule={row.original}
          onToggle={onToggle}
          onDelete={onDelete}
        />
      ),
    },
  ];
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function AutomationPage() {
  const queryClient = useQueryClient();

  const schedulesQuery = useQuery({
    queryKey: ["platform", "automation-schedules"],
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<AutomationSchedule[]>>(
        "/automation/schedules",
      ),
  });

  const actionsQuery = useQuery({
    queryKey: ["platform", "automation-actions"],
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<AutomationAction[]>>(
        "/automation/actions",
      ),
  });

  const createMutation = useMutation({
    mutationFn: (req: AutomationScheduleCreate) =>
      authorizedRequestJson<DataEnvelope<AutomationSchedule>>(
        "/automation/schedules",
        { method: "POST", body: req },
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["platform", "automation-schedules"],
      });
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({
      id,
      patch,
    }: {
      id: string;
      patch: AutomationScheduleUpdate;
    }) =>
      authorizedRequestJson<DataEnvelope<AutomationSchedule>>(
        `/automation/schedules/${encodeURIComponent(id)}`,
        { method: "PATCH", body: patch },
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["platform", "automation-schedules"],
      });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      authorizedRequestJson<void>(
        `/automation/schedules/${encodeURIComponent(id)}`,
        { method: "DELETE" },
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["platform", "automation-schedules"],
      });
    },
  });

  const schedules = schedulesQuery.data?.data ?? [];
  const actions = actionsQuery.data?.data ?? [];

  const enabledCount = useMemo(
    () => schedules.filter((s) => s.enabled).length,
    [schedules],
  );

  const columns = useMemo(
    () =>
      buildColumns(
        (id, enabled) => updateMutation.mutateAsync({ id, patch: { enabled } }),
        (id) => deleteMutation.mutateAsync(id),
      ),
    [updateMutation, deleteMutation],
  );

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <CreateScheduleDialog
          actions={actions}
          onCreate={(req) => createMutation.mutateAsync(req)}
          isPending={createMutation.isPending}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Total Schedules
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {schedulesQuery.isLoading ? "—" : schedules.length}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">
          Across your team
        </p></AilaCard>
        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Enabled
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {schedulesQuery.isLoading ? "—" : enabledCount}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">
          Currently firing on cron
        </p></AilaCard>
        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Available Actions
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {actionsQuery.isLoading ? "—" : actions.length}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">
          Registered by modules
        </p></AilaCard>
      </div>

      {schedulesQuery.isError && (
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-sm text-destructive">
          Failed to load schedules: {(schedulesQuery.error as Error).message}
        </div>
      )}

      {actionsQuery.isError && (
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-sm text-destructive">
          Failed to load actions: {(actionsQuery.error as Error).message}
        </div>
      )}

      {schedulesQuery.isLoading && (
        <AilaCard variant="default" padding="md" techBorder glow><LoadingSkeletonGroup lines={6} /></AilaCard>
      )}

      {!schedulesQuery.isLoading &&
        !schedulesQuery.isError &&
        schedules.length === 0 && (
          <EmptyState
            icon={<Robot className="h-10 w-10" />}
            title="No automation schedules"
            description={
              actions.length > 0
                ? "Create a schedule to run a registered action on a cron."
                : "No automation actions are registered. Modules contribute actions at startup."
            }
          />
        )}

      {!schedulesQuery.isLoading && schedules.length > 0 && (
        <AilaTable
          data={schedules}
          columns={columns}
          pageSize={25}
          enableSorting
          enableFiltering={false}
        >
          <AilaTable.Header />
          <AilaTable.Body emptyState="No schedules found." />
          <AilaTable.Pagination pageSizeOptions={[10, 25, 50]} />
        </AilaTable>
      )}
    </div>
  );
}
