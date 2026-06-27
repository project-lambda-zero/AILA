/**
 * ScheduledReportsPage -- admin-only scheduled report configurations.
 *
 * Lists scheduled reports with cron expressions and recipient lists. Admins
 * can create new reports, manually trigger a run, or delete a report.
 *
 * Endpoints (admin only):
 *   GET    /scheduled-reports
 *   POST   /scheduled-reports
 *   POST   /scheduled-reports/{id}/trigger
 *   DELETE /scheduled-reports/{id}
 */
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type ColumnDef } from "@tanstack/react-table";
import { Calendar } from "@phosphor-icons/react/dist/csr/Calendar";
import { Plus } from "@phosphor-icons/react/dist/csr/Plus";
import { Trash } from "@phosphor-icons/react/dist/csr/Trash";
import { PaperPlaneTilt } from "@phosphor-icons/react/dist/csr/PaperPlaneTilt";

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
// Types -- mirror src/aila/api/schemas/endpoints.py:ScheduledReport*
// ---------------------------------------------------------------------------

interface ScheduledReport {
  id: string;
  name: string;
  report_type: string;
  cron_expression: string;
  recipient_emails_json: string;
  config_json: string;
  is_active: boolean;
  last_run_at: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
}

interface ScheduledReportCreate {
  name: string;
  report_type: string;
  cron_expression: string;
  recipient_emails_json: string;
  config_json: string;
  is_active: boolean;
}

interface TriggerResponse {
  report_id: string;
  task_id: string;
  status: string;
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
  if (!value) return "--";
  return new Date(value).toLocaleString();
}

function parseRecipients(json: string): string[] {
  try {
    const parsed = JSON.parse(json);
    return Array.isArray(parsed) ? parsed.map((v) => String(v)) : [];
  } catch {
    return [];
  }
}

const DEFAULT_CREATE: ScheduledReportCreate = {
  name: "",
  report_type: "executive_summary",
  cron_expression: "0 9 * * MON",
  recipient_emails_json: "[]",
  config_json: "{}",
  is_active: true,
};

// ---------------------------------------------------------------------------
// Create dialog
// ---------------------------------------------------------------------------

function CreateReportDialog({
  onCreate,
  isPending,
}: {
  onCreate: (req: ScheduledReportCreate) => Promise<unknown>;
  isPending: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<ScheduledReportCreate>(DEFAULT_CREATE);
  const [recipientsInput, setRecipientsInput] = useState("");
  const [error, setError] = useState<string | null>(null);

  function handleClose() {
    setOpen(false);
    setTimeout(() => {
      setForm(DEFAULT_CREATE);
      setRecipientsInput("");
      setError(null);
    }, 200);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    const recipients = recipientsInput
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

    if (!form.name) {
      setError("Name is required");
      return;
    }
    if (!form.cron_expression) {
      setError("Cron expression is required");
      return;
    }

    let configJson = form.config_json.trim() || "{}";
    try {
      JSON.parse(configJson);
    } catch {
      setError("config_json must be valid JSON");
      return;
    }

    try {
      await onCreate({
        ...form,
        config_json: configJson,
        recipient_emails_json: JSON.stringify(recipients),
      });
      handleClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create report");
    }
  }

  return (
    <>
      <Button size="sm" className="gap-1.5" onClick={() => setOpen(true)}>
        <Plus className="h-4 w-4" />
        New report
      </Button>
      <Dialog open={open} onOpenChange={(v) => { if (!v) handleClose(); }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="font-mono text-text">
              New scheduled report
            </DialogTitle>
          </DialogHeader>
          <form className="flex flex-col gap-4" onSubmit={handleSubmit}>
            <div className="flex flex-col gap-1">
              <label className="font-mono text-xs text-text-muted" htmlFor="nr-name">
                Name *
              </label>
              <Input
                id="nr-name"
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="Weekly executive summary"
                className="font-mono text-sm"
              />
            </div>

            <div className="flex flex-col gap-1">
              <label className="font-mono text-xs text-text-muted" htmlFor="nr-type">
                Report type *
              </label>
              <Input
                id="nr-type"
                value={form.report_type}
                onChange={(e) =>
                  setForm((f) => ({ ...f, report_type: e.target.value }))
                }
                placeholder="executive_summary"
                className="font-mono text-sm"
              />
            </div>

            <div className="flex flex-col gap-1">
              <label className="font-mono text-xs text-text-muted" htmlFor="nr-cron">
                Cron expression *
              </label>
              <Input
                id="nr-cron"
                value={form.cron_expression}
                onChange={(e) =>
                  setForm((f) => ({ ...f, cron_expression: e.target.value }))
                }
                placeholder="0 9 * * MON"
                className="font-mono text-sm"
              />
            </div>

            <div className="flex flex-col gap-1">
              <label className="font-mono text-xs text-text-muted" htmlFor="nr-recipients">
                Recipients (comma-separated emails)
              </label>
              <Input
                id="nr-recipients"
                value={recipientsInput}
                onChange={(e) => setRecipientsInput(e.target.value)}
                placeholder="ops@example.com, lead@example.com"
                className="font-mono text-sm"
              />
            </div>

            <div className="flex flex-col gap-1">
              <label className="font-mono text-xs text-text-muted" htmlFor="nr-config">
                Config JSON
              </label>
              <textarea
                id="nr-config"
                rows={3}
                value={form.config_json}
                onChange={(e) =>
                  setForm((f) => ({ ...f, config_json: e.target.value }))
                }
                placeholder="{}"
                className="rounded-[2px] border border-border bg-base font-mono text-xs text-text px-2.5 py-1.5 outline-none focus:border-border-hover transition-colors duration-100 resize-none"
                spellCheck={false}
              />
            </div>

            <label className="flex items-center gap-2 font-mono text-xs text-text-muted">
              <input
                type="checkbox"
                checked={form.is_active}
                onChange={(e) =>
                  setForm((f) => ({ ...f, is_active: e.target.checked }))
                }
              />
              Active
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
// Row actions
// ---------------------------------------------------------------------------

function RowActions({
  report,
  onTrigger,
  onDelete,
}: {
  report: ScheduledReport;
  onTrigger: (id: string) => Promise<TriggerResponse>;
  onDelete: (id: string) => Promise<unknown>;
}) {
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleTrigger() {
    setError(null);
    setBusy(true);
    try {
      const res = await onTrigger(report.id);
      setStatus(`Queued: ${res.task_id}`);
      setTimeout(() => setStatus(null), 5000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to trigger");
    } finally {
      setBusy(false);
    }
  }

  async function handleDelete() {
    setError(null);
    setBusy(true);
    try {
      await onDelete(report.id);
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
          className="gap-1.5"
          disabled={busy || !report.is_active}
          onClick={handleTrigger}
          title={!report.is_active ? "Activate the report to trigger it" : undefined}
        >
          <PaperPlaneTilt className="h-3.5 w-3.5" />
          Trigger
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
      {status && (
        <span className="font-mono text-xs text-text-muted">{status}</span>
      )}
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
  onTrigger: (id: string) => Promise<TriggerResponse>,
  onDelete: (id: string) => Promise<unknown>,
): ColumnDef<ScheduledReport>[] {
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
      id: "report_type",
      header: "Type",
      accessorKey: "report_type",
      cell: ({ getValue }) => (
        <AilaBadge severity="neutral" size="sm">
          {String(getValue())}
        </AilaBadge>
      ),
    },
    {
      id: "cron_expression",
      header: "Schedule",
      accessorKey: "cron_expression",
      cell: ({ getValue }) => (
        <code className="font-mono text-xs text-text">{String(getValue())}</code>
      ),
    },
    {
      id: "recipients",
      header: "Recipients",
      accessorKey: "recipient_emails_json",
      enableSorting: false,
      cell: ({ getValue }) => {
        const emails = parseRecipients(String(getValue() ?? "[]"));
        if (emails.length === 0) {
          return <span className="font-mono text-xs text-text-muted">--</span>;
        }
        return (
          <span
            className="font-mono text-xs text-text-muted line-clamp-1 max-w-[220px]"
            title={emails.join(", ")}
          >
            {emails.join(", ")}
          </span>
        );
      },
    },
    {
      id: "is_active",
      header: "Status",
      accessorKey: "is_active",
      cell: ({ getValue }) =>
        getValue() ? (
          <AilaBadge severity="info" size="sm">Active</AilaBadge>
        ) : (
          <AilaBadge severity="neutral" size="sm">Paused</AilaBadge>
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
      id: "actions",
      header: "Actions",
      enableSorting: false,
      cell: ({ row }) => (
        <RowActions
          report={row.original}
          onTrigger={onTrigger}
          onDelete={onDelete}
        />
      ),
    },
  ];
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function ScheduledReportsPage() {
  const queryClient = useQueryClient();

  const reportsQuery = useQuery({
    queryKey: ["platform", "scheduled-reports"],
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<ScheduledReport[]>>("/scheduled-reports"),
  });

  const createMutation = useMutation({
    mutationFn: (req: ScheduledReportCreate) =>
      authorizedRequestJson<DataEnvelope<ScheduledReport>>("/scheduled-reports", {
        method: "POST",
        body: req,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["platform", "scheduled-reports"],
      });
    },
  });

  const triggerMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await authorizedRequestJson<DataEnvelope<TriggerResponse>>(
        `/scheduled-reports/${encodeURIComponent(id)}/trigger`,
        { method: "POST" },
      );
      return res.data;
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["platform", "scheduled-reports"],
      });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      authorizedRequestJson<void>(
        `/scheduled-reports/${encodeURIComponent(id)}`,
        { method: "DELETE" },
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["platform", "scheduled-reports"],
      });
    },
  });

  const reports = reportsQuery.data?.data ?? [];

  const activeCount = useMemo(
    () => reports.filter((r) => r.is_active).length,
    [reports],
  );

  const columns = useMemo(
    () =>
      buildColumns(
        (id) => triggerMutation.mutateAsync(id),
        (id) => deleteMutation.mutateAsync(id),
      ),
    [triggerMutation, deleteMutation],
  );

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <CreateReportDialog
          onCreate={(req) => createMutation.mutateAsync(req)}
          isPending={createMutation.isPending}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Total Reports
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {reportsQuery.isLoading ? "--" : reports.length}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">All configured</p></AilaCard>
        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Active
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {reportsQuery.isLoading ? "--" : activeCount}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">
          Firing on schedule
        </p></AilaCard>
        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Paused
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {reportsQuery.isLoading ? "--" : reports.length - activeCount}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">
          Won't fire automatically
        </p></AilaCard>
      </div>

      {reportsQuery.isError && (
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-sm text-destructive">
          Failed to load scheduled reports: {(reportsQuery.error as Error).message}
        </div>
      )}

      {reportsQuery.isLoading && (
        <AilaCard variant="default" padding="md" techBorder glow><LoadingSkeletonGroup lines={6} /></AilaCard>
      )}

      {!reportsQuery.isLoading &&
        !reportsQuery.isError &&
        reports.length === 0 && (
          <EmptyState
            icon={<Calendar className="h-10 w-10" />}
            title="No scheduled reports"
            description="Create a scheduled report to email summaries to stakeholders on a cron."
          />
        )}

      {!reportsQuery.isLoading && reports.length > 0 && (
        <AilaTable
          data={reports}
          columns={columns}
          pageSize={25}
          enableSorting
          enableFiltering={false}
        >
          <AilaTable.Header />
          <AilaTable.Body emptyState="No scheduled reports." />
          <AilaTable.Pagination pageSizeOptions={[10, 25, 50]} />
        </AilaTable>
      )}
    </div>
  );
}
