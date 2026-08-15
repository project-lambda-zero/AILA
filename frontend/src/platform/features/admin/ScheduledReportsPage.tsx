/**
 * ScheduledReportsPage -- admin-only scheduled report configurations.
 *
 * Endpoints (admin only):
 *   GET    /scheduled-reports
 *   POST   /scheduled-reports
 *   POST   /scheduled-reports/{id}/trigger
 *   DELETE /scheduled-reports/{id}
 */
import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import {
  SectionHeader,
  DataGrid,
  MonoBadge,
  BigStat,
} from "@/components/aila/mock";
import { authorizedRequestJson } from "@platform/api/http";

// ---------------------------------------------------------------------------
// Types
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
// Mock chrome
// ---------------------------------------------------------------------------

const BTN_STYLE: React.CSSProperties = {
  height: 26,
  fontSize: 9.5,
  padding: "0 11px",
  letterSpacing: "0.08em",
  borderRadius: 3,
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  cursor: "pointer",
  fontFamily: "var(--font-mono)",
  textTransform: "uppercase",
};

const BTN_ACCENT_STYLE: React.CSSProperties = {
  ...BTN_STYLE,
  border: "1px solid var(--accent)",
  background: "color-mix(in srgb, var(--accent) 14%, transparent)",
  color: "var(--accent)",
};

const BTN_DANGER_STYLE: React.CSSProperties = {
  ...BTN_STYLE,
  border: "1px solid color-mix(in srgb, var(--status-warn) 55%, transparent)",
  background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
  color: "var(--status-warn)",
};

const SMALL_BTN: React.CSSProperties = {
  ...BTN_STYLE,
  height: 22,
  fontSize: 9,
  padding: "0 9px",
};
const SMALL_DANGER: React.CSSProperties = {
  ...BTN_DANGER_STYLE,
  height: 22,
  fontSize: 9,
  padding: "0 9px",
};

const INPUT_STYLE: React.CSSProperties = {
  height: 28,
  fontSize: 11,
  padding: "0 10px",
  borderRadius: 3,
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  outline: "none",
  fontFamily: "var(--font-mono)",
  width: "100%",
};

const LABEL_STYLE: React.CSSProperties = {
  fontSize: 9,
  letterSpacing: "0.1em",
  color: "var(--text-faint)",
  fontFamily: "var(--font-mono)",
  textTransform: "uppercase",
};

function ErrorBox({ children }: { children: React.ReactNode }) {
  return (
    <div
      className="font-mono"
      style={{
        border:
          "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
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

/** Modal shell: fixed backdrop + centered WindowPanel. */
function ModalShell({
  open,
  title,
  onClose,
  width = 480,
  children,
}: {
  open: boolean;
  title: React.ReactNode;
  onClose: () => void;
  width?: number;
  children: React.ReactNode;
}) {
  useEffect(() => {
    if (!open) return;
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div
      role="dialog"
      aria-modal="true"
      onClick={onClose}
      style={{
        position: "fixed",
        inset: 0,
        background: "color-mix(in srgb, var(--surface-page) 78%, transparent)",
        backdropFilter: "blur(2px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 20,
        zIndex: 60,
      }}
    >
      <div onClick={(e) => e.stopPropagation()} style={{ width, maxWidth: "100%" }}>
        <WindowPanel
          title={title}
          actions={
            <button
              type="button"
              aria-label="Close"
              onClick={onClose}
              style={{
                width: 22,
                height: 22,
                border: "1px solid var(--border-soft)",
                background: "var(--surface-sunk)",
                color: "var(--text-primary)",
                fontSize: 10,
                cursor: "pointer",
                borderRadius: 2,
                fontFamily: "var(--font-mono)",
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
    const configJson = form.config_json.trim() || "{}";
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
      <button
        type="button"
        style={BTN_ACCENT_STYLE}
        onClick={() => setOpen(true)}
      >
        + NEW REPORT
      </button>
      <ModalShell
        open={open}
        title="new scheduled report"
        onClose={handleClose}
      >
        <form
          className="flex flex-col"
          style={{ gap: 12 }}
          onSubmit={handleSubmit}
        >
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={LABEL_STYLE} htmlFor="nr-name">
              name *
            </label>
            <input
              id="nr-name"
              value={form.name}
              onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
              placeholder="Weekly executive summary"
              style={INPUT_STYLE}
            />
          </div>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={LABEL_STYLE} htmlFor="nr-type">
              report type *
            </label>
            <input
              id="nr-type"
              value={form.report_type}
              onChange={(e) =>
                setForm((f) => ({ ...f, report_type: e.target.value }))
              }
              placeholder="executive_summary"
              style={INPUT_STYLE}
            />
          </div>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={LABEL_STYLE} htmlFor="nr-cron">
              cron expression *
            </label>
            <input
              id="nr-cron"
              value={form.cron_expression}
              onChange={(e) =>
                setForm((f) => ({ ...f, cron_expression: e.target.value }))
              }
              placeholder="0 9 * * MON"
              style={INPUT_STYLE}
            />
          </div>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={LABEL_STYLE} htmlFor="nr-recipients">
              recipients (comma-separated)
            </label>
            <input
              id="nr-recipients"
              value={recipientsInput}
              onChange={(e) => setRecipientsInput(e.target.value)}
              placeholder="ops@example.com, lead@example.com"
              style={INPUT_STYLE}
            />
          </div>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={LABEL_STYLE} htmlFor="nr-config">
              config json
            </label>
            <textarea
              id="nr-config"
              rows={3}
              value={form.config_json}
              onChange={(e) =>
                setForm((f) => ({ ...f, config_json: e.target.value }))
              }
              placeholder="{}"
              style={{
                ...INPUT_STYLE,
                height: "auto",
                paddingTop: 6,
                paddingBottom: 6,
                resize: "none",
              }}
              spellCheck={false}
            />
          </div>
          <label
            className="flex items-center font-mono"
            style={{
              gap: 6,
              fontSize: 10.5,
              color: "var(--text-primary)",
            }}
          >
            <input
              type="checkbox"
              checked={form.is_active}
              onChange={(e) =>
                setForm((f) => ({ ...f, is_active: e.target.checked }))
              }
            />
            <span
              className="uppercase"
              style={{ letterSpacing: "0.08em", fontSize: 10 }}
            >
              active
            </span>
          </label>
          {error && <ErrorBox>{error}</ErrorBox>}
          <div className="flex" style={{ gap: 8 }}>
            <button
              type="submit"
              style={{ ...BTN_ACCENT_STYLE, flex: 1 }}
              disabled={isPending}
            >
              {isPending ? "CREATING\u2026" : "CREATE"}
            </button>
            <button type="button" style={BTN_STYLE} onClick={handleClose}>
              CANCEL
            </button>
          </div>
        </form>
      </ModalShell>
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
      setStatus(`Queued: ${res.task_id.slice(0, 8)}\u2026`);
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
    <div
      className="flex flex-col items-end"
      style={{ gap: 3 }}
    >
      <div className="flex" style={{ gap: 5 }}>
        <button
          type="button"
          style={SMALL_BTN}
          disabled={busy || !report.is_active}
          onClick={handleTrigger}
          title={
            !report.is_active ? "Activate the report to trigger it" : undefined
          }
        >
          TRIGGER
        </button>
        <button
          type="button"
          style={SMALL_DANGER}
          disabled={busy}
          onClick={handleDelete}
        >
          DELETE
        </button>
      </div>
      {status && (
        <span
          className="font-mono"
          style={{ fontSize: 9.5, color: "var(--text-faint)" }}
        >
          {status}
        </span>
      )}
      {error && (
        <span
          className="font-mono"
          style={{ fontSize: 9.5, color: "var(--status-warn)" }}
        >
          {error}
        </span>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function ScheduledReportsPage() {
  const queryClient = useQueryClient();

  const reportsQuery = useQuery({
    queryKey: ["platform", "scheduled-reports"],
    queryFn: () =>
      authorizedRequestJson<DataEnvelope<ScheduledReport[]>>(
        "/scheduled-reports",
      ),
  });

  const createMutation = useMutation({
    mutationFn: (req: ScheduledReportCreate) =>
      authorizedRequestJson<DataEnvelope<ScheduledReport>>(
        "/scheduled-reports",
        { method: "POST", body: req },
      ),
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
  const pausedCount = reports.length - activeCount;

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <SectionHeader
        icon={"\u25a0"}
        title="Scheduled reports"
        actions={
          <div className="flex items-center" style={{ gap: 8 }}>
            <button
              type="button"
              style={BTN_STYLE}
              onClick={() => void reportsQuery.refetch()}
              disabled={reportsQuery.isFetching}
            >
              REFRESH
            </button>
            <CreateReportDialog
              onCreate={(req) => createMutation.mutateAsync(req)}
              isPending={createMutation.isPending}
            />
          </div>
        }
      />

      <div
        className="grid"
        style={{
          gridTemplateColumns: "repeat(3, minmax(0, 1fr))",
          gap: 12,
        }}
      >
        <WindowPanel title="total reports">
          <BigStat value={reports.length} sub="all configured" />
        </WindowPanel>
        <WindowPanel title="active">
          <BigStat value={activeCount} sub="firing on schedule" />
        </WindowPanel>
        <WindowPanel title="paused">
          <BigStat value={pausedCount} sub={"won\u2019t auto-fire"} />
        </WindowPanel>
      </div>

      {reportsQuery.isError && (
        <ErrorBox>
          failed to load scheduled reports:{" "}
          {(reportsQuery.error as Error).message}
        </ErrorBox>
      )}

      {reportsQuery.isLoading && (
        <WindowPanel title="reports" status="LOADING" tone="muted">
          <LoadingSkeletonGroup lines={6} />
        </WindowPanel>
      )}

      {!reportsQuery.isLoading && !reportsQuery.isError && (
        <WindowPanel title="schedules" flush>
          <DataGrid
            columns={[
              { label: "NAME", width: "1fr" },
              { label: "TYPE", width: "160px" },
              { label: "CADENCE", width: "160px" },
              { label: "RECIPIENTS", width: "180px" },
              { label: "OWNER", width: "150px" },
              { label: "NEXT / LAST RUN", width: "170px" },
              { label: "ACTIVE", width: "80px" },
              { label: "ACTIONS", width: "160px", align: "right" },
            ]}
            rows={reports}
            getKey={(r) => r.id}
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
                no scheduled reports. create one to email summaries on a cron.
              </div>
            }
            renderCells={(report) => {
              const recipients = parseRecipients(report.recipient_emails_json);
              return [
                <span
                  key="n"
                  className="font-mono"
                  style={{ fontSize: 11, color: "var(--text-primary)" }}
                >
                  {report.name}
                </span>,
                <MonoBadge key="t" tone="muted">
                  {report.report_type}
                </MonoBadge>,
                <code
                  key="c"
                  className="font-mono"
                  style={{ fontSize: 10.5, color: "var(--accent)" }}
                >
                  {report.cron_expression}
                </code>,
                <span
                  key="r"
                  className="font-mono truncate"
                  title={recipients.join(", ")}
                  style={{ fontSize: 10.5, color: "var(--text-muted)" }}
                >
                  {recipients.length === 0 ? "--" : recipients.join(", ")}
                </span>,
                <span
                  key="o"
                  className="font-mono truncate"
                  style={{ fontSize: 10.5, color: "var(--text-muted)" }}
                >
                  {report.created_by}
                </span>,
                <span
                  key="l"
                  className="font-mono"
                  style={{ fontSize: 10, color: "var(--text-faint)" }}
                >
                  {report.last_run_at
                    ? new Date(report.last_run_at).toLocaleString()
                    : "--"}
                </span>,
                <MonoBadge
                  key="a"
                  tone={report.is_active ? "ok" : "muted"}
                >
                  {report.is_active ? "ACTIVE" : "PAUSED"}
                </MonoBadge>,
                <RowActions
                  key="x"
                  report={report}
                  onTrigger={(id) => triggerMutation.mutateAsync(id)}
                  onDelete={(id) => deleteMutation.mutateAsync(id)}
                />,
              ];
            }}
          />
        </WindowPanel>
      )}
    </div>
  );
}
