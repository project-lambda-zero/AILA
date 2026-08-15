/**
 * AutomationPage -- manage cron-driven automation schedules.
 *
 * Endpoints:
 *   GET    /automation/schedules
 *   POST   /automation/schedules
 *   PATCH  /automation/schedules/{id}
 *   DELETE /automation/schedules/{id}
 *   GET    /automation/actions
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

const DEFAULT_CREATE: AutomationScheduleCreate = {
  action_id: "",
  target_name: "",
  cron_expression: "0 9 * * MON",
  enabled: true,
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

  const activeAction = actions.find((a) => a.action_id === form.action_id);

  return (
    <>
      <button
        type="button"
        style={BTN_ACCENT_STYLE}
        onClick={() => setOpen(true)}
        disabled={actions.length === 0}
      >
        + NEW SCHEDULE
      </button>
      <ModalShell
        open={open}
        title="new automation schedule"
        onClose={handleClose}
      >
        <form
          className="flex flex-col"
          style={{ gap: 12 }}
          onSubmit={handleSubmit}
        >
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={LABEL_STYLE} htmlFor="ns-action">
              action *
            </label>
            <select
              id="ns-action"
              value={form.action_id}
              onChange={(e) =>
                setForm((f) => ({ ...f, action_id: e.target.value }))
              }
              style={INPUT_STYLE}
            >
              <option value="">-- select an action --</option>
              {actions.map((a) => (
                <option key={a.action_id} value={a.action_id}>
                  {a.action_id} ({a.module_id})
                </option>
              ))}
            </select>
            {activeAction && (
              <span
                className="font-mono"
                style={{ fontSize: 10.5, color: "var(--text-faint)" }}
              >
                {activeAction.description}
              </span>
            )}
          </div>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={LABEL_STYLE} htmlFor="ns-target">
              target system *
            </label>
            <input
              id="ns-target"
              value={form.target_name}
              onChange={(e) =>
                setForm((f) => ({ ...f, target_name: e.target.value }))
              }
              placeholder="prod-vm-01"
              style={INPUT_STYLE}
            />
          </div>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={LABEL_STYLE} htmlFor="ns-cron">
              cron expression *
            </label>
            <input
              id="ns-cron"
              value={form.cron_expression}
              onChange={(e) =>
                setForm((f) => ({ ...f, cron_expression: e.target.value }))
              }
              placeholder="0 9 * * MON"
              style={INPUT_STYLE}
            />
            <span
              className="font-mono"
              style={{ fontSize: 10, color: "var(--text-faint)" }}
            >
              {"e.g. "}<code>0 9 * * MON</code>{" \u2192 every Monday 09:00 UTC"}
            </span>
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
              checked={form.enabled}
              onChange={(e) =>
                setForm((f) => ({ ...f, enabled: e.target.checked }))
              }
            />
            <span
              className="uppercase"
              style={{ letterSpacing: "0.08em", fontSize: 10 }}
            >
              enabled
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
    <div className="flex flex-col items-end" style={{ gap: 3 }}>
      <div className="flex" style={{ gap: 5 }}>
        <button
          type="button"
          style={SMALL_BTN}
          disabled={busy}
          onClick={handleToggle}
        >
          {schedule.enabled ? "DISABLE" : "ENABLE"}
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

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <SectionHeader
        icon={"\u25c6"}
        title="Automation"
        actions={
          <div className="flex items-center" style={{ gap: 8 }}>
            <button
              type="button"
              style={BTN_STYLE}
              onClick={() => void schedulesQuery.refetch()}
              disabled={schedulesQuery.isFetching}
            >
              REFRESH
            </button>
            <CreateScheduleDialog
              actions={actions}
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
        <WindowPanel title="total schedules">
          <BigStat value={schedules.length} sub="across your team" />
        </WindowPanel>
        <WindowPanel title="enabled">
          <BigStat value={enabledCount} sub="firing on cron" />
        </WindowPanel>
        <WindowPanel title="available actions">
          <BigStat value={actions.length} sub="registered by modules" />
        </WindowPanel>
      </div>

      {schedulesQuery.isError && (
        <ErrorBox>
          failed to load schedules:{" "}
          {(schedulesQuery.error as Error).message}
        </ErrorBox>
      )}
      {actionsQuery.isError && (
        <ErrorBox>
          failed to load actions: {(actionsQuery.error as Error).message}
        </ErrorBox>
      )}

      {schedulesQuery.isLoading && (
        <WindowPanel title="schedules" status="LOADING" tone="muted">
          <LoadingSkeletonGroup lines={6} />
        </WindowPanel>
      )}

      {!schedulesQuery.isLoading && !schedulesQuery.isError && (
        <WindowPanel title="automations" flush>
          <DataGrid
            columns={[
              { label: "ACTION", width: "1fr" },
              { label: "TRIGGER (CRON)", width: "170px" },
              { label: "TARGET", width: "180px" },
              { label: "LAST RUN", width: "170px" },
              { label: "RESULT", width: "180px" },
              { label: "ACTIVE", width: "100px" },
              { label: "ACTIONS", width: "170px", align: "right" },
            ]}
            rows={schedules}
            getKey={(s) => s.id}
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
                {actions.length > 0
                  ? "no automation schedules. create one to run a registered action on a cron."
                  : "no automation actions are registered. modules contribute actions at startup."}
              </div>
            }
            renderCells={(schedule) => [
              <span
                key="a"
                className="font-mono"
                style={{ fontSize: 11, color: "var(--text-primary)" }}
              >
                {schedule.action_id}
              </span>,
              <code
                key="c"
                className="font-mono"
                style={{ fontSize: 10.5, color: "var(--accent)" }}
              >
                {schedule.cron_expression}
              </code>,
              <span
                key="t"
                className="font-mono truncate"
                style={{ fontSize: 10.5, color: "var(--text-muted)" }}
              >
                {schedule.target_name}
              </span>,
              <span
                key="l"
                className="font-mono"
                style={{ fontSize: 10, color: "var(--text-faint)" }}
              >
                {schedule.last_run_at
                  ? new Date(schedule.last_run_at).toLocaleString()
                  : "--"}
              </span>,
              <span
                key="r"
                className="font-mono truncate"
                title={schedule.last_run_result ?? undefined}
                style={{ fontSize: 10.5, color: "var(--text-muted)" }}
              >
                {schedule.last_run_result ?? "--"}
              </span>,
              <MonoBadge
                key="e"
                tone={schedule.enabled ? "ok" : "muted"}
              >
                {schedule.enabled ? "ENABLED" : "DISABLED"}
              </MonoBadge>,
              <RowActions
                key="x"
                schedule={schedule}
                onToggle={(id, enabled) =>
                  updateMutation.mutateAsync({ id, patch: { enabled } })
                }
                onDelete={(id) => deleteMutation.mutateAsync(id)}
              />,
            ]}
          />
        </WindowPanel>
      )}
    </div>
  );
}
