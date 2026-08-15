/**
 * TeamsPage -- admin-only multi-team management (Phase 177).
 *
 * Lists all teams with member counts. Admins can create new teams and
 * click a row to navigate to the team detail page. Uses the
 * /admin/teams endpoints.
 *
 * Presentation rebuilt to the AILA mock language (SectionHeader +
 * WindowPanel + DataGrid + MonoBadge + StatBar). Data hooks, mutations,
 * route params, and testids are unchanged.
 */
import * as React from "react";
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router";

import { SectionHeader, DataGrid, MonoBadge, StatBar } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { authorizedRequestJson } from "@platform/api/http";

import {
  useCrossTeamStats,
  type CrossTeamStatsRow,
} from "./crossTeamQueries";

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
  width = 420,
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

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "--";
  return new Date(value).toLocaleString();
}

// ---------------------------------------------------------------------------
// Create modal
// ---------------------------------------------------------------------------

function CreateTeamButton({
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
      <button type="button" style={primaryBtn} onClick={() => setOpen(true)}>
        {"\u002b"} Create team
      </button>

      <ModalFrame open={open} onClose={handleClose} title="new team">
        <form className="flex flex-col" style={{ gap: 12 }} onSubmit={handleSubmit}>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={labelStyle} htmlFor="ct-name">name</label>
            <input
              id="ct-name"
              style={inputStyle}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="security-red"
            />
          </div>
          <div className="flex flex-col" style={{ gap: 4 }}>
            <label style={labelStyle} htmlFor="ct-desc">description</label>
            <input
              id="ct-desc"
              style={inputStyle}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Red team operations"
            />
          </div>
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
// Page
// ---------------------------------------------------------------------------

export function TeamsPage() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const teamsQuery = useQuery({
    queryKey: ["platform", "admin-teams"],
    queryFn: () => authorizedRequestJson<DataEnvelope<Team[]>>("/admin/teams"),
  });

  const crossQuery = useCrossTeamStats();

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

  const { totalMembers, totalSystems, totalRuns } = useMemo(() => {
    const members = crossRows.reduce((s, r) => s + r.members_count, 0);
    const systems = crossRows.reduce((s, r) => s + r.systems_count, 0);
    const runs = crossRows.reduce((s, r) => s + r.runs_count, 0);
    return { totalMembers: members, totalSystems: systems, totalRuns: runs };
  }, [crossRows]);

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <SectionHeader
        icon={"\u25ce"}
        title="teams"
        actions={
          <CreateTeamButton
            onCreate={(req) => createMutation.mutateAsync(req)}
            isPending={createMutation.isPending}
          />
        }
      />

      {/* Aggregate strip */}
      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 12 }}>
        <WindowPanel title="teams">
          <span className="font-mono" style={{ fontSize: 26, color: "var(--accent)" }}>
            {teams.length}
          </span>
        </WindowPanel>
        <WindowPanel title="members">
          <span className="font-mono" style={{ fontSize: 26, color: "var(--status-info)" }}>
            {totalMembers}
          </span>
        </WindowPanel>
        <WindowPanel title="systems">
          <span className="font-mono" style={{ fontSize: 26, color: "var(--status-ok)" }}>
            {totalSystems}
          </span>
        </WindowPanel>
        <WindowPanel title="workflow runs">
          <span className="font-mono" style={{ fontSize: 26, color: "var(--status-signal)" }}>
            {totalRuns}
          </span>
        </WindowPanel>
      </div>

      {teamsQuery.isError && (
        <ErrorLine>
          Failed to load teams: {(teamsQuery.error as Error).message}
        </ErrorLine>
      )}

      {teamsQuery.isLoading ? (
        <WindowPanel title="teams" status="LOADING" tone="muted">
          <LoadingSkeletonGroup lines={6} />
        </WindowPanel>
      ) : teams.length === 0 ? (
        <WindowPanel title="teams" tone="muted">
          <div
            className="flex flex-col items-center"
            style={{ padding: "42px 12px", gap: 12 }}
          >
            <span
              className="font-mono"
              style={{
                fontSize: 15,
                color: "var(--text-primary)",
                letterSpacing: "0.04em",
              }}
            >
              No teams yet
            </span>
            <span
              className="font-mono"
              style={{
                fontSize: 11,
                color: "var(--text-muted)",
                textAlign: "center",
                maxWidth: 380,
              }}
            >
              Create a team to organize members and isolate resources.
            </span>
          </div>
        </WindowPanel>
      ) : (
        <WindowPanel title="teams" flush>
          <DataGrid
            columns={[
              { label: "NAME", width: "1fr" },
              { label: "DESCRIPTION", width: "1.6fr" },
              { label: "MEMBERS", width: "90px", align: "right" },
              { label: "CREATED", width: "180px", align: "right" },
            ]}
            rows={teams}
            getKey={(t) => t.id}
            onRowClick={(t) => navigate(`/admin/teams/${t.id}`)}
            renderCells={(t) => [
              <span
                key="n"
                className="font-mono"
                style={{ fontSize: 12, color: "var(--text-primary)" }}
              >
                {t.name}
              </span>,
              <span
                key="d"
                className="font-mono truncate"
                style={{ fontSize: 10.5, color: "var(--text-muted)" }}
              >
                {t.description || "--"}
              </span>,
              <MonoBadge key="m" tone="info">{String(t.member_count)}</MonoBadge>,
              <span
                key="c"
                className="font-mono"
                style={{ fontSize: 10, color: "var(--text-faint)", whiteSpace: "nowrap" }}
              >
                {formatTimestamp(t.created_at)}
              </span>,
            ]}
          />
        </WindowPanel>
      )}

      {!crossQuery.isLoading && !crossQuery.isError && crossRows.length > 0 && (
        <CrossTeamComparison rows={crossRows} />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Cross-team comparison -- StatBar rows per team, one bar per metric.
// ---------------------------------------------------------------------------

interface CrossTeamComparisonProps {
  rows: CrossTeamStatsRow[];
}

function CrossTeamComparison({ rows }: CrossTeamComparisonProps) {
  const maxima = useMemo(() => {
    let sys = 0, run = 0, mem = 0;
    for (const r of rows) {
      if (r.systems_count > sys) sys = r.systems_count;
      if (r.runs_count > run) run = r.runs_count;
      if (r.members_count > mem) mem = r.members_count;
    }
    return { sys, run, mem };
  }, [rows]);

  const sorted = useMemo(
    () =>
      [...rows].sort(
        (a, b) =>
          b.systems_count + b.runs_count + b.members_count -
          (a.systems_count + a.runs_count + a.members_count),
      ),
    [rows],
  );

  return (
    <WindowPanel
      title="cross-team comparison"
      status={`${rows.length} TEAM${rows.length === 1 ? "" : "S"}`}
    >
      <div className="flex flex-col" style={{ gap: 14 }}>
        {sorted.map((row) => (
          <div key={row.team_id} className="flex flex-col" style={{ gap: 6 }}>
            <span
              className="font-mono"
              style={{ fontSize: 11, color: "var(--text-primary)" }}
            >
              {row.team_name}
            </span>
            <StatBar
              label="SYS"
              color="var(--accent)"
              value={row.systems_count}
              max={Math.max(1, maxima.sys)}
            />
            <StatBar
              label="RUNS"
              color="var(--status-info)"
              value={row.runs_count}
              max={Math.max(1, maxima.run)}
            />
            <StatBar
              label="MEM"
              color="var(--status-ok)"
              value={row.members_count}
              max={Math.max(1, maxima.mem)}
            />
          </div>
        ))}
      </div>
    </WindowPanel>
  );
}
