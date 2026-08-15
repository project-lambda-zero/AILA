import { useMemo } from "react";
import { useNavigate, useSearchParams } from "react-router";

import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import {
  SectionHeader,
  DataGrid,
  MonoBadge,
  BigStat,
  StatBar,
  toneColor,
  type GridColumn,
} from "@/components/aila/mock";

import { DeleteButton } from "../components/DeleteButton";
import { OperatorAvatar } from "../components/OperatorAvatar";
import { useDeleteProject } from "../mutations";
import { useProjectCompleteNotifier } from "../hooks/useProjectCompleteNotifier";
import {
  useInvestigations,
  useTargetMap,
  useVRProjects,
  useWorkspaces,
} from "../queries";
import type { VRProjectStatus, VRProjectSummary } from "../types";

// Mock-tone mapping for project status. Kept close to the mock's tone
// keys so MonoBadge renders the correct terminal-hue.
const statusTone: Record<VRProjectStatus, "info" | "warn" | "ok" | "critical" | "muted"> = {
  created: "info",
  analyzing: "warn",
  completed: "ok",
  failed: "critical",
  stalled: "muted",
};

function relativeTime(value?: string | null): string {
  if (!value) return "--";
  const t = new Date(value).getTime();
  if (Number.isNaN(t)) return "--";
  const delta = Date.now() - t;
  const s = Math.floor(delta / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

const COLUMNS: GridColumn[] = [
  { label: "status", width: "88px" },
  { label: "name", width: "minmax(0, 1.6fr)" },
  { label: "target", width: "minmax(0, 1fr)" },
  { label: "findings", width: "78px", align: "right" },
  { label: "investigations", width: "116px", align: "right" },
  { label: "operator", width: "96px" },
  { label: "updated", width: "108px" },
  { label: "\u00d7", width: "34px", align: "center" },
];

/** VR Projects landing page.
 *
 *  Rebuilt to the AILA mock language (dense mono, WindowPanels + honest
 *  DataGrid). Filter shelf drives URL search params for shareable views.
 *  Row navigation opens the ProjectDetailPage. */
export function ProjectsPage() {
  const navigate = useNavigate();
  const { data: result, isLoading, isError } = useVRProjects();
  const targetMap = useTargetMap();
  const { data: workspacesResult } = useWorkspaces();
  const { data: invsResult } = useInvestigations();
  useProjectCompleteNotifier();
  const deleteMut = useDeleteProject();

  const [searchParams, setSearchParams] = useSearchParams();
  const searchText = searchParams.get("q") ?? "";
  const statusFilter = searchParams.get("status") ?? "";
  const workspaceFilter = searchParams.get("workspace") ?? "";

  function updateFilter(key: string, value: string) {
    const next = new URLSearchParams(searchParams);
    if (value) next.set(key, value);
    else next.delete(key);
    setSearchParams(next, { replace: true });
  }

  const projects = result?.data ?? [];
  const workspaces = workspacesResult?.data ?? [];

  const investigationCountByTarget = useMemo(() => {
    const m = new Map<string, number>();
    for (const inv of invsResult?.data ?? []) {
      m.set(inv.target_id, (m.get(inv.target_id) ?? 0) + 1);
    }
    return m;
  }, [invsResult]);

  const stats = useMemo(() => {
    const total = projects.length;
    const analyzing = projects.filter((p) => p.status === "analyzing").length;
    const completed = projects.filter((p) => p.status === "completed").length;
    const failed = projects.filter((p) => p.status === "failed").length;
    const stalled = projects.filter((p) => p.status === "stalled").length;
    return { total, analyzing, completed, failed, stalled };
  }, [projects]);

  const filteredProjects = useMemo(() => {
    const q = searchText.trim().toLowerCase();
    let out = projects;
    if (q) {
      out = out.filter(
        (p) =>
          p.name.toLowerCase().includes(q) ||
          (p.cve_id ?? "").toLowerCase().includes(q),
      );
    }
    if (statusFilter) out = out.filter((p) => p.status === statusFilter);
    if (workspaceFilter) out = out.filter((p) => p.workspace_id === workspaceFilter);
    return [...out].sort(
      (a, b) =>
        new Date(b.created_at ?? 0).getTime() -
        new Date(a.created_at ?? 0).getTime(),
    );
  }, [projects, searchText, statusFilter, workspaceFilter]);

  const inputStyle = {
    background: "var(--surface-sunk)",
    border: "1px solid var(--border-soft)",
    color: "var(--text-primary)",
    fontFamily: "var(--font-mono)",
    fontSize: 10.5,
    padding: "0 8px",
    height: 26,
    borderRadius: 3,
    outline: "none",
  } as const;

  const newProjectButton = (
    <button
      type="button"
      onClick={() => navigate("/vr/projects/new")}
      className="font-mono uppercase"
      style={{
        height: 28,
        padding: "0 14px",
        fontSize: 10,
        letterSpacing: "0.09em",
        background: "var(--accent)",
        color: "var(--text-on-accent)",
        border: "1px solid var(--accent)",
        borderRadius: 3,
        cursor: "pointer",
      }}
      data-testid="vr-new-project"
    >
      + new project
    </button>
  );

  return (
    <div className="flex flex-col" style={{ gap: 18 }}>
      <h2 className="sr-only">Projects list</h2>
      <SectionHeader title="Projects" actions={newProjectButton} />

      {/* stats row -- three WindowPanels: total / analyzing / completed */}
      <div className="grid" style={{ gridTemplateColumns: "repeat(3, minmax(0, 1fr))", gap: 12 }}>
        <WindowPanel title="total" tone="accent">
          <BigStat value={stats.total} sub="projects tracked" />
          <div style={{ marginTop: 14, display: "flex", flexDirection: "column", gap: 6 }}>
            <StatBar
              label="failed"
              color={toneColor("critical")}
              value={stats.failed}
              max={Math.max(stats.total, 1)}
            />
            <StatBar
              label="stalled"
              color={toneColor("muted")}
              value={stats.stalled}
              max={Math.max(stats.total, 1)}
            />
          </div>
        </WindowPanel>
        <WindowPanel title="analyzing" tone="warn">
          <BigStat value={stats.analyzing} sub="in progress" />
          <div style={{ marginTop: 14 }}>
            <StatBar
              label="running"
              color={toneColor("warn")}
              value={stats.analyzing}
              max={Math.max(stats.total, 1)}
            />
          </div>
        </WindowPanel>
        <WindowPanel title="completed" tone="ok">
          <BigStat value={stats.completed} sub="shipped" />
          <div style={{ marginTop: 14 }}>
            <StatBar
              label="done"
              color={toneColor("ok")}
              value={stats.completed}
              max={Math.max(stats.total, 1)}
            />
          </div>
        </WindowPanel>
      </div>

      {/* filter shelf */}
      <div className="flex flex-wrap items-center" style={{ gap: 8 }}>
        <input
          type="search"
          placeholder="search by name or cve..."
          value={searchText}
          onChange={(e) => updateFilter("q", e.target.value)}
          aria-label="Search projects by name or CVE"
          style={{ ...inputStyle, flex: "1 1 260px", minWidth: 220 }}
        />
        <select
          value={statusFilter}
          onChange={(e) => updateFilter("status", e.target.value)}
          aria-label="Filter by status"
          className="uppercase"
          style={{ ...inputStyle, minWidth: 140 }}
        >
          <option value="">all statuses</option>
          <option value="created">created</option>
          <option value="analyzing">analyzing</option>
          <option value="completed">completed</option>
          <option value="failed">failed</option>
          <option value="stalled">stalled</option>
        </select>
        <select
          value={workspaceFilter}
          onChange={(e) => updateFilter("workspace", e.target.value)}
          aria-label="Filter by workspace"
          style={{ ...inputStyle, minWidth: 200 }}
        >
          <option value="">all workspaces</option>
          {workspaces.map((w) => (
            <option key={w.id} value={w.id}>
              {w.name}
            </option>
          ))}
        </select>
        <span
          className="font-mono uppercase"
          style={{ marginLeft: "auto", fontSize: 10, letterSpacing: "0.1em", color: "var(--text-faint)" }}
        >
          {filteredProjects.length}
          <span style={{ color: "var(--text-faint)" }}> / {projects.length}</span>
        </span>
      </div>

      {/* main grid / loading / error */}
      {isLoading && (
        <WindowPanel title="projects" tone="muted">
          <LoadingSkeleton size="lg" width="full" />
        </WindowPanel>
      )}

      {isError && (
        <WindowPanel title="projects" tone="accent">
          <p className="font-mono" style={{ fontSize: 11, color: "var(--accent)" }}>
            failed to load vr projects.
          </p>
        </WindowPanel>
      )}

      {!isLoading && !isError && (
        <WindowPanel title="projects" tone="accent" flush>
          <DataGrid<VRProjectSummary>
            columns={COLUMNS}
            rows={filteredProjects}
            getKey={(p) => p.id}
            onRowClick={(p) => navigate(`/vr/projects/${p.id}`)}
            empty={
              <div
                className="font-mono"
                style={{ padding: 34, textAlign: "center", fontSize: 12, color: "var(--text-muted)" }}
              >
                {projects.length === 0
                  ? "no vr projects yet -- spin up your first investigation via + new project."
                  : "no projects match the current filters."}
              </div>
            }
            renderCells={(p) => {
              const targetName = p.target_id
                ? targetMap.get(p.target_id)?.display_name ?? "loading..."
                : "--";
              const investigationCount = p.target_id
                ? investigationCountByTarget.get(p.target_id) ?? 0
                : 0;
              return [
                <MonoBadge tone={statusTone[p.status] ?? "muted"}>{p.status}</MonoBadge>,
                <span style={{ minWidth: 0, display: "flex", flexDirection: "column", gap: 2 }}>
                  <span
                    style={{
                      color: "var(--text-primary)",
                      fontSize: 12,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {p.name}
                  </span>
                  {p.cve_id ? (
                    <span
                      style={{
                        color: "var(--accent)",
                        fontSize: 9.5,
                        letterSpacing: "0.08em",
                      }}
                    >
                      {p.cve_id}
                    </span>
                  ) : null}
                </span>,
                <span
                  style={{
                    color: "var(--text-muted)",
                    fontSize: 11,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    display: "block",
                  }}
                >
                  {targetName}
                </span>,
                <span style={{ fontSize: 12, color: "var(--text-primary)" }}>
                  {p.finding_count}
                </span>,
                <span style={{ fontSize: 12, color: "var(--text-primary)" }}>
                  {investigationCount}
                </span>,
                <span className="flex items-center" style={{ gap: 6 }}>
                  <OperatorAvatar operatorId={p.operator_id} size={22} />
                  <span
                    style={{
                      fontSize: 10,
                      color: "var(--text-muted)",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {p.operator_id ?? "--"}
                  </span>
                </span>,
                <span style={{ fontSize: 10.5, color: "var(--text-muted)" }}>
                  {relativeTime(p.created_at)}
                </span>,
                <span
                  onClick={(e) => e.stopPropagation()}
                  style={{ display: "inline-flex", justifyContent: "center" }}
                >
                  <DeleteButton
                    id={p.id}
                    label={`project "${p.name}"`}
                    mutation={deleteMut}
                    compact
                  />
                </span>,
              ];
            }}
          />
        </WindowPanel>
      )}
    </div>
  );
}
