import { useMemo } from "react";
import { useNavigate, useSearchParams } from "react-router";
import { Plus } from "@phosphor-icons/react/dist/csr/Plus";
import { MagnifyingGlass } from "@phosphor-icons/react/dist/csr/MagnifyingGlass";
import { ArrowRight } from "@phosphor-icons/react/dist/csr/ArrowRight";
import { ShieldWarning } from "@phosphor-icons/react/dist/csr/ShieldWarning";
import { Pulse } from "@phosphor-icons/react/dist/csr/Pulse";
import { Folder } from "@phosphor-icons/react/dist/csr/Folder";
import { PaperPlaneTilt } from "@phosphor-icons/react/dist/csr/PaperPlaneTilt";
import { Warning } from "@phosphor-icons/react/dist/csr/Warning";
import { CheckCircle } from "@phosphor-icons/react/dist/csr/CheckCircle";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { SeverityPulse } from "@/components/aila/SeverityPulse";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { KpiTile } from "@/components/aila/KpiTile";

import { DeleteButton } from "../components/DeleteButton";
import { useDeleteProject } from "../mutations";
import { useProjectCompleteNotifier } from "../hooks/useProjectCompleteNotifier";
import { useTargetMap, useVRProjects } from "../queries";
import type { VRProjectStatus, VRProjectSummary } from "../types";
import { OperatorAvatar } from "../components/OperatorAvatar";

const statusColor: Record<VRProjectStatus, "info" | "low" | "medium" | "high" | "critical"> = {
  created: "info",
  analyzing: "medium",
  completed: "low",
  failed: "critical",
  stalled: "high",
};

function relativeTime(value?: string | null): string {
  if (!value) return "—";
  const t = new Date(value).getTime();
  if (Number.isNaN(t)) return "—";
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

function formatDate(value?: string | null): string {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}


// ─────────────────────────────────────────────────────────────────────
// Project card — replaces the table row. Visual hierarchy emphasises
// project name + status + severity, with a metric row underneath and a
// hover-revealed delete affordance.
// ─────────────────────────────────────────────────────────────────────
function ProjectCard({
  project,
  targetName,
  onOpen,
  deleteMut,
}: {
  project: VRProjectSummary;
  targetName: string;
  onOpen: () => void;
  deleteMut: ReturnType<typeof useDeleteProject>;
}) {
  const sev = statusColor[project.status] ?? "info";
  const isLive = project.status === "analyzing";
  const isFailed = project.status === "failed";

  // Tone the card top edge by status severity.
  const topEdgeColor: Record<typeof sev, string> = {
    info: "var(--color-text-muted)",
    low: "#97dbbe",
    medium: "#f0a8c7",
    high: "var(--color-accent)",
    critical: "var(--color-accent)",
  };

  return (
    <button
      type="button"
      onClick={onOpen}
      className="group relative flex flex-col text-left rounded-md border border-border bg-surface overflow-hidden transition-all duration-200 hover:border-accent/40 hover:-translate-y-0.5 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      style={{
        boxShadow:
          "inset 0 1px 0 0 color-mix(in srgb, var(--color-text) 5%, transparent)",
      }}
    >
      {/* Top edge — 2px severity-tinted bar */}
      <span
        aria-hidden
        className="absolute inset-x-0 top-0"
        style={{
          height: 2,
          background: `linear-gradient(90deg, transparent, ${topEdgeColor[sev]}, transparent)`,
        }}
      />
      {/* Subtle accent glow on hover */}
      <span
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-200"
        style={{
          background:
            "radial-gradient(80% 60% at 50% 0%, color-mix(in srgb, var(--color-accent) 8%, transparent), transparent 70%)",
        }}
      />

      {/* Header — status pulse + cve chip + operator avatar */}
      <div className="relative flex items-start justify-between gap-2 px-5 pt-4 pb-2">
        <div className="flex items-center gap-2 min-w-0">
          <SeverityPulse active={isLive || isFailed}>
            <AilaBadge severity={sev} size="sm">
              {project.status}
            </AilaBadge>
          </SeverityPulse>
          {project.cve_id && (
            <span
              className="inline-flex items-center px-2 py-0.5 rounded text-3xs font-mono tracking-wider"
              style={{
                color: "var(--color-accent)",
                background: "color-mix(in srgb, var(--color-accent) 10%, transparent)",
                border: "1px solid color-mix(in srgb, var(--color-accent) 25%, transparent)",
              }}
            >
              {project.cve_id}
            </span>
          )}
        </div>
        <div className="flex-shrink-0">
          <OperatorAvatar operatorId={project.operator_id} />
        </div>
      </div>

      {/* Title */}
      <div className="relative px-5 pb-3">
        <h3 className="font-display text-lg font-semibold text-foreground leading-tight truncate">
          {project.name}
        </h3>
        <p className="mt-0.5 text-xs font-mono text-text-muted truncate">
          {project.target_id ? targetName : "no target"}
        </p>
      </div>

      {/* Metric row */}
      <div
        className="relative grid grid-cols-3 gap-px mt-auto border-t border-border bg-border"
        aria-hidden={false}
      >
        <div className="bg-surface px-4 py-3">
          <p className="text-4xs font-mono uppercase tracking-cyber-sm text-text-muted">
            findings
          </p>
          <p className="mt-0.5 font-display text-xl font-semibold text-foreground leading-none">
            {project.finding_count}
          </p>
        </div>
        <div className="bg-surface px-4 py-3">
          <p className="text-4xs font-mono uppercase tracking-cyber-sm text-text-muted">
            disclosures
          </p>
          <p
            className="mt-0.5 font-display text-xl font-semibold leading-none"
            style={{
              color:
                project.latest_disclosure_status === "patched"
                  ? "#97dbbe"
                  : project.latest_disclosure_status
                    ? "var(--color-accent)"
                    : "var(--color-text-muted)",
            }}
          >
            {project.disclosure_submission_count ?? 0}
          </p>
        </div>
        <div className="bg-surface px-4 py-3">
          <p className="text-4xs font-mono uppercase tracking-cyber-sm text-text-muted">
            activity
          </p>
          <p className="mt-0.5 text-xs font-mono text-foreground truncate leading-none pt-1">
            {relativeTime(project.created_at)}
          </p>
        </div>
      </div>

      {/* Footer — disclosure status pill + open arrow + delete (hover) */}
      <div className="relative flex items-center justify-between gap-2 px-5 py-2.5 border-t border-border bg-base/40">
        <div className="min-w-0 flex-1">
          {project.latest_disclosure_status ? (
            <span className="inline-flex items-center gap-1.5 text-3xs font-mono uppercase tracking-wider text-text-muted">
              <PaperPlaneTilt className="h-3 w-3" />
              {project.latest_disclosure_status}
              {(project.disclosure_submission_count ?? 0) > 1 && (
                <span className="text-text-muted/60">
                  · ×{project.disclosure_submission_count}
                </span>
              )}
            </span>
          ) : (
            <span className="text-3xs font-mono text-text-muted/60">
              created {formatDate(project.created_at)}
            </span>
          )}
        </div>
        <div className="flex items-center gap-1">
          <div
            className="opacity-0 group-hover:opacity-100 transition-opacity"
            onClick={(e) => e.stopPropagation()}
          >
            <DeleteButton
              id={project.id}
              label={`project "${project.name}"`}
              mutation={deleteMut}
              compact
            />
          </div>
          <span
            aria-hidden
            className="inline-flex items-center text-text-muted group-hover:text-accent group-hover:translate-x-0.5 transition-all"
          >
            <ArrowRight className="h-4 w-4" />
          </span>
        </div>
      </div>
    </button>
  );
}

// ─────────────────────────────────────────────────────────────────────
// ProjectsPage — Vuln Research Projects landing.
//
// Layout (new design):
//   ┌─ KPI hero strip (4 tiles)
//   ├─ Action bar (search + status filter + sort + New Project CTA)
//   └─ Card grid (3 cols xl / 2 lg / 1 sm)
//
// Old design (dense 10-column table) was replaced because table density
// hid status + severity signals operator needs to scan for "what's
// running, what's failing, what's getting close to a disclosure".
// ─────────────────────────────────────────────────────────────────────
export function ProjectsPage() {
  const navigate = useNavigate();
  const { data: result, isLoading, isError } = useVRProjects();
  const targetMap = useTargetMap();
  useProjectCompleteNotifier();
  const deleteMut = useDeleteProject();

  const [searchParams, setSearchParams] = useSearchParams();
  const searchText = searchParams.get("q") ?? "";
  const statusFilter = searchParams.get("status") ?? "";
  const sortField = searchParams.get("sort") ?? "updated";

  function updateFilter(key: string, value: string) {
    const next = new URLSearchParams(searchParams);
    if (value) next.set(key, value);
    else next.delete(key);
    setSearchParams(next, { replace: true });
  }

  const projects = result?.data ?? [];

  const kpis = useMemo(() => {
    const total = projects.length;
    const active = projects.filter((p) => p.status === "analyzing").length;
    const stalled = projects.filter(
      (p) => p.status === "stalled" || p.status === "failed",
    ).length;
    const findings = projects.reduce((sum, p) => sum + (p.finding_count ?? 0), 0);
    const disclosures = projects.reduce(
      (sum, p) => sum + (p.disclosure_submission_count ?? 0),
      0,
    );
    return { total, active, stalled, findings, disclosures };
  }, [projects]);

  const filteredProjects = (() => {
    const q = searchText.trim().toLowerCase();
    let out = projects;
    if (q) {
      out = out.filter(
        (p) =>
          p.name.toLowerCase().includes(q) ||
          (p.cve_id ?? "").toLowerCase().includes(q),
      );
    }
    if (statusFilter) {
      out = out.filter((p) => p.status === statusFilter);
    }
    const sorted = [...out];
    if (sortField === "name") {
      sorted.sort((a, b) => a.name.localeCompare(b.name));
    } else if (sortField === "findings") {
      sorted.sort((a, b) => b.finding_count - a.finding_count);
    } else {
      sorted.sort(
        (a, b) =>
          new Date(b.created_at ?? 0).getTime() -
          new Date(a.created_at ?? 0).getTime(),
      );
    }
    return sorted;
  })();

  return (
    <div className="flex flex-col gap-6">
      {/* sr-only section heading bridges PageShell h1 → ProjectCard h3s for screen readers. */}
      <h2 className="sr-only">Projects list</h2>
      {/* ── KPI hero strip ───────────────────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <KpiTile
          label="Active projects"
          value={kpis.total}
          hint={kpis.active ? `${kpis.active} analyzing` : "none running"}
          icon={<Folder weight="duotone" />}
          tone="accent"
        />
        <KpiTile
          label="Investigations live"
          value={kpis.active}
          hint={
            kpis.active === 0
              ? "all idle"
              : kpis.active === 1
                ? "1 in progress"
                : `${kpis.active} in progress`
          }
          icon={<Pulse weight="duotone" />}
          tone={kpis.active > 0 ? "warn" : "neutral"}
        />
        <KpiTile
          label="Open findings"
          value={kpis.findings}
          hint={kpis.findings ? "across all projects" : "no findings yet"}
          icon={<ShieldWarning weight="duotone" />}
          tone={kpis.findings > 0 ? "crit" : "neutral"}
        />
        <KpiTile
          label="Disclosures sent"
          value={kpis.disclosures}
          hint={
            kpis.stalled
              ? `${kpis.stalled} stalled/failed`
              : "pipeline healthy"
          }
          icon={kpis.stalled > 0 ? <Warning weight="duotone" /> : <CheckCircle weight="duotone" />}
          tone={kpis.stalled > 0 ? "warn" : "ok"}
        />
      </div>

      {/* ── Action bar ──────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 max-w-md" style={{ minWidth: 220 }}>
          <MagnifyingGlass
            className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-text-muted pointer-events-none"
          />
          <input
            type="text"
            placeholder="Search by name or CVE…"
            value={searchText}
            onChange={(e) => updateFilter("q", e.target.value)}
            aria-label="Search projects by name or CVE"
            className="w-full pl-9 pr-3 py-2 text-sm rounded-md bg-surface border border-border focus:border-accent focus:outline-none transition-colors"
          />
        </div>
        <select
          value={statusFilter}
          onChange={(e) => updateFilter("status", e.target.value)}
          className="px-3 py-2 text-xs font-mono rounded-md bg-surface border border-border focus:border-accent focus:outline-none uppercase tracking-wider"
          aria-label="Filter by status"
        >
          <option value="">all statuses</option>
          <option value="created">created</option>
          <option value="analyzing">analyzing</option>
          <option value="completed">completed</option>
          <option value="failed">failed</option>
          <option value="stalled">stalled</option>
        </select>
        <select
          value={sortField}
          onChange={(e) => updateFilter("sort", e.target.value)}
          className="px-3 py-2 text-xs font-mono rounded-md bg-surface border border-border focus:border-accent focus:outline-none uppercase tracking-wider"
          aria-label="Sort field"
        >
          <option value="updated">last activity</option>
          <option value="created">created</option>
          <option value="name">name</option>
          <option value="findings">findings</option>
        </select>
        <span className="text-2xs font-mono text-text-muted ml-auto">
          {filteredProjects.length}
          <span className="text-text-muted/50"> / {projects.length}</span>
        </span>
        <button
          type="button"
          onClick={() => navigate("/vr/projects/new")}
          className="inline-flex items-center gap-1.5 px-4 py-2 text-sm font-semibold rounded-md text-base transition-all hover:-translate-y-px"
          style={{
            background: "var(--color-accent)",
            boxShadow:
              "0 0 0 1px color-mix(in srgb, var(--color-accent) 50%, transparent), 0 0 16px color-mix(in srgb, var(--color-accent) 28%, transparent)",
          }}
        >
          <Plus className="h-4 w-4" weight="bold" />
          New project
        </button>
      </div>

      {/* ── Loading / error / empty ─────────────────────────────────── */}
      {isLoading && <LoadingSkeleton size="lg" width="full" />}

      {isError && (
        <AilaCard className="border-border-danger" techBorder glow>
          <p className="text-sm text-text-danger">Failed to load VR projects.</p>
        </AilaCard>
      )}

      {!isLoading && !isError && projects.length === 0 && (
        <div
          className="rounded-md border border-dashed border-border px-8 py-16 text-center"
          style={{
            background: "color-mix(in srgb, var(--color-accent) 3%, transparent)",
          }}
        >
          <div
            className="inline-flex h-14 w-14 items-center justify-center rounded-full mb-4"
            style={{
              background: "color-mix(in srgb, var(--color-accent) 12%, transparent)",
              color: "var(--color-accent)",
            }}
          >
            <Folder className="h-7 w-7" weight="duotone" />
          </div>
          <p className="font-display text-lg font-semibold text-foreground">
            No VR projects yet
          </p>
          <p className="mt-1 text-sm text-text-muted">
            Spin up your first investigation against a target binary or service.
          </p>
          <button
            type="button"
            onClick={() => navigate("/vr/projects/new")}
            className="mt-5 inline-flex items-center gap-1.5 px-4 py-2 text-sm font-semibold rounded-md text-base transition-all hover:-translate-y-px"
            style={{
              background: "var(--color-accent)",
              boxShadow: "0 0 16px color-mix(in srgb, var(--color-accent) 28%, transparent)",
            }}
          >
            <Plus className="h-4 w-4" weight="bold" />
            Create your first project
          </button>
        </div>
      )}

      {/* ── Card grid ───────────────────────────────────────────────── */}
      {!isLoading && !isError && filteredProjects.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3">
          {filteredProjects.map((project) => (
            <ProjectCard
              key={project.id}
              project={project}
              targetName={
                project.target_id
                  ? targetMap.get(project.target_id)?.display_name ?? "loading…"
                  : "—"
              }
              onOpen={() => navigate(`/vr/projects/${project.id}`)}
              deleteMut={deleteMut}
            />
          ))}
        </div>
      )}

      {!isLoading && !isError && projects.length > 0 && filteredProjects.length === 0 && (
        <div className="rounded-md border border-dashed border-border px-6 py-10 text-center">
          <p className="text-sm text-text-muted">No projects match the current filter.</p>
          <button
            type="button"
            onClick={() => {
              const next = new URLSearchParams(searchParams);
              next.delete("q");
              next.delete("status");
              setSearchParams(next, { replace: true });
            }}
            className="mt-3 text-sm text-accent hover:underline"
          >
            Clear filters
          </button>
        </div>
      )}
    </div>
  );
}
