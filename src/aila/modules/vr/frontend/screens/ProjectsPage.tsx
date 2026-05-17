import { useNavigate, useSearchParams } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { SeverityPulse } from "@/components/aila/SeverityPulse";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { DeleteButton } from "../components/DeleteButton";
import { useDeleteProject } from "../mutations";
import { useProjectCompleteNotifier } from "../hooks/useProjectCompleteNotifier";
import { useTargetMap, useVRProjects } from "../queries";
import type { VRProjectStatus } from "../types";

const statusColor: Record<VRProjectStatus, "info" | "low" | "medium" | "high" | "critical"> = {
  created: "info",
  analyzing: "medium",
  completed: "low",
  failed: "critical",
  stalled: "high",
};


function relativeTime(value?: string | null): string {
  if (!value) return "—";
  try {
    const ago = Date.now() - new Date(value).getTime();
    if (ago < 60_000) return "just now";
    if (ago < 3600_000) return `${Math.floor(ago / 60_000)}m ago`;
    if (ago < 86_400_000) return `${Math.floor(ago / 3600_000)}h ago`;
    return `${Math.floor(ago / 86_400_000)}d ago`;
  } catch {
    return "—";
  }
}
function formatDate(value?: string | null): string {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleDateString();
  } catch {
    return value;
  }
}

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
      // updated / created — fallback to created_at desc (no updated_at on summary)
      sorted.sort(
        (a, b) =>
          new Date(b.created_at ?? 0).getTime() -
          new Date(a.created_at ?? 0).getTime(),
      );
    }
    return sorted;
  })();

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold font-mono text-foreground">
            Vulnerability Research
          </h1>
          <p className="text-sm text-text-muted mt-1">
            Manage n-day reproduction and disclosure projects.
          </p>
        </div>
        <button
          type="button"
          onClick={() => navigate("/vr/projects/new")}
          className="px-4 py-2 text-sm font-medium rounded-md bg-accent text-white hover:bg-accent/90 transition-colors"
        >
          New Project
        </button>
      </div>

      {isLoading && <LoadingSkeleton size="lg" width="full" />}

      {isError && (
        <AilaCard className="border-border-danger">
          <p className="text-sm text-text-danger">Failed to load VR projects.</p>
        </AilaCard>
      )}

      {!isLoading && !isError && projects.length === 0 && (
        <AilaCard>
          <div className="text-center py-8">
            <p className="text-text-muted">No VR projects yet.</p>
            <button
              type="button"
              onClick={() => navigate("/vr/projects/new")}
              className="mt-3 text-sm text-accent hover:underline"
            >
              Create your first project
            </button>
          </div>
        </AilaCard>
      )}

      {/* Filter bar (§Topic 1 consensus + spec §1.1) — status / target
          class / workstation / free-text search. Persisted in URL via
          useSearchParams so the view deep-links. */}
      {!isLoading && !isError && (
        <AilaCard>
          <div className="flex items-center gap-2 flex-wrap text-xs">
            <input
              type="text"
              placeholder="search name / CVE…"
              value={searchText}
              onChange={(e) => updateFilter("q", e.target.value)}
              className="px-2 py-1 rounded bg-surface border border-border-default font-mono w-48"
            />
            <select
              value={statusFilter}
              onChange={(e) => updateFilter("status", e.target.value)}
              className="px-2 py-1 rounded bg-surface border border-border-default font-mono"
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
              className="px-2 py-1 rounded bg-surface border border-border-default font-mono"
              aria-label="Sort field"
            >
              <option value="updated">sort: last activity</option>
              <option value="created">sort: created</option>
              <option value="name">sort: name</option>
              <option value="findings">sort: findings</option>
            </select>
            <span className="text-text-muted ml-auto">
              {filteredProjects.length} of {projects.length}
            </span>
          </div>
        </AilaCard>
      )}

      {!isLoading && !isError && filteredProjects.length > 0 && (
        <AilaCard className="overflow-x-auto p-0">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border-default text-left text-xs uppercase tracking-wide text-text-muted">
                <th className="px-4 py-2 font-semibold">Name</th>
                <th className="px-4 py-2 font-semibold">CVE</th>
                <th className="px-4 py-2 font-semibold">Status</th>
                <th className="px-4 py-2 font-semibold">Target</th>
                <th className="px-4 py-2 font-semibold text-right">Findings</th>
                <th className="px-4 py-2 font-semibold">Created</th>
                <th className="px-4 py-2 font-semibold">Last activity</th>
                <th className="px-2 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {filteredProjects.map((project) => (
                <tr
                  key={project.id}
                  onClick={() => navigate(`/vr/projects/${project.id}`)}
                  className="border-b border-border-default last:border-b-0 cursor-pointer hover:bg-surface transition-colors"
                >
                  <td className="px-4 py-2 font-mono font-semibold text-foreground">
                    {project.name}
                  </td>
                  <td className="px-4 py-2 font-mono text-text-muted">
                    {project.cve_id ?? "—"}
                  </td>
                  <td className="px-4 py-2">
                    <SeverityPulse
                      active={
                        project.status === "analyzing" ||
                        project.status === "failed"
                      }
                    >
                      <AilaBadge
                        severity={statusColor[project.status] ?? "info"}
                        size="sm"
                      >
                        {project.status}
                      </AilaBadge>
                    </SeverityPulse>
                  </td>
                  <td className="px-4 py-2 font-mono text-text-muted">
                    {project.target_id ? (
                      <span className="text-foreground">{targetMap.get(project.target_id)?.display_name ?? "loading…"}</span>
                    ) : "—"}
                  </td>
                  <td className="px-4 py-2 font-mono text-right text-foreground">
                    {project.finding_count}
                  </td>
                  <td className="px-4 py-2 font-mono text-text-muted">
                    {formatDate(project.created_at)}
                  </td>
                  <td className="px-4 py-2 font-mono text-text-muted">
                    {relativeTime(project.created_at)}
                  </td>
                  <td className="px-2 py-2 text-right">
                    <DeleteButton
                      id={project.id}
                      label={`project "${project.name}"`}
                      mutation={deleteMut}
                      compact
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </AilaCard>
      )}
    </div>
  );
}
