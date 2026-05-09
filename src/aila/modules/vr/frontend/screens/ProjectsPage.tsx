import { useNavigate } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { useVRProjects } from "../queries";
import type { VRProjectStatus } from "../types";

const statusColor: Record<VRProjectStatus, "info" | "low" | "medium" | "high" | "critical"> = {
  created: "info",
  analyzing: "medium",
  completed: "low",
  failed: "critical",
  stalled: "high",
};

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

  const projects = result?.data ?? [];

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

      {!isLoading && !isError && projects.length > 0 && (
        <AilaCard className="overflow-x-auto p-0">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border-default text-left text-xs uppercase tracking-wide text-text-muted">
                <th className="px-4 py-2 font-semibold">Name</th>
                <th className="px-4 py-2 font-semibold">CVE</th>
                <th className="px-4 py-2 font-semibold">Status</th>
                <th className="px-4 py-2 font-semibold">Target Class</th>
                <th className="px-4 py-2 font-semibold">Input Source</th>
                <th className="px-4 py-2 font-semibold text-right">Findings</th>
                <th className="px-4 py-2 font-semibold">Created</th>
              </tr>
            </thead>
            <tbody>
              {projects.map((project) => (
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
                    <AilaBadge severity={statusColor[project.status] ?? "info"} size="sm">
                      {project.status}
                    </AilaBadge>
                  </td>
                  <td className="px-4 py-2">
                    <AilaBadge severity="info" size="sm">
                      {project.target_class}
                    </AilaBadge>
                  </td>
                  <td className="px-4 py-2 font-mono text-text-muted">
                    {project.input_source ?? "—"}
                  </td>
                  <td className="px-4 py-2 font-mono text-right text-foreground">
                    {project.finding_count}
                  </td>
                  <td className="px-4 py-2 font-mono text-text-muted">
                    {formatDate(project.created_at)}
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
