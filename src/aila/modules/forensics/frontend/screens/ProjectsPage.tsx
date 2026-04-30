import { useState } from "react";
import { useNavigate } from "react-router-dom";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { useForensicsProjects } from "../queries";
import { useDeleteProject } from "../mutations";
import type { ProjectSummary } from "../types";

const statusColor: Record<string, "info" | "low" | "medium" | "high" | "critical"> = {
  created: "info",
  ready: "low",
  analyzing: "medium",
  completed: "low",
  failed: "critical",
};

function ProjectCard({
  project,
  onClick,
  onDelete,
}: {
  project: ProjectSummary;
  onClick: () => void;
  onDelete: (e: React.MouseEvent) => void;
}) {
  return (
    <AilaCard onClick={onClick} className="cursor-pointer hover:ring-1 hover:ring-border-accent transition-shadow relative group">
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <h3 className="text-base font-semibold font-mono text-foreground truncate">{project.name}</h3>
          <div className="flex items-center gap-2">
            <AilaBadge severity={statusColor[project.status] ?? "info"} size="sm">
              {project.status}
            </AilaBadge>
            <button
              type="button"
              onClick={onDelete}
              title="Delete project"
              className="p-1 rounded text-text-muted hover:text-text-danger hover:bg-surface-danger/20 transition-colors"
            >
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="3 6 5 6 21 6" />
                <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" />
                <path d="M10 11v6M14 11v6" />
                <path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2" />
              </svg>
            </button>
          </div>
        </div>
        {project.description && (
          <p className="text-sm text-text-muted line-clamp-2">{project.description}</p>
        )}
        <div className="flex gap-4 text-xs text-text-muted">
          <span>{project.evidence_count} evidence</span>
          <span>{project.artifact_count} artifacts</span>
          <span>{project.lead_count} leads</span>
          <span>{project.investigation_count} investigations</span>
        </div>
        <div className="flex items-center justify-between text-xs text-text-muted">
          {project.system_name && <span>Machine: {project.system_name}</span>}
          {project.created_at && (
            <span>{new Date(project.created_at).toLocaleDateString()}</span>
          )}
        </div>
      </div>
    </AilaCard>
  );
}

function ConfirmDeleteDialog({
  projectName,
  onConfirm,
  onCancel,
}: {
  projectName: string;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onCancel}>
      <div
        className="bg-surface-elevated border border-border-default rounded-lg p-6 max-w-sm w-full mx-4 space-y-4"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="text-base font-semibold font-mono text-foreground">Delete Project</h2>
        <p className="text-sm text-text-muted">
          Delete <span className="text-foreground font-medium">"{projectName}"</span>? This will permanently remove all evidence records, artifacts, leads, investigations, and write-ups.
        </p>
        <div className="flex justify-end gap-3">
          <button
            type="button"
            onClick={onCancel}
            className="px-3 py-1.5 text-sm rounded-md border border-border-default text-text-muted hover:text-foreground transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            className="px-3 py-1.5 text-sm rounded-md bg-red-600 text-white hover:bg-red-700 transition-colors"
          >
            Delete
          </button>
        </div>
      </div>
    </div>
  );
}

export function ProjectsPage() {
  const navigate = useNavigate();
  const { data: result, isLoading, isError } = useForensicsProjects();
  const deleteProject = useDeleteProject();
  const [confirmDelete, setConfirmDelete] = useState<ProjectSummary | null>(null);

  const projects = result?.items ?? [];

  function handleDeleteClick(e: React.MouseEvent, project: ProjectSummary) {
    e.stopPropagation();
    setConfirmDelete(project);
  }

  function handleConfirmDelete() {
    if (!confirmDelete) return;
    deleteProject.mutate(confirmDelete.id, {
      onSettled: () => setConfirmDelete(null),
    });
  }

  return (
    <div className="space-y-4">
      {confirmDelete && (
        <ConfirmDeleteDialog
          projectName={confirmDelete.name}
          onConfirm={handleConfirmDelete}
          onCancel={() => setConfirmDelete(null)}
        />
      )}

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold font-mono text-foreground">Forensics Projects</h1>
          <p className="text-sm text-text-muted mt-1">
            Manage forensic investigation projects on remote analyzer machines.
          </p>
        </div>
        <button
          type="button"
          onClick={() => navigate("/forensics/projects/new")}
          className="px-4 py-2 text-sm font-medium rounded-md bg-accent text-white hover:bg-accent/90 transition-colors"
        >
          New Project
        </button>
      </div>

      {isLoading && <LoadingSkeleton size="lg" width="full" />}

      {isError && (
        <AilaCard className="border-border-danger">
          <p className="text-sm text-text-danger">Failed to load forensics projects.</p>
        </AilaCard>
      )}

      {!isLoading && !isError && projects.length === 0 && (
        <AilaCard>
          <div className="text-center py-8">
            <p className="text-text-muted">No forensics projects yet.</p>
            <button
              type="button"
              onClick={() => navigate("/forensics/projects/new")}
              className="mt-3 text-sm text-accent hover:underline"
            >
              Create your first project
            </button>
          </div>
        </AilaCard>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {projects.map((project) => (
          <ProjectCard
            key={project.id}
            project={project}
            onClick={() => navigate(`/forensics/projects/${project.id}`)}
            onDelete={(e) => handleDeleteClick(e, project)}
          />
        ))}
      </div>
    </div>
  );
}
