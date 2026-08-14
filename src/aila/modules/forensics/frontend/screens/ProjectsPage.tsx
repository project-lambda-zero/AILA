import { useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router";

import { Folder } from "@phosphor-icons/react/dist/csr/Folder";
import { MagnifyingGlass } from "@phosphor-icons/react/dist/csr/MagnifyingGlass";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { EmptyState } from "@/components/aila/EmptyState";

import { ProjectCardSkeletonGrid } from "../components/skeletons";
import { useForensicsProjects } from "../queries";
import { useDeleteProject } from "../mutations";
import { useDebouncedValue, useRowKeyboardNav, sortRows } from "../powerTable";
import type { ProjectSummary } from "../types";
import { useForensicsListLive } from "../useLiveInvalidation";
import { SavedViews } from "../components/SavedViews";

const PROJECTS_LIST_KEY = ["forensics", "projects"] as const;

// Serialized shape stored in SavedFilterRecord.filter_json for the
// projects grid. Additive only -- when new controls appear, extend
// the type and default missing keys on apply so older views still
// round-trip.
interface ProjectsViewState {
  search: string;
  sortKey: ProjectSortKey;
  sortDir: "asc" | "desc";
}

const PROJECT_SORT_KEYS: readonly ProjectSortKey[] = [
  "name",
  "status",
  "evidence_count",
  "investigation_count",
  "created_at",
];

// Sort keys align with ProjectSummary fields the operator can reasonably rank
// by from the grid. Server currently exposes only page + page_size (no `query`
// / `sort` params), so ordering and free-text filtering are applied client-side
// over the currently loaded page. When the backend grows a search param, wire
// it into the query hook and this dropdown stays in place.
type ProjectSortKey = "name" | "status" | "evidence_count" | "investigation_count" | "created_at";

const PROJECT_SORT_OPTIONS: readonly { key: ProjectSortKey; label: string }[] = [
  { key: "name", label: "Name" },
  { key: "status", label: "Status" },
  { key: "evidence_count", label: "Evidence" },
  { key: "investigation_count", label: "Investigations" },
  { key: "created_at", label: "Created" },
];

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
    <AilaCard
      onClick={onClick}
      onKeyDown={(e: React.KeyboardEvent<HTMLDivElement>) => {
        if (e.defaultPrevented) return;
        if (e.key === "Enter" || e.key === " ") {
          const target = e.target as HTMLElement | null;
          // Preserve the row-click escape hatch: inline buttons (Delete)
          // still handle their own key events. Only fire the card's open
          // action when focus is on the card wrapper itself.
          if (target && target !== e.currentTarget) return;
          e.preventDefault();
          onClick();
        }
      }}
      role="button"
      tabIndex={0}
      aria-label={`Open forensics project ${project.name}`}
      data-power-row="project"
      className="cursor-pointer hover:ring-1 hover:ring-border-accent transition-shadow relative group focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent focus-visible:-outline-offset-2"
      techBorder
      glow
    ><div className="space-y-2">
      <div className="flex items-center justify-between">
        <h2 className="text-base font-semibold font-mono text-foreground truncate">{project.name}</h2>
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
    </div></AilaCard>
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
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      role="button"
      tabIndex={0}
      aria-label="Close delete confirmation"
      onClick={onCancel}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " " || e.key === "Escape") {
          if (e.key === " ") e.preventDefault();
          onCancel();
        }
      }}
    >
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
  // Additive live refetch: forensics-scoped platform SSE events (e.g.
  // a new project/investigation lifecycle transition) invalidate the
  // projects list cache so the grid reflects teammate activity without
  // a full reload. No-op for unrelated events.
  useForensicsListLive(PROJECTS_LIST_KEY);
  const [confirmDelete, setConfirmDelete] = useState<ProjectSummary | null>(null);

  const [search, setSearch] = useState("");
  const debouncedSearch = useDebouncedValue(search.trim().toLowerCase(), 300);
  const [sortKey, setSortKey] = useState<ProjectSortKey>("created_at");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  const gridRef = useRef<HTMLDivElement | null>(null);
  useRowKeyboardNav({
    containerRef: gridRef,
    rowSelector: '[data-power-row="project"]',
  });

  const rawProjects = result?.items ?? [];

  const projects = useMemo(() => {
    const q = debouncedSearch;
    const filtered = q
      ? rawProjects.filter((p) => {
          const name = p.name?.toLowerCase() ?? "";
          const desc = p.description?.toLowerCase() ?? "";
          const system = p.system_name?.toLowerCase() ?? "";
          return name.includes(q) || desc.includes(q) || system.includes(q);
        })
      : rawProjects;
    return sortRows(
      filtered,
      (p) => {
        switch (sortKey) {
          case "name":
            return p.name ?? "";
          case "status":
            return p.status ?? "";
          case "evidence_count":
            return p.evidence_count;
          case "investigation_count":
            return p.investigation_count;
          case "created_at":
            return p.created_at ?? "";
        }
      },
      sortDir,
    );
  }, [rawProjects, debouncedSearch, sortKey, sortDir]);

  const savedViewState: ProjectsViewState = { search, sortKey, sortDir };

  function applySavedView(state: ProjectsViewState) {
    // Defensive: filter_json is caller-controlled and older payloads may
    // pre-date newer sort keys. Fall back to current values when a field
    // is missing or drifted rather than crashing the grid.
    if (typeof state.search === "string") setSearch(state.search);
    if (state.sortKey && PROJECT_SORT_KEYS.includes(state.sortKey)) {
      setSortKey(state.sortKey);
    }
    if (state.sortDir === "asc" || state.sortDir === "desc") {
      setSortDir(state.sortDir);
    }
  }

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

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search projects..."
            aria-label="Search projects by name, description, or machine"
            data-testid="forensics-projects-search"
            className="px-3 py-1.5 text-sm rounded-md border border-border bg-surface text-foreground placeholder:text-text-muted focus:outline-none focus:border-accent min-w-[220px]"
          />
          <label className="flex items-center gap-1.5 text-xs text-text-muted">
            <span>Sort</span>
            <select
              value={sortKey}
              onChange={(e) => setSortKey(e.target.value as ProjectSortKey)}
              aria-label="Sort projects by"
              data-testid="forensics-projects-sort-key"
              className="px-2 py-1 text-xs rounded-md border border-border bg-surface text-foreground focus:outline-none focus:border-accent"
            >
              {PROJECT_SORT_OPTIONS.map((opt) => (
                <option key={opt.key} value={opt.key}>{opt.label}</option>
              ))}
            </select>
            <button
              type="button"
              onClick={() => setSortDir((d) => (d === "asc" ? "desc" : "asc"))}
              aria-label={`Sort direction, currently ${sortDir === "asc" ? "ascending" : "descending"}`}
              data-testid="forensics-projects-sort-dir"
              className="px-2 py-1 text-xs rounded-md border border-border bg-surface text-foreground hover:border-accent focus:outline-none focus:border-accent"
            >
              {sortDir === "asc" ? "↑" : "↓"}
            </button>
          </label>
          <SavedViews<ProjectsViewState>
            entityType="forensics_project"
            currentState={savedViewState}
            onApply={applySavedView}
            testIdPrefix="forensics-projects-views"
          />
        </div>
        <button
          type="button"
          onClick={() => navigate("/forensics/projects/new")}
          className="px-4 py-2 text-sm font-medium rounded-md bg-accent text-white hover:bg-accent/90 transition-colors"
        >
          New Project
        </button>
      </div>

      {isLoading && <ProjectCardSkeletonGrid count={6} />}

      {isError && (
        <AilaCard className="border-border-danger" techBorder glow><p className="text-sm text-text-danger">Failed to load forensics projects.</p></AilaCard>
      )}

      {!isLoading && !isError && projects.length === 0 && (
        debouncedSearch ? (
          <EmptyState
            icon={<MagnifyingGlass className="h-10 w-10" />}
            title={`No projects match “${search}”.`}
            description="Clear the search to see every forensics project on this workspace."
            action={{ label: "Clear search", onClick: () => setSearch("") }}
            secondaryAction={{ label: "New project", onClick: () => navigate("/forensics/projects/new") }}
          />
        ) : (
          <EmptyState
            icon={<Folder className="h-10 w-10" />}
            title="No forensics projects yet."
            description="Start with an evidence upload or a raw directory to unlock intake, findings, and reasoning replays."
            action={{ label: "New project", onClick: () => navigate("/forensics/projects/new") }}
          />
        )
      )}

      <div
        ref={gridRef}
        className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4"
      >
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
