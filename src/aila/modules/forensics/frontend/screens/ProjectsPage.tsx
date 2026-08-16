import { useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router";

import { Folder } from "@phosphor-icons/react/dist/csr/Folder";
import { MagnifyingGlass } from "@phosphor-icons/react/dist/csr/MagnifyingGlass";

import { EmptyState } from "@/components/aila/EmptyState";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { PixelIcon } from "@/components/aila/PixelIcon";
import { SectionHeader, MonoBadge } from "@/components/aila/mock";

import { ProjectCardSkeletonGrid } from "../components/skeletons";
import { useForensicsProjects } from "../queries";
import { useDeleteProject } from "../mutations";
import { useDebouncedValue, useRowKeyboardNav, sortRows } from "../powerTable";
import type { ProjectSummary } from "../types";
import { useForensicsListLive } from "../useLiveInvalidation";
import { SavedViews } from "../components/SavedViews";

const PROJECTS_LIST_KEY = ["forensics", "projects"] as const;

// Sort keys align with ProjectSummary fields the operator can reasonably rank
// by from the grid. Server currently exposes only page + page_size (no `query`
// / `sort` params), so ordering and free-text filtering are applied client-side
// over the currently loaded page. When the backend grows a search param, wire
// it into the query hook and this dropdown stays in place.
type ProjectSortKey = "name" | "status" | "evidence_count" | "investigation_count" | "created_at";

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

const PROJECT_SORT_OPTIONS: readonly { key: ProjectSortKey; label: string }[] = [
  { key: "name", label: "Name" },
  { key: "status", label: "Status" },
  { key: "evidence_count", label: "Evidence" },
  { key: "investigation_count", label: "Investigations" },
  { key: "created_at", label: "Created" },
];

// Status tone -> mock badge tone. Keeps the earlier statusColor semantics but
// speaks the mock's semantic vocabulary (info/low/medium/critical/warn).
function statusTone(status: string): "info" | "low" | "medium" | "high" | "critical" | "muted" {
  switch (status) {
    case "created":
    case "queued":
    case "pending":
      return "info";
    case "ready":
    case "completed":
      return "low";
    case "analyzing":
    case "running":
      return "medium";
    case "exhausted":
    case "cancelled":
      return "high";
    case "failed":
      return "critical";
    default:
      return "muted";
  }
}

// Reusable inline styles for the raw controls -- mock language, not shadcn.
const INPUT_STYLE: React.CSSProperties = {
  height: 28,
  padding: "0 10px",
  fontSize: 11,
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-primary)",
  borderRadius: 3,
  minWidth: 220,
};

const SELECT_STYLE: React.CSSProperties = {
  height: 28,
  padding: "0 8px",
  fontSize: 10,
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-primary)",
  borderRadius: 3,
};

const DIR_BUTTON_STYLE: React.CSSProperties = {
  height: 28,
  padding: "0 10px",
  fontSize: 10,
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-muted)",
  borderRadius: 3,
  cursor: "pointer",
  letterSpacing: "0.08em",
};

const ACCENT_BUTTON_STYLE: React.CSSProperties = {
  height: 28,
  padding: "0 12px",
  fontSize: 10,
  letterSpacing: "0.08em",
  color: "var(--text-on-accent)",
  background: "var(--accent)",
  border: "1px solid var(--accent)",
  borderRadius: 3,
  cursor: "pointer",
  boxShadow: "var(--bevel-key)",
};

const MUTED_BUTTON_STYLE: React.CSSProperties = {
  height: 28,
  padding: "0 12px",
  fontSize: 10,
  letterSpacing: "0.08em",
  color: "var(--text-muted)",
  background: "transparent",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  cursor: "pointer",
};

function NewProjectButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="font-mono uppercase"
      style={ACCENT_BUTTON_STYLE}
    >
      + new project
    </button>
  );
}

function ProjectCard({
  project,
  onClick,
  onDelete,
}: {
  project: ProjectSummary;
  onClick: () => void;
  onDelete: (e: React.MouseEvent) => void;
}) {
  const [hover, setHover] = useState(false);
  const [focus, setFocus] = useState(false);
  return (
    <WindowPanel
      title={project.name.toLowerCase()}
      tone={statusTone(project.status) === "critical" ? "warn" : "accent"}
      status={`machine ; ${project.system_name ?? "unknown"}`}
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
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      onFocus={() => setFocus(true)}
      onBlur={() => setFocus(false)}
      role="button"
      tabIndex={0}
      aria-label={`Open forensics project ${project.name}`}
      data-power-row="project"
      className="cursor-pointer"
      style={{
        boxShadow: hover ? "0 0 0 1px var(--accent)" : undefined,
        outline: focus ? "2px solid var(--accent)" : undefined,
        outlineOffset: focus ? -2 : undefined,
      }}
    >
      <div className="space-y-2 relative">
        <div className="flex items-center justify-between gap-2">
          <MonoBadge tone={statusTone(project.status)}>{project.status}</MonoBadge>
        </div>
        {project.description && (
          <p
            className="font-mono line-clamp-2"
            style={{ fontSize: 11, color: "var(--text-muted)" }}
          >
            {project.description}
          </p>
        )}
        <div
          className="font-mono"
          style={{ fontSize: 10, color: "var(--text-muted)", lineHeight: 1.6 }}
        >
          <div>
            evidence <span style={{ color: "var(--text-primary)" }}>{project.evidence_count}</span>
          </div>
          <div>
            artifacts <span style={{ color: "var(--text-primary)" }}>{project.artifact_count}</span>
          </div>
          <div>
            leads <span style={{ color: "var(--text-primary)" }}>{project.lead_count}</span>
          </div>
          <div>
            investigations{" "}
            <span style={{ color: "var(--text-primary)" }}>{project.investigation_count}</span>
          </div>
        </div>
        <div
          className="font-mono flex items-center justify-between"
          style={{ fontSize: 9.5, color: "var(--text-faint)", letterSpacing: "0.06em" }}
        >
          <span>
            {project.created_at
              ? new Date(project.created_at).toLocaleDateString()
              : "\u2014"}
          </span>
          <button
            type="button"
            onClick={onDelete}
            title="Delete project"
            aria-label={`Delete project ${project.name}`}
            className="font-mono uppercase"
            style={{
              padding: "2px 6px",
              fontSize: 9,
              letterSpacing: "0.08em",
              color: "var(--text-faint)",
              background: "transparent",
              border: "1px solid var(--border-faint)",
              borderRadius: 2,
              cursor: "pointer",
            }}
          >
            del
          </button>
        </div>
      </div>
    </WindowPanel>
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
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ background: "color-mix(in srgb, var(--surface-sunk) 65%, transparent)" }}
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
      <WindowPanel
        title="delete project"
        tone="warn"
        className="max-w-sm w-full mx-4"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="space-y-4">
          <p
            className="font-mono"
            style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.55 }}
          >
            delete{" "}
            <span style={{ color: "var(--text-primary)" }}>&quot;{projectName}&quot;</span>? this
            will permanently remove all evidence records, artifacts, leads, investigations, and
            write-ups.
          </p>
          <div className="flex justify-end gap-3">
            <button
              type="button"
              onClick={onCancel}
              className="font-mono uppercase"
              style={MUTED_BUTTON_STYLE}
            >
              cancel
            </button>
            <button
              type="button"
              onClick={onConfirm}
              className="font-mono uppercase"
              style={ACCENT_BUTTON_STYLE}
            >
              delete
            </button>
          </div>
        </div>
      </WindowPanel>
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

      <SectionHeader
        icon={<PixelIcon name="folder" />}
        title="forensics projects"
        actions={<NewProjectButton onClick={() => navigate("/forensics/projects/new")} />}
      />

      <div className="flex flex-wrap items-center gap-2">
        <input
          type="search"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="search projects..."
          aria-label="Search projects by name, description, or machine"
          data-testid="forensics-projects-search"
          className="font-mono"
          style={INPUT_STYLE}
        />
        <span
          className="font-mono uppercase"
          style={{ fontSize: 9.5, color: "var(--text-faint)", letterSpacing: "0.1em" }}
        >
          sort
        </span>
        <select
          value={sortKey}
          onChange={(e) => setSortKey(e.target.value as ProjectSortKey)}
          aria-label="Sort projects by"
          data-testid="forensics-projects-sort-key"
          className="font-mono uppercase"
          style={SELECT_STYLE}
        >
          {PROJECT_SORT_OPTIONS.map((opt) => (
            <option key={opt.key} value={opt.key}>
              {opt.label}
            </option>
          ))}
        </select>
        <button
          type="button"
          onClick={() => setSortDir((d) => (d === "asc" ? "desc" : "asc"))}
          aria-label={`Sort direction, currently ${sortDir === "asc" ? "ascending" : "descending"}`}
          data-testid="forensics-projects-sort-dir"
          className="font-mono uppercase"
          style={DIR_BUTTON_STYLE}
        >
          {sortDir === "asc" ? "\u2191" : "\u2193"}
        </button>
        <SavedViews<ProjectsViewState>
          entityType="forensics_project"
          currentState={savedViewState}
          onApply={applySavedView}
          testIdPrefix="forensics-projects-views"
        />
      </div>

      {isLoading && <ProjectCardSkeletonGrid count={6} />}

      {isError && (
        <WindowPanel title="load error" tone="warn" status="forensics ; projects unavailable">
          <p className="font-mono" style={{ fontSize: 11, color: "var(--accent)" }}>
            failed to load forensics projects.
          </p>
        </WindowPanel>
      )}

      {!isLoading && !isError && projects.length === 0 && (
        debouncedSearch ? (
          <EmptyState
            icon={<MagnifyingGlass className="h-10 w-10" />}
            title={`No projects match \u201c${search}\u201d.`}
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

      {!isLoading && !isError && projects.length > 0 && (
        <div
          ref={gridRef}
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3"
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
      )}
    </div>
  );
}
