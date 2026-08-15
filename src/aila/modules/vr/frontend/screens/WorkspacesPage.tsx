import { useMemo, useRef, useState } from "react";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { EmptyState } from "@/components/aila/EmptyState";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { Briefcase } from "@phosphor-icons/react/dist/csr/Briefcase";

import { DeleteButton } from "../components/DeleteButton";
import {
  SortHeader,
  useSortableRows,
  useTableRowNav,
  type SortValue,
} from "../components/tableHelpers";
import { useCreateWorkspace, useDeleteWorkspace } from "../mutations";
import { useWorkspaces } from "../queries";
import { useVRListInvalidation } from "../hooks/useVRListInvalidation";
import type { VRWorkspaceSummary, WorkspaceTheme } from "../types";

const THEMES: { value: WorkspaceTheme; label: string }[] = [
  { value: "browser_engines", label: "Browser engines" },
  { value: "linux_kernel", label: "Linux kernel" },
  { value: "container_runtimes", label: "Container runtimes" },
  { value: "industrial_scada", label: "Industrial / SCADA" },
  { value: "mobile_baseband", label: "Mobile baseband" },
  { value: "custom", label: "Custom" },
];

function formatDate(value?: string | null): string {
  if (!value) return "--";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

export function WorkspacesPage() {
  useVRListInvalidation("workspaces");
  const { data: result, isLoading, isError } = useWorkspaces();
  const createMut = useCreateWorkspace();
  const deleteMut = useDeleteWorkspace();

  const [showForm, setShowForm] = useState(false);
  const [formName, setFormName] = useState("");
  const [formSlug, setFormSlug] = useState("");
  const [formDescription, setFormDescription] = useState("");
  const [formTheme, setFormTheme] = useState<WorkspaceTheme>("custom");

  // Client-side quick filter: /vr/workspaces has no `q` param, so
  // filter the loaded page inline. Matches name / slug / theme
  // case-insensitively.
  const [query, setQuery] = useState("");

  const workspaces = result?.data ?? [];

  const filteredWorkspaces = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return workspaces;
    return workspaces.filter((ws) => {
      return (
        ws.name.toLowerCase().includes(needle) ||
        ws.slug.toLowerCase().includes(needle) ||
        ws.theme.toLowerCase().includes(needle) ||
        (ws.description ?? "").toLowerCase().includes(needle)
      );
    });
  }, [workspaces, query]);

  const accessors = useMemo<
    Record<string, (ws: VRWorkspaceSummary) => SortValue>
  >(
    () => ({
      name: (ws) => ws.name,
      slug: (ws) => ws.slug,
      theme: (ws) => ws.theme,
      status: (ws) => ws.status,
      target_count: (ws) => ws.target_count,
      active_investigation_count: (ws) => ws.active_investigation_count,
      created_at: (ws) => (ws.created_at ? new Date(ws.created_at) : null),
    }),
    [],
  );
  const { sortedRows, sortKey, sortDir, cycleSort } = useSortableRows(
    filteredWorkspaces,
    accessors,
  );

  const tbodyRef = useRef<HTMLTableSectionElement | null>(null);
  // Workspaces rows aren't clickable-to-navigate today; Enter on a row
  // is inert (there is no WorkspaceDetailPage). Row nav still gives
  // j/k highlight so operators can eyeball long lists.
  const { tbodyProps, getRowProps } = useTableRowNav(
    sortedRows,
    () => {},
    tbodyRef,
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <button
          type="button"
          onClick={() => setShowForm((v) => !v)}
          className="px-4 py-2 text-sm font-medium rounded-md bg-accent text-background hover:bg-accent/90 transition-colors"
        >
          {showForm ? "Cancel" : "New Workspace"}
        </button>
      </div>

      {showForm && (
        <AilaCard  techBorder glow><h2 className="font-mono uppercase tracking-cyber-sm text-2xs text-muted-foreground mb-2 pb-1.5 border-b border-border">
          Create workspace
        </h2>
        <div className="space-y-2">
          <input
            type="text"
            value={formName}
            onChange={(e) => setFormName(e.target.value)}
            placeholder="Name (e.g. 'Browser engines')"
            aria-label="Workspace name"
            className="w-full px-3 py-2 text-sm rounded-md bg-surface border border-border focus:border-accent focus:outline-none"
          />
          <input
            type="text"
            value={formSlug}
            onChange={(e) =>
              setFormSlug(e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, "-"))
            }
            placeholder="Slug (URL-safe, e.g. 'browser-engines')"
            pattern="[a-z0-9][a-z0-9_-]*"
            aria-label="Workspace slug"
            className="w-full px-3 py-2 text-sm font-mono rounded-md bg-surface border border-border focus:border-accent focus:outline-none"
          />
          <textarea
            value={formDescription}
            onChange={(e) => setFormDescription(e.target.value)}
            placeholder="Description (optional)"
            rows={2}
            aria-label="Workspace description"
            className="w-full px-3 py-2 text-sm rounded-md bg-surface border border-border focus:border-accent focus:outline-none"
          />
          <div className="flex gap-2 items-center">
            <label htmlFor="ws-theme" className="text-sm text-text-muted">Theme:</label>
            <select
              id="ws-theme"
              value={formTheme}
              onChange={(e) => setFormTheme(e.target.value as WorkspaceTheme)}
              className="px-3 py-2 text-sm rounded-md bg-surface border border-border"
            >
              {THEMES.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </select>
            <button
              type="button"
              disabled={
                !formName.trim() || !formSlug.trim() || createMut.isPending
              }
              onClick={() => {
                createMut.mutate(
                  {
                    name: formName.trim(),
                    slug: formSlug.trim(),
                    description: formDescription.trim() || undefined,
                    theme: formTheme,
                  },
                  {
                    onSuccess: () => {
                      setShowForm(false);
                      setFormName("");
                      setFormSlug("");
                      setFormDescription("");
                      setFormTheme("custom");
                    },
                  },
                );
              }}
              className="ml-auto px-4 py-2 text-sm font-medium rounded-md bg-accent text-background hover:bg-accent/90 transition-colors disabled:opacity-50"
            >
              {createMut.isPending ? "Creating…" : "Create"}
            </button>
          </div>
        </div></AilaCard>
      )}

      {isLoading && <LoadingSkeleton size="lg" width="full" />}

      {isError && (
        <AilaCard className="border-critical" techBorder glow><p className="text-sm text-critical">Failed to load workspaces.</p></AilaCard>
      )}

      {!isLoading && !isError && workspaces.length > 0 && (
        <AilaCard techBorder glow>
          <div className="flex items-center gap-2 flex-wrap">
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter workspaces (name / slug / theme)…"
              aria-label="Filter workspaces"
              className="flex-1 min-w-[220px] px-3 py-1.5 text-sm rounded-md bg-surface border border-border focus:border-accent focus:outline-none"
            />
            <span className="text-xs text-text-muted ml-auto">
              {sortedRows.length} of {workspaces.length} workspace
              {workspaces.length === 1 ? "" : "s"}
            </span>
          </div>
        </AilaCard>
      )}

      {!isLoading && !isError && workspaces.length === 0 && (
        <EmptyState
          icon={<Briefcase className="h-7 w-7" weight="duotone" />}
          title="No workspaces yet"
          description="A workspace groups targets and investigations under a shared theme (browser engines, kernel, container runtimes, and so on). It's the precondition for creating targets and investigations."
          action={{
            label: showForm ? "Cancel" : "New Workspace",
            onClick: () => setShowForm((v) => !v),
          }}
        />
      )}

      {!isLoading && !isError && workspaces.length > 0 && (
        <AilaCard className="overflow-x-auto p-0" techBorder glow><table className="w-full text-sm">
          <caption className="sr-only">Workspaces</caption>
          <thead>
            <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-text-muted">
              <SortHeader columnKey="name" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort}>Name</SortHeader>
              <SortHeader columnKey="slug" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort}>Slug</SortHeader>
              <SortHeader columnKey="theme" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort}>Theme</SortHeader>
              <SortHeader columnKey="status" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort}>Status</SortHeader>
              <SortHeader columnKey="target_count" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort} align="right">Targets</SortHeader>
              <SortHeader columnKey="active_investigation_count" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort} align="right">Active investigations</SortHeader>
              <SortHeader columnKey="created_at" currentKey={sortKey} currentDir={sortDir} onSort={cycleSort}>Created</SortHeader>
              <th className="px-2 py-2"></th>
            </tr>
          </thead>
          <tbody ref={tbodyRef} {...tbodyProps}>
            {sortedRows.map((ws, idx) => {
              const rowProps = getRowProps(idx);
              return (
              <tr
                key={ws.id}
                {...rowProps}
                className={
                  "border-b border-border last:border-b-0 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-inset " +
                  (rowProps["data-row-active"] ? "bg-elevated" : "")
                }
              >
                <td className="px-4 py-2 font-semibold text-foreground">
                  {ws.name}
                </td>
                <td className="px-4 py-2 font-mono text-xs text-text-muted">
                  {ws.slug}
                </td>
                <td className="px-4 py-2 font-mono text-xs text-text-muted">
                  {ws.theme}
                </td>
                <td className="px-4 py-2">
                  <AilaBadge
                    severity={ws.status === "active" ? "low" : "info"}
                    size="sm"
                  >
                    {ws.status}
                  </AilaBadge>
                </td>
                <td className="px-4 py-2 font-mono text-right text-foreground">
                  {ws.target_count}
                </td>
                <td className="px-4 py-2 font-mono text-right text-foreground">
                  {ws.active_investigation_count}
                </td>
                <td className="px-4 py-2 font-mono text-xs text-text-muted">
                  {formatDate(ws.created_at)}
                </td>
                <td className="px-2 py-2 text-right">
                  <DeleteButton
                    id={ws.id}
                    label={`workspace "${ws.name}"`}
                    mutation={deleteMut}
                    compact
                  />
                </td>
              </tr>
              );
            })}
          </tbody>
        </table></AilaCard>
      )}
    </div>
  );
}
