import { useState } from "react";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { useCreateWorkspace } from "../mutations";
import { useWorkspaces } from "../queries";
import type { WorkspaceTheme } from "../types";

const THEMES: { value: WorkspaceTheme; label: string }[] = [
  { value: "browser_engines", label: "Browser engines" },
  { value: "linux_kernel", label: "Linux kernel" },
  { value: "container_runtimes", label: "Container runtimes" },
  { value: "industrial_scada", label: "Industrial / SCADA" },
  { value: "mobile_baseband", label: "Mobile baseband" },
  { value: "custom", label: "Custom" },
];

function formatDate(value?: string | null): string {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

export function WorkspacesPage() {
  const { data: result, isLoading, isError } = useWorkspaces();
  const createMut = useCreateWorkspace();

  const [showForm, setShowForm] = useState(false);
  const [formName, setFormName] = useState("");
  const [formSlug, setFormSlug] = useState("");
  const [formDescription, setFormDescription] = useState("");
  const [formTheme, setFormTheme] = useState<WorkspaceTheme>("custom");

  const workspaces = result?.data ?? [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold font-mono text-foreground">
            Workspaces
          </h1>
          <p className="text-sm text-text-muted mt-1">
            Thematic projects (D-49). Each workspace groups related targets
            for cross-target pattern visibility + audit memo scoping.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setShowForm((v) => !v)}
          className="px-4 py-2 text-sm font-medium rounded-md bg-accent text-white hover:bg-accent/90 transition-colors"
        >
          {showForm ? "Cancel" : "New Workspace"}
        </button>
      </div>

      {showForm && (
        <AilaCard>
          <h2 className="text-sm font-semibold text-foreground mb-2">
            Create workspace
          </h2>
          <div className="space-y-2">
            <input
              type="text"
              value={formName}
              onChange={(e) => setFormName(e.target.value)}
              placeholder="Name (e.g. 'Browser engines')"
              className="w-full px-3 py-2 text-sm rounded-md bg-surface border border-border-default focus:border-accent focus:outline-none"
            />
            <input
              type="text"
              value={formSlug}
              onChange={(e) =>
                setFormSlug(e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, "-"))
              }
              placeholder="Slug (URL-safe, e.g. 'browser-engines')"
              pattern="[a-z0-9][a-z0-9_-]*"
              className="w-full px-3 py-2 text-sm font-mono rounded-md bg-surface border border-border-default focus:border-accent focus:outline-none"
            />
            <textarea
              value={formDescription}
              onChange={(e) => setFormDescription(e.target.value)}
              placeholder="Description (optional)"
              rows={2}
              className="w-full px-3 py-2 text-sm rounded-md bg-surface border border-border-default focus:border-accent focus:outline-none"
            />
            <div className="flex gap-2 items-center">
              <label className="text-sm text-text-muted">Theme:</label>
              <select
                value={formTheme}
                onChange={(e) => setFormTheme(e.target.value as WorkspaceTheme)}
                className="px-3 py-2 text-sm rounded-md bg-surface border border-border-default"
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
                className="ml-auto px-4 py-2 text-sm font-medium rounded-md bg-accent text-white hover:bg-accent/90 transition-colors disabled:opacity-50"
              >
                {createMut.isPending ? "Creating…" : "Create"}
              </button>
            </div>
          </div>
        </AilaCard>
      )}

      {isLoading && <LoadingSkeleton size="lg" width="full" />}

      {isError && (
        <AilaCard className="border-border-danger">
          <p className="text-sm text-text-danger">Failed to load workspaces.</p>
        </AilaCard>
      )}

      {!isLoading && !isError && workspaces.length === 0 && (
        <AilaCard>
          <div className="text-center py-8">
            <p className="text-text-muted">No workspaces yet.</p>
            <p className="text-text-muted text-xs mt-2">
              Create one above. Workspace is the precondition for creating
              targets and investigations.
            </p>
          </div>
        </AilaCard>
      )}

      {!isLoading && !isError && workspaces.length > 0 && (
        <AilaCard className="overflow-x-auto p-0">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border-default text-left text-xs uppercase tracking-wide text-text-muted">
                <th className="px-4 py-2 font-semibold">Name</th>
                <th className="px-4 py-2 font-semibold">Slug</th>
                <th className="px-4 py-2 font-semibold">Theme</th>
                <th className="px-4 py-2 font-semibold">Status</th>
                <th className="px-4 py-2 font-semibold text-right">Targets</th>
                <th className="px-4 py-2 font-semibold text-right">
                  Active investigations
                </th>
                <th className="px-4 py-2 font-semibold">Created</th>
              </tr>
            </thead>
            <tbody>
              {workspaces.map((ws) => (
                <tr
                  key={ws.id}
                  className="border-b border-border-default last:border-b-0"
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
                </tr>
              ))}
            </tbody>
          </table>
        </AilaCard>
      )}
    </div>
  );
}
