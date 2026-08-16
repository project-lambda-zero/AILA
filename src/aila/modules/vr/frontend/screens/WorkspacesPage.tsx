import { useMemo, useState } from "react";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";
import {
  DataGrid,
  MonoBadge,
  SectionHeader,
} from "@/components/aila/mock";

import { DeleteButton } from "../components/DeleteButton";
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

// Mock chrome for raw form controls.
const CTRL: React.CSSProperties = {
  height: 26,
  fontSize: 10.5,
  padding: "0 8px",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-primary)",
  borderRadius: 3,
  letterSpacing: "0.04em",
  outline: "none",
  fontFamily: "var(--font-mono)",
};

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

  // ─── Header actions: + new ───
  const headerActions = (
    <button
      type="button"
      onClick={() => setShowForm((v) => !v)}
      className="font-mono uppercase"
      style={{
        height: 28,
        padding: "0 12px",
        fontSize: 10,
        letterSpacing: "0.08em",
        background: showForm ? "var(--surface-sunk)" : "var(--accent)",
        border:
          "1px solid " +
          (showForm ? "var(--border-soft)" : "var(--accent)"),
        color: showForm ? "var(--text-primary)" : "var(--text-on-accent)",
        borderRadius: 3,
        cursor: "pointer",
      }}
    >
      {showForm ? "cancel" : "+ new workspace"}
    </button>
  );

  // ─── Create form ───
  const createFormPanel = showForm ? (
    <WindowPanel title="new workspace" tone="accent">
      <div className="flex flex-col" style={{ gap: 10 }}>
        <input
          type="text"
          value={formName}
          onChange={(e) => setFormName(e.target.value)}
          placeholder="name (e.g. 'Browser engines')"
          aria-label="Workspace name"
          className="font-mono w-full"
          style={{ ...CTRL, height: 30, fontSize: 11 }}
        />
        <input
          type="text"
          value={formSlug}
          onChange={(e) =>
            setFormSlug(
              e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, "-"),
            )
          }
          placeholder="slug (URL-safe, e.g. 'browser-engines')"
          pattern="[a-z0-9][a-z0-9_-]*"
          aria-label="Workspace slug"
          className="font-mono w-full"
          style={{ ...CTRL, height: 30, fontSize: 11 }}
        />
        <textarea
          value={formDescription}
          onChange={(e) => setFormDescription(e.target.value)}
          placeholder="description (optional)"
          rows={2}
          aria-label="Workspace description"
          className="font-mono w-full"
          style={{
            ...CTRL,
            height: "auto",
            padding: "8px 10px",
            fontSize: 11,
            resize: "vertical",
          }}
        />
        <div className="flex flex-wrap items-center" style={{ gap: 8 }}>
          <label
            htmlFor="ws-theme"
            className="font-mono uppercase"
            style={{
              fontSize: 10,
              letterSpacing: "0.08em",
              color: "var(--text-muted)",
            }}
          >
            theme:
          </label>
          <select
            id="ws-theme"
            value={formTheme}
            onChange={(e) => setFormTheme(e.target.value as WorkspaceTheme)}
            className="font-mono uppercase"
            style={CTRL}
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
            className="font-mono uppercase"
            style={{
              marginLeft: "auto",
              height: 28,
              padding: "0 14px",
              fontSize: 10,
              letterSpacing: "0.08em",
              background: "var(--accent)",
              border: "1px solid var(--accent)",
              color: "var(--text-on-accent)",
              borderRadius: 3,
              cursor: createMut.isPending ? "wait" : "pointer",
              opacity: createMut.isPending ? 0.7 : 1,
            }}
          >
            {createMut.isPending ? "creating…" : "create"}
          </button>
        </div>
      </div>
    </WindowPanel>
  ) : null;

  // ─── Filter shelf ───
  const filterShelf = (
    <WindowPanel title="filters" tone="muted">
      <div className="flex flex-wrap items-center" style={{ gap: 8 }}>
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="filter (name / slug / theme)…"
          aria-label="Filter workspaces"
          className="font-mono"
          style={{ ...CTRL, width: 260 }}
        />
        <span style={{ flex: 1 }} />
        <span
          className="font-mono"
          style={{
            fontSize: 10,
            color: "var(--text-faint)",
            letterSpacing: "0.06em",
          }}
        >
          {query.trim()
            ? `${filteredWorkspaces.length} of ${workspaces.length}`
            : `${workspaces.length}`}
          {" "}workspace{workspaces.length === 1 ? "" : "s"}
        </span>
      </div>
    </WindowPanel>
  );

  // ─── Table ───
  const columns: {
    label: string;
    width: string;
    align?: "left" | "right" | "center";
  }[] = [
    { label: "name", width: "1fr" },
    { label: "slug", width: "180px" },
    { label: "theme", width: "160px" },
    { label: "status", width: "90px" },
    { label: "targets", width: "80px", align: "right" },
    { label: "active inv.", width: "100px", align: "right" },
    { label: "created", width: "150px" },
    { label: "", width: "40px", align: "center" },
  ];

  function renderCells(ws: VRWorkspaceSummary): React.ReactNode[] {
    return [
      <span
        className="font-mono"
        title={ws.name}
        style={{
          fontSize: 11.5,
          color: "var(--text-primary)",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          display: "block",
        }}
      >
        {ws.name}
      </span>,
      <span
        className="font-mono"
        style={{ fontSize: 10.5, color: "var(--text-muted)" }}
      >
        {ws.slug}
      </span>,
      <span
        className="font-mono"
        style={{ fontSize: 10.5, color: "var(--text-muted)" }}
      >
        {ws.theme}
      </span>,
      <MonoBadge tone={ws.status === "active" ? "ok" : "info"}>
        {ws.status}
      </MonoBadge>,
      <span
        className="font-mono"
        style={{ fontSize: 11, color: "var(--text-primary)" }}
      >
        {ws.target_count}
      </span>,
      <span
        className="font-mono"
        style={{ fontSize: 11, color: "var(--text-primary)" }}
      >
        {ws.active_investigation_count}
      </span>,
      <span
        className="font-mono"
        style={{ fontSize: 10, color: "var(--text-faint)" }}
      >
        {formatDate(ws.created_at)}
      </span>,
      <span onClick={(e) => e.stopPropagation()}>
        <DeleteButton
          id={ws.id}
          label={`workspace "${ws.name}"`}
          mutation={deleteMut}
          compact
        />
      </span>,
    ];
  }

  const tableActions = (
    <span
      className="font-mono"
      style={{
        fontSize: 10,
        letterSpacing: "0.06em",
        color: "var(--text-faint)",
      }}
    >
      {filteredWorkspaces.length}
      <span style={{ opacity: 0.5 }}> / {workspaces.length}</span>
    </span>
  );

  let tableBody: React.ReactNode;
  if (isLoading) {
    tableBody = (
      <div style={{ padding: 12 }}>
        <LoadingSkeleton size="lg" width="full" />
      </div>
    );
  } else if (isError) {
    tableBody = (
      <div
        className="font-mono"
        style={{
          padding: 24,
          textAlign: "center",
          color: "var(--accent)",
          fontSize: 11,
          letterSpacing: "0.06em",
        }}
      >
        failed to load workspaces.
      </div>
    );
  } else {
    tableBody = (
      <DataGrid
        columns={columns}
        rows={filteredWorkspaces}
        renderCells={renderCells}
        getKey={(ws) => ws.id}
        empty={
          <div
            className="font-mono"
            style={{
              padding: 34,
              textAlign: "center",
              fontSize: 11.5,
              color: "var(--text-muted)",
              letterSpacing: "0.04em",
            }}
          >
            {query.trim()
              ? "no workspaces match the current filter."
              : "no workspaces yet -- create one from the header."}
          </div>
        }
      />
    );
  }

  return (
    <div className="flex flex-col" style={{ gap: 14 }}>
      <SectionHeader
        icon="◈"
        title="Workspaces"
        actions={headerActions}
      />
      {createFormPanel}
      {filterShelf}
      <WindowPanel
        title="results"
        tone="accent"
        actions={tableActions}
        flush
      >
        {tableBody}
      </WindowPanel>
    </div>
  );
}
