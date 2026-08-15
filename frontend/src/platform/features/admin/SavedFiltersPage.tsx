/**
 * SavedFiltersPage -- admin management for user-saved filter configurations.
 *
 * Backed by /saved-filters (BE-09 / D-41/D-42, T-138-17). Admins see their
 * own filters plus team-shared filters (shared_with_team=true). Only the
 * owner can update or delete a given filter; the API enforces ownership and
 * the UI hides edit/delete actions when the current user is not the owner.
 *
 * Presentation rebuilt to the AILA mock language. Data hooks, mutations,
 * and testids preserved.
 */
import * as React from "react";
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { SectionHeader, DataGrid, MonoBadge, FilterChip } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { authorizedRequestJson } from "@platform/api/http";
import { useAuthStore } from "@platform/auth/useAuthStore";

// ---------------------------------------------------------------------------
// Types -- mirror src/aila/api/schemas/endpoints.py SavedFilter*
// ---------------------------------------------------------------------------

interface SavedFilter {
  id: string;
  user_id: string;
  name: string;
  entity_type: string;
  filter_json: string;
  is_pinned: boolean;
  shared_with_team: boolean;
  created_at: string;
  updated_at: string;
}

interface PaginatedMeta {
  total: number;
  offset: number;
  limit: number;
}

interface SavedFilterListEnvelope {
  data: SavedFilter[];
  meta: PaginatedMeta;
}

interface SavedFilterEnvelope {
  data: SavedFilter;
}

interface SavedFilterCreateRequest {
  name: string;
  entity_type: string;
  filter_json: string;
  is_pinned: boolean;
  shared_with_team: boolean;
}

interface SavedFilterUpdateRequest {
  name?: string;
  filter_json?: string;
  is_pinned?: boolean;
  shared_with_team?: boolean;
}

// ---------------------------------------------------------------------------
// Local mock styles
// ---------------------------------------------------------------------------

const btnBase: React.CSSProperties = {
  height: 26,
  fontSize: 9.5,
  letterSpacing: "0.08em",
  padding: "0 11px",
  borderRadius: 3,
  border: "1px solid var(--border-soft)",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  cursor: "pointer",
  textTransform: "uppercase",
  fontFamily: "var(--font-mono)",
};

const primaryBtn: React.CSSProperties = {
  ...btnBase,
  background: "var(--accent)",
  color: "var(--text-on-accent)",
  borderColor: "var(--accent)",
};

const dangerBtn: React.CSSProperties = {
  ...btnBase,
  color: "var(--status-warn)",
  borderColor: "color-mix(in srgb, var(--status-warn) 40%, transparent)",
};

const inputStyle: React.CSSProperties = {
  height: 28,
  padding: "0 8px",
  fontSize: 11,
  fontFamily: "var(--font-mono)",
  color: "var(--text-primary)",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  outline: "none",
  width: "100%",
};

const textareaStyle: React.CSSProperties = {
  ...inputStyle,
  height: "auto",
  padding: "6px 8px",
  resize: "vertical",
  lineHeight: 1.5,
};

const labelStyle: React.CSSProperties = {
  fontFamily: "var(--font-mono)",
  fontSize: 9,
  letterSpacing: "0.12em",
  textTransform: "uppercase",
  color: "var(--text-faint)",
};

function ErrorLine({ children }: { children: React.ReactNode }) {
  return (
    <div
      className="font-mono"
      style={{
        border: "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
        background: "color-mix(in srgb, var(--status-warn) 10%, transparent)",
        color: "var(--status-warn)",
        padding: "8px 12px",
        fontSize: 11,
        borderRadius: 3,
      }}
    >
      {children}
    </div>
  );
}

function ModalFrame({
  open,
  onClose,
  title,
  children,
  width = 500,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
  width?: number;
}) {
  if (!open) return null;
  return (
    <div
      className="flex items-center justify-center"
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 60,
        background: "color-mix(in srgb, var(--surface-page) 80%, transparent)",
      }}
      onClick={onClose}
      role="presentation"
    >
      <div onClick={(e) => e.stopPropagation()} style={{ width, maxWidth: "94vw" }}>
        <WindowPanel
          title={title}
          tone="accent"
          actions={
            <button
              type="button"
              aria-label="Close"
              onClick={onClose}
              className="font-mono"
              style={{
                width: 20,
                height: 20,
                border: 0,
                background: "transparent",
                color: "var(--text-muted)",
                cursor: "pointer",
                fontSize: 13,
                lineHeight: 1,
              }}
            >
              {"\u2715"}
            </button>
          }
        >
          <div style={{ maxHeight: "70vh", overflowY: "auto" }}>{children}</div>
        </WindowPanel>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "--";
  return new Date(value).toLocaleString();
}

function validateJson(value: string): string | null {
  if (value.trim() === "") return "Filter criteria cannot be empty.";
  try {
    JSON.parse(value);
    return null;
  } catch (e) {
    return e instanceof Error ? `Invalid JSON: ${e.message}` : "Invalid JSON";
  }
}

function shortUserId(userId: string): string {
  return userId.length > 12 ? `${userId.slice(0, 8)}\u2026` : userId;
}

// ---------------------------------------------------------------------------
// Filter editor modal (shared)
// ---------------------------------------------------------------------------

interface FilterFormState {
  name: string;
  entity_type: string;
  filter_json: string;
  is_pinned: boolean;
  shared_with_team: boolean;
}

const DEFAULT_FORM: FilterFormState = {
  name: "",
  entity_type: "findings",
  filter_json: "{}",
  is_pinned: false,
  shared_with_team: false,
};

interface FilterEditorDialogProps {
  mode: "create" | "edit";
  open: boolean;
  initial: FilterFormState;
  isPending: boolean;
  onSubmit: (form: FilterFormState) => Promise<unknown>;
  onClose: () => void;
}

function FilterEditorDialog({
  mode,
  open,
  initial,
  isPending,
  onSubmit,
  onClose,
}: FilterEditorDialogProps) {
  const [form, setForm] = useState<FilterFormState>(initial);
  const [error, setError] = useState<string | null>(null);

  const [lastInitialKey, setLastInitialKey] = useState(JSON.stringify(initial));
  const currentInitialKey = JSON.stringify(initial);
  if (open && currentInitialKey !== lastInitialKey) {
    setForm(initial);
    setError(null);
    setLastInitialKey(currentInitialKey);
  }

  function handleClose() {
    onClose();
    setTimeout(() => {
      setForm(DEFAULT_FORM);
      setError(null);
    }, 200);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (form.name.trim().length === 0) {
      setError("Name is required.");
      return;
    }
    if (form.name.length > 128) {
      setError("Name must be 128 characters or fewer.");
      return;
    }
    if (mode === "create" && form.entity_type.trim().length === 0) {
      setError("Target page (entity_type) is required.");
      return;
    }
    const jsonError = validateJson(form.filter_json);
    if (jsonError) {
      setError(jsonError);
      return;
    }

    try {
      await onSubmit(form);
      handleClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save filter");
    }
  }

  return (
    <ModalFrame
      open={open}
      onClose={handleClose}
      title={mode === "create" ? "new saved filter" : "edit saved filter"}
    >
      <form className="flex flex-col" style={{ gap: 12 }} onSubmit={handleSubmit}>
        <div className="flex flex-col" style={{ gap: 4 }}>
          <label style={labelStyle} htmlFor="sf-name">name</label>
          <input
            id="sf-name"
            style={inputStyle}
            value={form.name}
            onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
            placeholder="e.g. Critical + KEV"
            maxLength={128}
            autoComplete="off"
          />
        </div>

        <div className="flex flex-col" style={{ gap: 4 }}>
          <label style={labelStyle} htmlFor="sf-entity">target page (entity_type)</label>
          <input
            id="sf-entity"
            style={{ ...inputStyle, opacity: mode === "edit" ? 0.6 : 1 }}
            value={form.entity_type}
            onChange={(e) => setForm((f) => ({ ...f, entity_type: e.target.value }))}
            placeholder="findings"
            disabled={mode === "edit"}
            autoComplete="off"
          />
          {mode === "edit" && (
            <p className="font-mono" style={{ fontSize: 9.5, color: "var(--text-faint)" }}>
              entity_type is immutable; create a new filter to target a different page.
            </p>
          )}
        </div>

        <div className="flex flex-col" style={{ gap: 4 }}>
          <label style={labelStyle} htmlFor="sf-json">filter criteria (json)</label>
          <textarea
            id="sf-json"
            style={textareaStyle}
            value={form.filter_json}
            onChange={(e) => setForm((f) => ({ ...f, filter_json: e.target.value }))}
            rows={6}
            placeholder='{"severity": ["critical", "high"]}'
            spellCheck={false}
          />
        </div>

        <fieldset
          className="flex flex-col"
          style={{ border: 0, padding: 0, gap: 6 }}
        >
          <legend className="sr-only">Filter visibility options</legend>
          <label
            className="inline-flex items-center font-mono"
            style={{ gap: 8, fontSize: 11, color: "var(--text-primary)" }}
          >
            <input
              type="checkbox"
              checked={form.is_pinned}
              onChange={(e) => setForm((f) => ({ ...f, is_pinned: e.target.checked }))}
            />
            Pin to toolbar
          </label>
          <label
            className="inline-flex items-center font-mono"
            style={{ gap: 8, fontSize: 11, color: "var(--text-primary)" }}
          >
            <input
              type="checkbox"
              checked={form.shared_with_team}
              onChange={(e) => setForm((f) => ({ ...f, shared_with_team: e.target.checked }))}
            />
            Share with team
          </label>
        </fieldset>

        {error && <ErrorLine>{error}</ErrorLine>}

        <div className="flex" style={{ gap: 8, marginTop: 4 }}>
          <button
            type="submit"
            style={{ ...primaryBtn, flex: 1 }}
            disabled={isPending}
          >
            {isPending
              ? mode === "create" ? "Creating..." : "Saving..."
              : mode === "create" ? "Create filter" : "Save changes"}
          </button>
          <button type="button" style={btnBase} onClick={handleClose}>
            Cancel
          </button>
        </div>
      </form>
    </ModalFrame>
  );
}

// ---------------------------------------------------------------------------
// Delete modal
// ---------------------------------------------------------------------------

interface DeleteFilterDialogProps {
  filter: SavedFilter | null;
  isPending: boolean;
  onConfirm: (id: string) => Promise<unknown>;
  onClose: () => void;
}

function DeleteFilterDialog({
  filter,
  isPending,
  onConfirm,
  onClose,
}: DeleteFilterDialogProps) {
  const [error, setError] = useState<string | null>(null);

  async function handleConfirm() {
    if (!filter) return;
    setError(null);
    try {
      await onConfirm(filter.id);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete filter");
    }
  }

  return (
    <ModalFrame
      open={filter !== null}
      onClose={() => {
        setError(null);
        onClose();
      }}
      title="delete saved filter"
      width={420}
    >
      {filter && (
        <div className="flex flex-col" style={{ gap: 12 }}>
          <p className="font-mono" style={{ fontSize: 11, color: "var(--text-primary)" }}>
            Filter{" "}
            <span style={{ color: "var(--accent)" }}>{filter.name}</span> will
            be removed permanently.
          </p>
          {error && <ErrorLine>{error}</ErrorLine>}
          <div className="flex" style={{ gap: 8 }}>
            <button
              type="button"
              style={{
                ...primaryBtn,
                flex: 1,
                background: "var(--status-warn)",
                borderColor: "var(--status-warn)",
              }}
              onClick={handleConfirm}
              disabled={isPending}
            >
              {isPending ? "Deleting..." : "Confirm Delete"}
            </button>
            <button
              type="button"
              style={btnBase}
              onClick={() => {
                setError(null);
                onClose();
              }}
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </ModalFrame>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

type VisibilityFilter = "all" | "pinned" | "shared" | "mine";

export function SavedFiltersPage() {
  const queryClient = useQueryClient();
  const currentUserId = useAuthStore((s) => s.userId);

  const [createOpen, setCreateOpen] = useState(false);
  const [editing, setEditing] = useState<SavedFilter | null>(null);
  const [deleting, setDeleting] = useState<SavedFilter | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [visibility, setVisibility] = useState<VisibilityFilter>("all");

  const filtersQuery = useQuery({
    queryKey: ["platform", "saved-filters"],
    queryFn: () =>
      authorizedRequestJson<SavedFilterListEnvelope>(
        "/saved-filters?offset=0&limit=250",
      ),
  });

  const createMutation = useMutation({
    mutationFn: (req: SavedFilterCreateRequest) =>
      authorizedRequestJson<SavedFilterEnvelope>("/saved-filters", {
        method: "POST",
        body: req,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "saved-filters"] });
    },
  });

  const updateMutation = useMutation({
    mutationFn: (args: { id: string; req: SavedFilterUpdateRequest }) =>
      authorizedRequestJson<SavedFilterEnvelope>(`/saved-filters/${args.id}`, {
        method: "PATCH",
        body: args.req,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "saved-filters"] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      authorizedRequestJson<void>(`/saved-filters/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "saved-filters"] });
    },
  });

  const filters = filtersQuery.data?.data ?? [];

  const { totalFilters, pinnedFilters, sharedFilters, myFilters } = useMemo(() => {
    return {
      totalFilters: filters.length,
      pinnedFilters: filters.filter((f) => f.is_pinned).length,
      sharedFilters: filters.filter((f) => f.shared_with_team).length,
      myFilters:
        currentUserId === null
          ? 0
          : filters.filter((f) => f.user_id === currentUserId).length,
    };
  }, [filters, currentUserId]);

  const shown = useMemo(() => {
    return filters.filter((f) => {
      if (visibility === "pinned" && !f.is_pinned) return false;
      if (visibility === "shared" && !f.shared_with_team) return false;
      if (
        visibility === "mine" &&
        (currentUserId === null || f.user_id !== currentUserId)
      )
        return false;
      return true;
    });
  }, [filters, visibility, currentUserId]);

  const selected = useMemo(
    () => (selectedId ? filters.find((f) => f.id === selectedId) ?? null : null),
    [filters, selectedId],
  );

  const editInitial: FilterFormState = editing
    ? {
        name: editing.name,
        entity_type: editing.entity_type,
        filter_json: editing.filter_json,
        is_pinned: editing.is_pinned,
        shared_with_team: editing.shared_with_team,
      }
    : DEFAULT_FORM;

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <SectionHeader
        icon={"\u25ce"}
        title="saved filters"
        actions={
          <button
            type="button"
            style={primaryBtn}
            onClick={() => setCreateOpen(true)}
          >
            {"\u002b"} New Filter
          </button>
        }
      />

      {/* Metric strip */}
      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 12 }}>
        <WindowPanel title="total filters">
          <span className="font-mono" style={{ fontSize: 26, color: "var(--accent)" }}>
            {totalFilters}
          </span>
        </WindowPanel>
        <WindowPanel title="pinned">
          <span className="font-mono" style={{ fontSize: 26, color: "var(--status-info)" }}>
            {pinnedFilters}
          </span>
        </WindowPanel>
        <WindowPanel title="team-shared">
          <span className="font-mono" style={{ fontSize: 26, color: "var(--status-ok)" }}>
            {sharedFilters}
          </span>
        </WindowPanel>
        <WindowPanel title="mine">
          <span className="font-mono" style={{ fontSize: 26, color: "var(--status-signal)" }}>
            {myFilters}
          </span>
        </WindowPanel>
      </div>

      {/* Filter chips */}
      <div className="flex items-center flex-wrap" style={{ gap: 8 }}>
        <FilterChip active={visibility === "all"} onClick={() => setVisibility("all")}>
          ALL ({totalFilters})
        </FilterChip>
        <FilterChip
          active={visibility === "pinned"}
          color="var(--status-info)"
          onClick={() => setVisibility("pinned")}
        >
          PINNED ({pinnedFilters})
        </FilterChip>
        <FilterChip
          active={visibility === "shared"}
          color="var(--status-ok)"
          onClick={() => setVisibility("shared")}
        >
          SHARED ({sharedFilters})
        </FilterChip>
        <FilterChip
          active={visibility === "mine"}
          color="var(--status-signal)"
          onClick={() => setVisibility("mine")}
        >
          MINE ({myFilters})
        </FilterChip>
      </div>

      {filtersQuery.isError && (
        <ErrorLine>
          Failed to load saved filters: {(filtersQuery.error as Error).message}
        </ErrorLine>
      )}

      {filtersQuery.isLoading ? (
        <WindowPanel title="filters" status="LOADING" tone="muted">
          <LoadingSkeletonGroup lines={6} />
        </WindowPanel>
      ) : filters.length === 0 ? (
        <WindowPanel title="filters" tone="muted">
          <div
            className="flex flex-col items-center"
            style={{ padding: "42px 12px", gap: 10 }}
          >
            <span
              className="font-mono"
              style={{ fontSize: 15, color: "var(--text-primary)", letterSpacing: "0.04em" }}
            >
              No saved filters
            </span>
            <span
              className="font-mono"
              style={{ fontSize: 11, color: "var(--text-muted)", textAlign: "center", maxWidth: 420 }}
            >
              Create your first saved filter to reuse complex queries across sessions.
            </span>
          </div>
        </WindowPanel>
      ) : (
        <div className="grid" style={{ gridTemplateColumns: "1fr 360px", gap: 16 }}>
          <WindowPanel
            title="filters"
            status={`${shown.length} SHOWN / ${filters.length} TOTAL`}
            flush
          >
            <DataGrid
              columns={[
                { label: "NAME", width: "1fr" },
                { label: "ENTITY", width: "130px" },
                { label: "OWNER", width: "160px" },
                { label: "UPDATED", width: "170px" },
                { label: "ACTIONS", width: "110px", align: "right" },
              ]}
              rows={shown}
              getKey={(f) => f.id}
              onRowClick={(f) => setSelectedId(f.id)}
              renderCells={(f) => {
                const isOwner =
                  currentUserId !== null && f.user_id === currentUserId;
                return [
                  <div key="n" className="flex items-center" style={{ gap: 6, minWidth: 0 }}>
                    <span
                      className="font-mono truncate"
                      style={{ fontSize: 11.5, color: "var(--text-primary)" }}
                    >
                      {f.name}
                    </span>
                    {f.is_pinned && (
                      <MonoBadge tone="info">pinned</MonoBadge>
                    )}
                    {f.shared_with_team && (
                      <MonoBadge tone="ok">shared</MonoBadge>
                    )}
                  </div>,
                  <span
                    key="e"
                    className="font-mono"
                    style={{ fontSize: 10.5, color: "var(--text-muted)" }}
                  >
                    {f.entity_type}
                  </span>,
                  <div key="o" className="flex items-center" style={{ gap: 6, minWidth: 0 }}>
                    <span
                      className="font-mono truncate"
                      style={{ fontSize: 10, color: "var(--text-muted)" }}
                      title={f.user_id}
                    >
                      {shortUserId(f.user_id)}
                    </span>
                    {isOwner && <MonoBadge tone="info">you</MonoBadge>}
                  </div>,
                  <span
                    key="u"
                    className="font-mono"
                    style={{ fontSize: 10, color: "var(--text-faint)", whiteSpace: "nowrap" }}
                  >
                    {formatTimestamp(f.updated_at)}
                  </span>,
                  <div
                    key="a"
                    className="flex"
                    style={{ gap: 6, justifyContent: "flex-end" }}
                    onClick={(e) => e.stopPropagation()}
                  >
                    <button
                      type="button"
                      style={btnBase}
                      disabled={!isOwner}
                      title={isOwner ? "Edit filter" : "Only the owner can edit this filter"}
                      onClick={() => setEditing(f)}
                      aria-label={`Edit ${f.name}`}
                    >
                      Edit
                    </button>
                    <button
                      type="button"
                      style={dangerBtn}
                      disabled={!isOwner}
                      title={isOwner ? "Delete filter" : "Only the owner can delete this filter"}
                      onClick={() => setDeleting(f)}
                      aria-label={`Delete ${f.name}`}
                    >
                      Del
                    </button>
                  </div>,
                ];
              }}
            />
          </WindowPanel>

          <WindowPanel
            title={selected ? "preview" : "select a filter"}
            tone={selected ? "accent" : "muted"}
          >
            {selected ? (
              <div className="flex flex-col" style={{ gap: 12 }}>
                <div className="flex flex-col" style={{ gap: 3 }}>
                  <span style={labelStyle}>name</span>
                  <span
                    className="font-mono"
                    style={{ fontSize: 12, color: "var(--text-primary)" }}
                  >
                    {selected.name}
                  </span>
                </div>
                <div className="flex flex-col" style={{ gap: 3 }}>
                  <span style={labelStyle}>entity</span>
                  <span
                    className="font-mono"
                    style={{ fontSize: 11, color: "var(--text-muted)" }}
                  >
                    {selected.entity_type}
                  </span>
                </div>
                <div className="flex" style={{ gap: 6, flexWrap: "wrap" }}>
                  {selected.is_pinned && <MonoBadge tone="info">pinned</MonoBadge>}
                  {selected.shared_with_team && (
                    <MonoBadge tone="ok">shared</MonoBadge>
                  )}
                  {currentUserId !== null && selected.user_id === currentUserId && (
                    <MonoBadge tone="accent">you</MonoBadge>
                  )}
                </div>
                <div className="flex flex-col" style={{ gap: 3 }}>
                  <span style={labelStyle}>criteria (json)</span>
                  <pre
                    className="font-mono"
                    style={{
                      fontSize: 10.5,
                      color: "var(--text-primary)",
                      background: "var(--surface-sunk)",
                      border: "1px solid var(--border-soft)",
                      borderRadius: 3,
                      padding: 10,
                      whiteSpace: "pre-wrap",
                      wordBreak: "break-word",
                      maxHeight: 220,
                      overflowY: "auto",
                    }}
                  >
                    {(() => {
                      try {
                        return JSON.stringify(
                          JSON.parse(selected.filter_json),
                          null,
                          2,
                        );
                      } catch {
                        return selected.filter_json;
                      }
                    })()}
                  </pre>
                </div>
                <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                  <div className="flex flex-col" style={{ gap: 3 }}>
                    <span style={labelStyle}>created</span>
                    <span
                      className="font-mono"
                      style={{ fontSize: 10, color: "var(--text-faint)" }}
                    >
                      {formatTimestamp(selected.created_at)}
                    </span>
                  </div>
                  <div className="flex flex-col" style={{ gap: 3 }}>
                    <span style={labelStyle}>updated</span>
                    <span
                      className="font-mono"
                      style={{ fontSize: 10, color: "var(--text-faint)" }}
                    >
                      {formatTimestamp(selected.updated_at)}
                    </span>
                  </div>
                </div>
              </div>
            ) : (
              <span
                className="font-mono"
                style={{ fontSize: 11, color: "var(--text-muted)" }}
              >
                click a row to preview its criteria.
              </span>
            )}
          </WindowPanel>
        </div>
      )}

      <FilterEditorDialog
        mode="create"
        open={createOpen}
        initial={DEFAULT_FORM}
        isPending={createMutation.isPending}
        onSubmit={(form) =>
          createMutation.mutateAsync({
            name: form.name.trim(),
            entity_type: form.entity_type.trim(),
            filter_json: form.filter_json,
            is_pinned: form.is_pinned,
            shared_with_team: form.shared_with_team,
          })
        }
        onClose={() => setCreateOpen(false)}
      />

      <FilterEditorDialog
        mode="edit"
        open={editing !== null}
        initial={editInitial}
        isPending={updateMutation.isPending}
        onSubmit={(form) => {
          if (!editing) return Promise.resolve();
          return updateMutation.mutateAsync({
            id: editing.id,
            req: {
              name: form.name.trim(),
              filter_json: form.filter_json,
              is_pinned: form.is_pinned,
              shared_with_team: form.shared_with_team,
            },
          });
        }}
        onClose={() => setEditing(null)}
      />

      <DeleteFilterDialog
        filter={deleting}
        isPending={deleteMutation.isPending}
        onConfirm={(id) => deleteMutation.mutateAsync(id)}
        onClose={() => setDeleting(null)}
      />
    </div>
  );
}
