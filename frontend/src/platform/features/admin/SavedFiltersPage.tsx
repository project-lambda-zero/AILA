/**
 * SavedFiltersPage -- admin management for user-saved filter configurations.
 *
 * Backed by /saved-filters (BE-09 / D-41/D-42, T-138-17). Admins see their
 * own filters plus team-shared filters (shared_with_team=true). Only the
 * owner can update or delete a given filter; the API enforces ownership and
 * the UI hides edit/delete actions when the current user is not the owner.
 */
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BookmarkSimple } from "@phosphor-icons/react/dist/csr/BookmarkSimple";
import { PencilSimple } from "@phosphor-icons/react/dist/csr/PencilSimple";
import { Plus } from "@phosphor-icons/react/dist/csr/Plus";
import { Trash } from "@phosphor-icons/react/dist/csr/Trash";

import { AilaCard } from "@/components/aila/AilaCard";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { EmptyState } from "@/components/aila/EmptyState";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { authorizedRequestJson } from "@platform/api/http";
import { useAuthStore } from "@platform/auth/useAuthStore";

// ---------------------------------------------------------------------------
// Types — mirror src/aila/api/schemas/endpoints.py SavedFilter*
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
// Utilities
// ---------------------------------------------------------------------------

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "--";
  return new Date(value).toLocaleString();
}

/** Validate a JSON string — returns null if valid, error message otherwise. */
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
  // user_id is a UUID-ish string; show enough to disambiguate without
  // overflowing the table cell.
  return userId.length > 12 ? `${userId.slice(0, 8)}…` : userId;
}

// ---------------------------------------------------------------------------
// Filter editor dialog (shared between Create and Edit)
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
  /**
   * In edit mode, entity_type is immutable (the backend does not accept
   * entity_type in SavedFilterUpdate); we render it disabled.
   */
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

  // Reset form when the dialog opens with a new initial value.
  // useState initializer only runs once, so when `initial` changes between
  // edits we must sync explicitly.
  const [lastInitialKey, setLastInitialKey] = useState(JSON.stringify(initial));
  const currentInitialKey = JSON.stringify(initial);
  if (open && currentInitialKey !== lastInitialKey) {
    setForm(initial);
    setError(null);
    setLastInitialKey(currentInitialKey);
  }

  function handleClose() {
    onClose();
    // Defer reset so the user does not see the form jump while the dialog
    // animates out.
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
    <Dialog open={open} onOpenChange={(v) => { if (!v) handleClose(); }}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="font-mono text-text">
            {mode === "create" ? "Create saved filter" : "Edit saved filter"}
          </DialogTitle>
        </DialogHeader>

        <form className="flex flex-col gap-4" onSubmit={handleSubmit}>
          <div className="flex flex-col gap-1">
            <label className="font-mono text-xs text-text-muted" htmlFor="sf-name">
              Name
            </label>
            <Input
              id="sf-name"
              value={form.name}
              onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
              placeholder="e.g. Critical + KEV"
              className="font-mono text-sm"
              autoComplete="off"
              maxLength={128}
            />
          </div>

          <div className="flex flex-col gap-1">
            <label className="font-mono text-xs text-text-muted" htmlFor="sf-entity">
              Target page (entity_type)
            </label>
            <Input
              id="sf-entity"
              value={form.entity_type}
              onChange={(e) => setForm((f) => ({ ...f, entity_type: e.target.value }))}
              placeholder="findings"
              className="font-mono text-sm"
              autoComplete="off"
              disabled={mode === "edit"}
            />
            {mode === "edit" && (
              <p className="font-mono text-[10px] text-text-muted">
                entity_type is immutable; create a new filter to target a different page.
              </p>
            )}
          </div>

          <div className="flex flex-col gap-1">
            <label className="font-mono text-xs text-text-muted" htmlFor="sf-json">
              Filter criteria (JSON)
            </label>
            <textarea
              id="sf-json"
              value={form.filter_json}
              onChange={(e) => setForm((f) => ({ ...f, filter_json: e.target.value }))}
              rows={6}
              className="rounded-[2px] border border-border bg-base font-mono text-xs text-text px-2.5 py-1.5 outline-none focus:border-border-hover transition-colors duration-100 resize-y"
              placeholder='{"severity": ["critical", "high"]}'
              spellCheck={false}
            />
          </div>

          <div className="flex flex-col gap-2">
            <label className="flex items-center gap-2 font-mono text-xs text-text">
              <input
                type="checkbox"
                checked={form.is_pinned}
                onChange={(e) => setForm((f) => ({ ...f, is_pinned: e.target.checked }))}
                className="h-3.5 w-3.5"
              />
              Pin to toolbar
            </label>
            <label className="flex items-center gap-2 font-mono text-xs text-text">
              <input
                type="checkbox"
                checked={form.shared_with_team}
                onChange={(e) => setForm((f) => ({ ...f, shared_with_team: e.target.checked }))}
                className="h-3.5 w-3.5"
              />
              Share with team
            </label>
          </div>

          {error && (
            <div className="rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
              {error}
            </div>
          )}

          <div className="flex gap-2">
            <Button type="submit" size="sm" disabled={isPending} className="flex-1">
              {isPending
                ? mode === "create" ? "Creating..." : "Saving..."
                : mode === "create" ? "Create filter" : "Save changes"}
            </Button>
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={handleClose}
            >
              Cancel
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Delete confirmation
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
    <Dialog open={filter !== null} onOpenChange={(v) => { if (!v) { setError(null); onClose(); } }}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle className="font-mono text-text">Delete saved filter</DialogTitle>
        </DialogHeader>

        <div className="flex flex-col gap-4">
          {filter && (
            <div className="rounded-[4px] border border-destructive/40 bg-destructive/10 px-4 py-3">
              <p className="font-mono text-xs text-destructive font-semibold mb-1">
                This cannot be undone.
              </p>
              <p className="font-mono text-xs text-text-muted">
                Filter <span className="text-text font-semibold">{filter.name}</span>
                {" "}will be removed permanently.
              </p>
            </div>
          )}

          {error && (
            <div className="rounded-[4px] border border-destructive bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">
              {error}
            </div>
          )}

          <div className="flex gap-2">
            <Button
              type="button"
              size="sm"
              className="flex-1 bg-destructive hover:bg-destructive/90 text-white"
              onClick={handleConfirm}
              disabled={isPending}
            >
              {isPending ? "Deleting..." : "Confirm Delete"}
            </Button>
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => { setError(null); onClose(); }}
            >
              Cancel
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function SavedFiltersPage() {
  const queryClient = useQueryClient();
  const currentUserId = useAuthStore((s) => s.userId);

  const [createOpen, setCreateOpen] = useState(false);
  const [editing, setEditing] = useState<SavedFilter | null>(null);
  const [deleting, setDeleting] = useState<SavedFilter | null>(null);

  const filtersQuery = useQuery({
    queryKey: ["platform", "saved-filters"],
    queryFn: () =>
      authorizedRequestJson<SavedFilterListEnvelope>("/saved-filters?offset=0&limit=250"),
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
      authorizedRequestJson<void>(`/saved-filters/${id}`, {
        method: "DELETE",
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["platform", "saved-filters"] });
    },
  });

  const filters = filtersQuery.data?.data ?? [];

  const { totalFilters, pinnedFilters, sharedFilters } = useMemo(() => {
    return {
      totalFilters: filters.length,
      pinnedFilters: filters.filter((f) => f.is_pinned).length,
      sharedFilters: filters.filter((f) => f.shared_with_team).length,
    };
  }, [filters]);

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
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      {/* Page header */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">

        <Button size="sm" className="gap-1.5" onClick={() => setCreateOpen(true)}>
          <Plus className="h-4 w-4" />
          New Filter
        </Button>
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Total Filters
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {filtersQuery.isLoading ? "--" : totalFilters}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">
          Visible to current user
        </p></AilaCard>

        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Pinned
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {filtersQuery.isLoading ? "--" : pinnedFilters}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">
          Surfaced in toolbars
        </p></AilaCard>

        <AilaCard variant="elevated" padding="md" techBorder glow><p className="font-mono text-xs uppercase tracking-wider text-text-muted">
          Team-Shared
        </p>
        <p className="font-mono text-2xl font-semibold text-text mt-1">
          {filtersQuery.isLoading ? "--" : sharedFilters}
        </p>
        <p className="font-mono text-xs text-text-muted mt-0.5">
          Shared across the team
        </p></AilaCard>
      </div>

      {/* Error banner */}
      {filtersQuery.isError && (
        <div className="rounded-[4px] border border-destructive bg-destructive/10 px-4 py-3 font-mono text-sm text-destructive">
          Failed to load saved filters: {(filtersQuery.error as Error).message}
        </div>
      )}

      {/* Loading skeleton */}
      {filtersQuery.isLoading && (
        <AilaCard variant="default" padding="md" techBorder glow><LoadingSkeletonGroup lines={6} /></AilaCard>
      )}

      {/* Empty state */}
      {!filtersQuery.isLoading && !filtersQuery.isError && filters.length === 0 && (
        <EmptyState
          icon={<BookmarkSimple className="h-10 w-10" />}
          title="No saved filters"
          description="Create your first saved filter to reuse complex queries across sessions."
          action={{ label: "New Filter", onClick: () => setCreateOpen(true) }}
        />
      )}

      {/* Filters table */}
      {!filtersQuery.isLoading && filters.length > 0 && (
        <AilaCard variant="default" padding="none" techBorder glow><div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <th className="py-2 px-3 text-left font-mono text-xs text-text-muted">Name</th>
                <th className="py-2 px-3 text-left font-mono text-xs text-text-muted">Target page</th>
                <th className="py-2 px-3 text-left font-mono text-xs text-text-muted hidden md:table-cell">Filter criteria</th>
                <th className="py-2 px-3 text-left font-mono text-xs text-text-muted hidden lg:table-cell">Created by</th>
                <th className="py-2 px-3 text-left font-mono text-xs text-text-muted hidden xl:table-cell">Updated</th>
                <th className="py-2 px-3 text-left font-mono text-xs text-text-muted">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filters.map((filter) => {
                const isOwner = currentUserId !== null && filter.user_id === currentUserId;
                return (
                  <tr key={filter.id} className="border-b border-border last:border-0 font-mono text-xs hover:bg-elevated">
                    <td className="py-2 px-3 text-text font-semibold">
                      <div className="flex items-center gap-1.5">
                        <span className="break-all">{filter.name}</span>
                        {filter.is_pinned && (
                          <AilaBadge severity="info" size="sm">pinned</AilaBadge>
                        )}
                        {filter.shared_with_team && (
                          <AilaBadge severity="neutral" size="sm">shared</AilaBadge>
                        )}
                      </div>
                    </td>
                    <td className="py-2 px-3 text-text-muted">{filter.entity_type}</td>
                    <td className="py-2 px-3 text-text-muted hidden md:table-cell max-w-[280px]">
                      <code className="block truncate bg-base px-2 py-0.5 rounded-[2px]" title={filter.filter_json}>
                        {filter.filter_json}
                      </code>
                    </td>
                    <td className="py-2 px-3 text-text-muted hidden lg:table-cell">
                      <span title={filter.user_id}>{shortUserId(filter.user_id)}</span>
                      {isOwner && (
                        <AilaBadge severity="info" size="sm" className="ml-1.5">you</AilaBadge>
                      )}
                    </td>
                    <td className="py-2 px-3 text-text-muted hidden xl:table-cell whitespace-nowrap">
                      {formatTimestamp(filter.updated_at)}
                    </td>
                    <td className="py-2 px-3">
                      <div className="flex items-center gap-1">
                        <Button
                          size="xs"
                          variant="outline"
                          disabled={!isOwner}
                          title={isOwner ? "Edit filter" : "Only the owner can edit this filter"}
                          onClick={() => setEditing(filter)}
                        >
                          <PencilSimple className="h-3 w-3" />
                        </Button>
                        <Button
                          size="xs"
                          variant="outline"
                          className="text-destructive border-destructive/40 hover:bg-destructive/10 hover:border-destructive disabled:text-text-muted disabled:border-border"
                          disabled={!isOwner}
                          title={isOwner ? "Delete filter" : "Only the owner can delete this filter"}
                          onClick={() => setDeleting(filter)}
                        >
                          <Trash className="h-3 w-3" />
                        </Button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div></AilaCard>
      )}

      {/* Create dialog */}
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

      {/* Edit dialog */}
      <FilterEditorDialog
        mode="edit"
        open={editing !== null}
        initial={editInitial}
        isPending={updateMutation.isPending}
        onSubmit={(form) => {
          if (!editing) return Promise.resolve();
          // Send only fields that may change. entity_type is immutable per
          // SavedFilterUpdate schema, so it's never included.
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

      {/* Delete dialog */}
      <DeleteFilterDialog
        filter={deleting}
        isPending={deleteMutation.isPending}
        onConfirm={(id) => deleteMutation.mutateAsync(id)}
        onClose={() => setDeleting(null)}
      />
    </div>
  );
}
