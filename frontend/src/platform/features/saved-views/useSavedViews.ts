/**
 * useSavedViews -- shell-local hook for named, persistable filter presets.
 *
 * Backed by /saved-filters (BE-09 / D-41/D-42, T-138-17). Each surface
 * chooses its own `entityType` string ("audit", "system", "task", "scan"…)
 * and its own `TState` shape; `filter_json` is the round-trip serialization
 * of that state. Ownership + team-share visibility are enforced by the
 * router; a caller only sees its own filters plus team-shared filters that
 * live within its team.
 *
 * Mirrors the pattern established by the vulnerability module's own
 * saved-filter hook but talks to the generic backend and is
 * strongly typed against a caller-supplied state shape. Kept shell-local so
 * every high-cardinality shell list can reuse it without importing across
 * module boundaries.
 */
import { useMemo } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { authorizedRequestJson } from "@platform/api/http";

// ---------------------------------------------------------------------------
// Backend types (mirror src/aila/api/schemas/endpoints.py SavedFilter*)
// ---------------------------------------------------------------------------

export interface SavedFilterRecord {
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
  data: SavedFilterRecord[];
  meta: PaginatedMeta;
}

interface SavedFilterEnvelope {
  data: SavedFilterRecord;
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface SavedView<TState> {
  id: string;
  name: string;
  state: TState;
  isPinned: boolean;
  sharedWithTeam: boolean;
  ownedByMe: boolean;
  ownerUserId: string;
  updatedAt: string;
}

export interface CreateViewArgs<TState> {
  name: string;
  state: TState;
  isPinned?: boolean;
  sharedWithTeam?: boolean;
}

export interface PatchViewArgs {
  id: string;
  name?: string;
  isPinned?: boolean;
  sharedWithTeam?: boolean;
  state?: unknown;
}

export interface UseSavedViewsResult<TState> {
  views: SavedView<TState>[];
  pinned: SavedView<TState>[];
  isLoading: boolean;
  isError: boolean;
  error: Error | null;
  isMutating: boolean;
  createView: (args: CreateViewArgs<TState>) => Promise<SavedFilterRecord>;
  patchView: (args: PatchViewArgs) => Promise<SavedFilterRecord>;
  removeView: (id: string) => Promise<void>;
  refetch: () => void;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * List + mutate the current user's saved views for one shell surface.
 *
 * @param entityType arbitrary string chosen per surface -- e.g. "audit",
 *   "system", "task", "scan". Filters are round-tripped through the generic
 *   /saved-filters endpoint using this discriminator.
 * @param currentUserId the caller's user id (from `useAuthStore().userId`).
 *   Used to flag views as `ownedByMe` so read-only shared views hide the
 *   edit/delete controls; passing `null` treats every view as read-only.
 */
export function useSavedViews<TState>(
  entityType: string,
  currentUserId: string | null,
): UseSavedViewsResult<TState> {
  const queryClient = useQueryClient();
  // Query key is stable across renders for the same entity so mutation
  // callbacks can invalidate exactly the surface they belong to.
  const queryKey = ["platform", "saved-views", entityType] as const;

  const listQuery = useQuery({
    queryKey,
    queryFn: () =>
      authorizedRequestJson<SavedFilterListEnvelope>(
        `/saved-filters?entity_type=${encodeURIComponent(entityType)}&offset=0&limit=250`,
      ),
  });

  const createMutation = useMutation({
    mutationFn: (args: CreateViewArgs<TState>) =>
      authorizedRequestJson<SavedFilterEnvelope>("/saved-filters", {
        method: "POST",
        body: {
          name: args.name,
          entity_type: entityType,
          filter_json: JSON.stringify(args.state ?? {}),
          is_pinned: args.isPinned ?? false,
          shared_with_team: args.sharedWithTeam ?? false,
        },
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey });
    },
  });

  const patchMutation = useMutation({
    mutationFn: (args: PatchViewArgs) => {
      const body: Record<string, unknown> = {};
      if (args.name !== undefined) body.name = args.name;
      if (args.isPinned !== undefined) body.is_pinned = args.isPinned;
      if (args.sharedWithTeam !== undefined) body.shared_with_team = args.sharedWithTeam;
      if (args.state !== undefined) body.filter_json = JSON.stringify(args.state);
      return authorizedRequestJson<SavedFilterEnvelope>(`/saved-filters/${args.id}`, {
        method: "PATCH",
        body,
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      authorizedRequestJson<void>(`/saved-filters/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey });
    },
  });

  const views = useMemo<SavedView<TState>[]>(() => {
    const records = listQuery.data?.data ?? [];
    return records.map((record) => {
      // Corrupt filter_json (hand-edited via SavedFiltersPage or an older
      // schema) is surfaced with an empty state so the row can still be
      // deleted or overwritten, but never applied blindly.
      let parsed: TState | null = null;
      try {
        parsed = JSON.parse(record.filter_json) as TState;
      } catch {
        parsed = null;
      }
      return {
        id: record.id,
        name: record.name,
        state: parsed ?? ({} as TState),
        isPinned: record.is_pinned,
        sharedWithTeam: record.shared_with_team,
        ownedByMe: currentUserId !== null && record.user_id === currentUserId,
        ownerUserId: record.user_id,
        updatedAt: record.updated_at,
      };
    });
  }, [listQuery.data, currentUserId]);

  const pinned = useMemo(() => views.filter((v) => v.isPinned), [views]);

  return {
    views,
    pinned,
    isLoading: listQuery.isLoading,
    isError: listQuery.isError,
    error: (listQuery.error as Error | null) ?? null,
    isMutating:
      createMutation.isPending || patchMutation.isPending || deleteMutation.isPending,
    createView: async (args) => (await createMutation.mutateAsync(args)).data,
    patchView: async (args) => (await patchMutation.mutateAsync(args)).data,
    removeView: async (id) => {
      await deleteMutation.mutateAsync(id);
    },
    refetch: () => {
      void listQuery.refetch();
    },
  };
}
