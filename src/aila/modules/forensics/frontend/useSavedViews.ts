/**
 * useSavedViews -- forensics-local hook over the generic /saved-filters
 * backend (BE-09 / D-41/D-42). Mirrors the ergonomics of vulnerability's
 * useSavedFilters but persists views server-side via authorizedRequestJson
 * so a saved view survives browser reloads and can be shared with the
 * caller's team.
 *
 * Contract (matches src/aila/api/schemas/endpoints.py SavedFilter*):
 *   entity_type identifies the surface (e.g. "forensics_project",
 *   "forensics_investigation"). filter_json is an opaque stringified JSON
 *   blob owned by the caller -- serialize the surface's current
 *   filter/search/sort state on save and JSON.parse it back on apply.
 *
 * All writes invalidate the ["forensics", "saved-views", entityType] key
 * so the list snaps to the freshly-persisted state.
 */
import { useCallback } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { authorizedRequestJson } from "@platform/api/http";
import { useAuthStore } from "@platform/auth/useAuthStore";

// ---------------------------------------------------------------------------
// Types -- mirror src/aila/api/schemas/endpoints.py SavedFilter*
// ---------------------------------------------------------------------------

export interface SavedView {
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

interface SavedViewListEnvelope {
  data: SavedView[];
  meta: PaginatedMeta;
}

interface SavedViewEnvelope {
  data: SavedView;
}

interface SavedViewCreateRequest {
  name: string;
  entity_type: string;
  filter_json: string;
  is_pinned: boolean;
  shared_with_team: boolean;
}

interface SavedViewUpdateRequest {
  name?: string;
  filter_json?: string;
  is_pinned?: boolean;
  shared_with_team?: boolean;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export interface UseSavedViewsReturn<TState> {
  views: SavedView[];
  isLoading: boolean;
  isError: boolean;
  saveCurrent: (
    name: string,
    state: TState,
    opts?: { shared?: boolean; pinned?: boolean },
  ) => Promise<SavedView>;
  updateFilter: (id: string, state: TState) => Promise<SavedView>;
  pin: (id: string, pinned: boolean) => Promise<SavedView>;
  share: (id: string, shared: boolean) => Promise<SavedView>;
  remove: (id: string) => Promise<void>;
  isOwner: (view: SavedView) => boolean;
  parseState: (view: SavedView) => TState | null;
}

export function useSavedViews<TState>(entityType: string): UseSavedViewsReturn<TState> {
  const queryClient = useQueryClient();
  const currentUserId = useAuthStore((s) => s.userId);
  const listKey = ["forensics", "saved-views", entityType] as const;

  const listQuery = useQuery({
    queryKey: listKey,
    queryFn: () =>
      authorizedRequestJson<SavedViewListEnvelope>(
        `/saved-filters?entity_type=${encodeURIComponent(entityType)}&offset=0&limit=100`,
      ),
    // Keep the sidebar snappy: pinned/shared views rarely change out from
    // under the operator, but re-fetch on remount so team edits show up.
    staleTime: 30_000,
  });

  const invalidate = useCallback(() => {
    void queryClient.invalidateQueries({ queryKey: listKey });
  }, [queryClient, listKey]);

  const createMutation = useMutation({
    mutationFn: (req: SavedViewCreateRequest) =>
      authorizedRequestJson<SavedViewEnvelope>("/saved-filters", {
        method: "POST",
        body: req,
      }),
    onSuccess: invalidate,
  });

  const updateMutation = useMutation({
    mutationFn: (args: { id: string; req: SavedViewUpdateRequest }) =>
      authorizedRequestJson<SavedViewEnvelope>(
        `/saved-filters/${encodeURIComponent(args.id)}`,
        { method: "PATCH", body: args.req },
      ),
    onSuccess: invalidate,
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      authorizedRequestJson<void>(
        `/saved-filters/${encodeURIComponent(id)}`,
        { method: "DELETE" },
      ),
    onSuccess: invalidate,
  });

  const saveCurrent = useCallback(
    async (
      name: string,
      state: TState,
      opts?: { shared?: boolean; pinned?: boolean },
    ): Promise<SavedView> => {
      const res = await createMutation.mutateAsync({
        name,
        entity_type: entityType,
        filter_json: JSON.stringify(state),
        is_pinned: opts?.pinned ?? false,
        shared_with_team: opts?.shared ?? false,
      });
      return res.data;
    },
    [createMutation, entityType],
  );

  const updateFilter = useCallback(
    async (id: string, state: TState): Promise<SavedView> => {
      const res = await updateMutation.mutateAsync({
        id,
        req: { filter_json: JSON.stringify(state) },
      });
      return res.data;
    },
    [updateMutation],
  );

  const pin = useCallback(
    async (id: string, pinned: boolean): Promise<SavedView> => {
      const res = await updateMutation.mutateAsync({
        id,
        req: { is_pinned: pinned },
      });
      return res.data;
    },
    [updateMutation],
  );

  const share = useCallback(
    async (id: string, shared: boolean): Promise<SavedView> => {
      const res = await updateMutation.mutateAsync({
        id,
        req: { shared_with_team: shared },
      });
      return res.data;
    },
    [updateMutation],
  );

  const remove = useCallback(
    async (id: string): Promise<void> => {
      await deleteMutation.mutateAsync(id);
    },
    [deleteMutation],
  );

  const isOwner = useCallback(
    (view: SavedView) => currentUserId !== null && view.user_id === currentUserId,
    [currentUserId],
  );

  const parseState = useCallback((view: SavedView): TState | null => {
    // filter_json is caller-controlled JSON. Bad payloads (hand-edited,
    // shape-drifted after a schema change) MUST NOT crash the sidebar --
    // return null and let the caller show a soft-fail badge instead.
    try {
      const parsed = JSON.parse(view.filter_json);
      if (parsed === null || typeof parsed !== "object") return null;
      return parsed as TState;
    } catch {
      return null;
    }
  }, []);

  return {
    views: listQuery.data?.data ?? [],
    isLoading: listQuery.isLoading,
    isError: listQuery.isError,
    saveCurrent,
    updateFilter,
    pin,
    share,
    remove,
    isOwner,
    parseState,
  };
}
