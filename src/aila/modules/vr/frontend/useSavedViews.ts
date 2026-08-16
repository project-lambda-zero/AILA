/**
 * VR saved-views hook.
 *
 * Backed by the generic /saved-filters endpoint (BE-09 / D-41/D-42,
 * T-138-17). Each VR list surface picks its own `entityType` string
 * (`vr_investigation`, `vr_finding`, `vr_target`) and stringifies its
 * own filter/search/sort state into `filter_json`; the hook stays
 * shape-agnostic.
 *
 * Mirrors the shell's SavedFiltersPage transport layer (the reference
 * vulnerability module ships a localStorage-only variant that is
 * unavailable to sibling modules -- imports across module frontends
 * are forbidden by the workspace layout, so this is a LOCAL copy of
 * that pattern wired to the real backend).
 *
 * TanStack Query: one list query per entity type; every mutation
 * invalidates that key so the chip row re-renders in place.
 */
import { useCallback } from "react";
import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";

import { authorizedRequestJson } from "@platform/api/http";

// ---------------------------------------------------------------------------
// Wire types -- mirror src/aila/api/schemas/endpoints.py SavedFilter*
// ---------------------------------------------------------------------------

export interface SavedView {
  id: string;
  user_id: string;
  name: string;
  entity_type: string;
  /** Stringified JSON. Callers parse per surface. */
  filter_json: string;
  is_pinned: boolean;
  shared_with_team: boolean;
  created_at: string;
  updated_at: string;
}

interface SavedViewListEnvelope {
  data: SavedView[];
  meta: { total: number; offset: number; limit: number };
}

interface SavedViewEnvelope {
  data: SavedView;
}

export interface CreateViewInput {
  name: string;
  filter_json: string;
  is_pinned?: boolean;
  shared_with_team?: boolean;
}

export interface UpdateViewInput {
  name?: string;
  filter_json?: string;
  is_pinned?: boolean;
  shared_with_team?: boolean;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export interface UseSavedViewsReturn {
  views: SavedView[];
  isLoading: boolean;
  isError: boolean;
  createView: (input: CreateViewInput) => Promise<SavedView>;
  updateView: (id: string, patch: UpdateViewInput) => Promise<SavedView>;
  deleteView: (id: string) => Promise<void>;
  isMutating: boolean;
}

export function useSavedViews(entityType: string): UseSavedViewsReturn {
  const queryClient = useQueryClient();
  const queryKey = ["vr", "saved-filters", entityType] as const;

  const listQuery = useQuery<SavedViewListEnvelope>({
    queryKey,
    queryFn: () =>
      authorizedRequestJson<SavedViewListEnvelope>(
        // A single user rarely owns more than a handful of views per
        // surface; 100 is comfortably above the practical ceiling and
        // one page keeps the chip row's ordering deterministic.
        `/saved-filters?entity_type=${encodeURIComponent(entityType)}&offset=0&limit=100`,
      ),
    // Views don't self-refresh -- only mutations dirty the list, and
    // each mutation invalidates below.
    staleTime: 60_000,
    retry: false,
    throwOnError: false,
  });

  // Shared invalidator wired to every mutation so the chip row
  // re-renders in place after any create/patch/delete.
  const invalidate = useCallback(() => {
    void queryClient.invalidateQueries({ queryKey });
    // queryKey is a stable per-render tuple whose members are the two
    // deps below; listing it directly confuses the exhaustive-deps
    // linter without changing behavior.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [queryClient, entityType]);

  const createMut = useMutation({
    mutationFn: async (input: CreateViewInput) => {
      const env = await authorizedRequestJson<SavedViewEnvelope>(
        "/saved-filters",
        {
          method: "POST",
          body: {
            name: input.name,
            entity_type: entityType,
            filter_json: input.filter_json,
            is_pinned: input.is_pinned ?? false,
            shared_with_team: input.shared_with_team ?? false,
          },
        },
      );
      return env.data;
    },
    onSuccess: invalidate,
  });

  const updateMut = useMutation({
    mutationFn: async ({
      id,
      patch,
    }: {
      id: string;
      patch: UpdateViewInput;
    }) => {
      const env = await authorizedRequestJson<SavedViewEnvelope>(
        `/saved-filters/${encodeURIComponent(id)}`,
        { method: "PATCH", body: patch },
      );
      return env.data;
    },
    onSuccess: invalidate,
  });

  const deleteMut = useMutation({
    mutationFn: async (id: string) => {
      await authorizedRequestJson<void>(
        `/saved-filters/${encodeURIComponent(id)}`,
        { method: "DELETE" },
      );
    },
    onSuccess: invalidate,
  });

  // updateView re-shapes (id, patch) into the mutation's single-arg
  // object so callers don't have to know the internal shape.
  const updateView = useCallback(
    (id: string, patch: UpdateViewInput) =>
      updateMut.mutateAsync({ id, patch }),
    [updateMut],
  );

  return {
    views: listQuery.data?.data ?? [],
    isLoading: listQuery.isLoading,
    isError: listQuery.isError,
    createView: createMut.mutateAsync,
    updateView,
    deleteView: deleteMut.mutateAsync,
    isMutating:
      createMut.isPending || updateMut.isPending || deleteMut.isPending,
  };
}
