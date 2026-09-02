/** React Query hooks over `GET/PUT /widgets/layout` (req 32).
 *
 * The layout is per-user and stored as a JSON string; the query decodes it to
 * a `WidgetLayout` (falling back to the default), and the mutation serializes a
 * layout back and primes the cache so the host + editor stay in lockstep. */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "../../api/client";
import { DEFAULT_LAYOUT, parseLayout, serializeLayout } from "./layout";
import type { WidgetLayout } from "./types";

interface WidgetLayoutResponse {
  user_id: string;
  layout_json: string;
  updated_at: string;
}

const LAYOUT_KEY = ["widgets", "layout"] as const;

export function useWidgetLayout() {
  return useQuery({
    queryKey: LAYOUT_KEY,
    queryFn: async (): Promise<WidgetLayout> => {
      const res = await apiFetch<WidgetLayoutResponse>("/widgets/layout");
      return parseLayout(res?.layout_json ?? null);
    },
    staleTime: 30_000,
  });
}

export function useSaveWidgetLayout() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (layout: WidgetLayout): Promise<WidgetLayout> => {
      await apiFetch<WidgetLayoutResponse>("/widgets/layout", {
        method: "PUT",
        body: JSON.stringify({ layout_json: serializeLayout(layout) }),
      });
      return layout;
    },
    onSuccess: (layout) => {
      qc.setQueryData(LAYOUT_KEY, layout);
    },
  });
}

export { DEFAULT_LAYOUT };
