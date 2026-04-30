import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";

import { authorizedRequestJson } from "@platform/api/http";
import { DEFAULT_LAYOUT } from "./widgetRegistry";
import type { SerializedLayout } from "./types";

interface WidgetLayoutResponse {
  user_id: string;
  layout_json: string;
  updated_at: string;
}

interface DataEnvelope<T> {
  data: T;
  meta?: Record<string, unknown>;
}

const LAYOUT_QUERY_KEY = ["dashboard", "layout"] as const;

function parseLayout(raw: string): SerializedLayout | null {
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (
      parsed &&
      typeof parsed === "object" &&
      "version" in parsed &&
      "items" in parsed &&
      Array.isArray((parsed as SerializedLayout).items) &&
      (parsed as SerializedLayout).items.length > 0
    ) {
      return parsed as SerializedLayout;
    }
  } catch {
    // fall through to null
  }
  return null;
}

/**
 * Loads the user's dashboard layout from the backend.
 * Falls back to DEFAULT_LAYOUT when the backend returns a default (no saved layout)
 * or when the stored JSON is missing/empty.
 */
export function useWidgetLayout() {
  const result = useQuery({
    queryKey: LAYOUT_QUERY_KEY,
    queryFn: async () => {
      const response = await authorizedRequestJson<DataEnvelope<WidgetLayoutResponse>>(
        "/widgets/layout",
      );

      const isDefault = response.meta?.is_default === true;
      if (isDefault) {
        return DEFAULT_LAYOUT;
      }

      const parsed = parseLayout(response.data.layout_json);
      return parsed ?? DEFAULT_LAYOUT;
    },
  });

  return {
    layout: result.data ?? DEFAULT_LAYOUT,
    isLoading: result.isLoading,
    isError: result.isError,
    error: result.error,
  };
}

/**
 * Saves the user's dashboard layout to the backend via PUT /widgets/layout.
 * Invalidates the layout query on success to keep the cache fresh.
 */
export function useSaveLayout() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (layout: SerializedLayout) =>
      authorizedRequestJson<DataEnvelope<WidgetLayoutResponse>>("/widgets/layout", {
        method: "PUT",
        body: { layout_json: JSON.stringify(layout) },
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: LAYOUT_QUERY_KEY });
    },
  });
}
