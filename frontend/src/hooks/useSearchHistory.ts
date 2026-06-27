import { useState, useCallback } from "react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SearchHistoryItem {
  query: string;
  searchedAt: number;
}

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

const STORAGE_KEY = "aila-search-history";
const MAX_ITEMS = 10;

function loadHistory(): SearchHistoryItem[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (item): item is SearchHistoryItem =>
        typeof item === "object" &&
        item !== null &&
        typeof (item as SearchHistoryItem).query === "string" &&
        typeof (item as SearchHistoryItem).searchedAt === "number",
    );
  } catch {
    return [];
  }
}

function saveHistory(items: SearchHistoryItem[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(items));
  } catch {
    // localStorage unavailable -- ignore
  }
}

function addToHistory(
  items: SearchHistoryItem[],
  query: string,
): SearchHistoryItem[] {
  const now = Date.now();
  const trimmed = query.trim();
  if (!trimmed) return items;
  // Deduplicate by query (case-insensitive), most recent first
  const deduped = items.filter(
    (item) => item.query.toLowerCase() !== trimmed.toLowerCase(),
  );
  const updated: SearchHistoryItem[] = [
    { query: trimmed, searchedAt: now },
    ...deduped,
  ];
  return updated.slice(0, MAX_ITEMS);
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

interface UseSearchHistoryReturn {
  items: SearchHistoryItem[];
  addSearch: (query: string) => void;
  clearHistory: () => void;
}

/**
 * useSearchHistory -- persist and retrieve search history from localStorage.
 *
 * Used by CommandPalette to show recent searches in the empty-query state.
 * Records a search entry when the user selects a search result.
 */
export function useSearchHistory(): UseSearchHistoryReturn {
  const [items, setItems] = useState<SearchHistoryItem[]>(loadHistory);

  const addSearch = useCallback((query: string) => {
    setItems((prev) => {
      const updated = addToHistory(prev, query);
      saveHistory(updated);
      return updated;
    });
  }, []);

  const clearHistory = useCallback(() => {
    setItems([]);
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch {
      // ignore
    }
  }, []);

  return { items, addSearch, clearHistory };
}
