import { useState, useEffect, useCallback } from "react";
import { useLocation } from "react-router-dom";

export interface RecentItem {
  path: string;
  label: string;
  visitedAt: number;
}

const STORAGE_KEY = "aila-recently-viewed";
const MAX_ITEMS = 5;

const EXCLUDED_PATHS = new Set([
  "/login",
  "/auth/callback",
  "/403",
  "/404",
  "/500",
]);

function pathToLabel(pathname: string): string {
  if (pathname === "/") return "Dashboard";
  return pathname
    .replace(/^\/+/, "")
    .split("/")
    .filter(Boolean)
    .map((segment) => {
      if (/^\d+$/.test(segment)) return "Detail";
      return segment
        .split(/[-_]/g)
        .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
        .join(" ");
    })
    .join(" / ");
}

function loadItems(): RecentItem[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (item): item is RecentItem =>
        typeof item === "object" &&
        item !== null &&
        typeof (item as RecentItem).path === "string" &&
        typeof (item as RecentItem).label === "string" &&
        typeof (item as RecentItem).visitedAt === "number",
    );
  } catch {
    return [];
  }
}

function saveItems(items: RecentItem[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(items));
  } catch {
    // localStorage unavailable — ignore
  }
}

function addItem(items: RecentItem[], path: string, label: string): RecentItem[] {
  const now = Date.now();
  // Deduplicate by path, most recent first
  const deduped = items.filter((item) => item.path !== path);
  const updated: RecentItem[] = [{ path, label, visitedAt: now }, ...deduped];
  return updated.slice(0, MAX_ITEMS);
}

interface UseRecentlyViewedReturn {
  items: RecentItem[];
  clearRecent: () => void;
}

export function useRecentlyViewed(): UseRecentlyViewedReturn {
  const location = useLocation();
  const [items, setItems] = useState<RecentItem[]>(loadItems);

  useEffect(() => {
    const { pathname } = location;

    // Skip excluded routes
    if (EXCLUDED_PATHS.has(pathname)) return;

    const label = pathToLabel(pathname);
    setItems((prev) => {
      const updated = addItem(prev, pathname, label);
      saveItems(updated);
      return updated;
    });
  }, [location.pathname]); // eslint-disable-line react-hooks/exhaustive-deps

  const clearRecent = useCallback(() => {
    setItems([]);
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch {
      // ignore
    }
  }, []);

  return { items, clearRecent };
}
