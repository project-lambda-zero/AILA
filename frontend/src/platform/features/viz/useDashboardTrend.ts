/**
 * useDashboardTrend — daily-binned findings trend for the FindingsTrendChart.
 *
 * The platform `/dashboard` endpoint exposes a `module_data` map for module
 * contributions, but no module currently registers a `vulnerability.trend`
 * provider, so reading from that key always returned `[]` and the trend chart
 * always rendered the empty state.
 *
 * To produce a real time series without backend changes, this hook derives a
 * daily bucket count from `created_at` on `/vulnerability/findings` and pads
 * the result to a fixed window so the chart always has continuous x-axis
 * coverage. Pages are walked sequentially up to a hard cap so the hook never
 * fans out into the entire dataset.
 */
import { useQuery } from "@tanstack/react-query";

import { authorizedRequestJson } from "@platform/api/http";

export interface TrendDataPoint {
  date: string;
  count: number;
}

interface FindingRow {
  id: number;
  created_at: string | null;
}

interface FindingsListResponse {
  data: {
    total: number;
    page: number;
    page_size: number;
    pages: number;
    items: FindingRow[];
  };
}

const TREND_WINDOW_DAYS = 30;
const PAGE_SIZE = 250;
const MAX_PAGES = 4; // 1000 findings cap — enough for daily trends without runaway fetches

/** ISO date (YYYY-MM-DD) in the user's local timezone. */
function isoDay(date: Date): string {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, "0");
  const d = String(date.getDate()).padStart(2, "0");
  return `${y}-${m}-${d}`;
}

function buildEmptyWindow(days: number): TrendDataPoint[] {
  const window: TrendDataPoint[] = [];
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  for (let i = days - 1; i >= 0; i -= 1) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    window.push({ date: isoDay(d), count: 0 });
  }
  return window;
}

async function fetchAllFindings(): Promise<FindingRow[]> {
  const collected: FindingRow[] = [];
  for (let page = 1; page <= MAX_PAGES; page += 1) {
    const resp = await authorizedRequestJson<FindingsListResponse>(
      `/vulnerability/findings?page=${page}&page_size=${PAGE_SIZE}`,
    );
    const items = resp.data?.items ?? [];
    collected.push(...items);
    const totalPages = resp.data?.pages ?? 0;
    if (page >= totalPages || items.length === 0) break;
  }
  return collected;
}

/**
 * Derive a 30-day finding-count trend by bucketing `created_at` per day.
 * Returns an empty window when no findings have a valid `created_at`.
 */
function bucketByDay(findings: FindingRow[]): TrendDataPoint[] {
  const window = buildEmptyWindow(TREND_WINDOW_DAYS);
  if (findings.length === 0) return window;

  const indexByDate = new Map<string, number>();
  window.forEach((point, i) => indexByDate.set(point.date, i));

  for (const f of findings) {
    if (!f.created_at) continue;
    const ts = new Date(f.created_at);
    if (Number.isNaN(ts.getTime())) continue;
    const key = isoDay(ts);
    const idx = indexByDate.get(key);
    if (idx !== undefined) {
      window[idx].count += 1;
    }
  }
  return window;
}

export function useDashboardTrend() {
  return useQuery({
    queryKey: ["platform", "dashboard-trend", TREND_WINDOW_DAYS],
    queryFn: async (): Promise<TrendDataPoint[]> => {
      try {
        const findings = await fetchAllFindings();
        return bucketByDay(findings);
      } catch {
        // Surface a real failure as an empty array so FindingsTrendChart
        // can show its empty state instead of a misleading flat-zero line.
        return [];
      }
    },
    staleTime: 60_000,
    retry: 1,
  });
}
