/** List-side state for DataPage: parent scope, filters (client and server),
 * pagination, and the fetched rows. */

import { useEffect, useMemo, useState } from "react";
import type { Dispatch, SetStateAction } from "react";

import { useQueries, useQuery } from "@tanstack/react-query";

import { apiFetch, apiFetchEnvelope } from "../../../api/client";
import { fetchFieldOptions } from "../../../api/mutations";
import type { FieldOption } from "../../../api/mutations";
import { asRecord, readArray, readNum } from "../../../api/parse";
import {
  asList,
  asRange,
  deriveOptions,
  envelopeTotal,
  filterHasValue,
  matchFilter,
  serverFilterQuery,
  toRows,
} from "./rows";
import type { DataRow, FilterValue, PageColumn, PageFilter, PageListConfig } from "./types";

export const PAGE_SIZE = 50;
/** Backend maximum page size, used when fetching every page. */
const FULL_PAGE = 250;

export interface FilterOptions {
  options: FieldOption[];
  loading: boolean;
}

export interface DataRows {
  /** Resolved list endpoint (scope applied); empty while the scope loads. */
  endpoint: string;
  /** Selected parent scope id ("" when the config has no scope). */
  activeScope: string;
  scopeParents: DataRow[];
  setScope: (id: string) => void;
  isLoading: boolean;
  isError: boolean;
  error: Error | null;
  /** Every fetched row, before client-side filters. */
  allRows: DataRow[];
  /** The rows to render (filtered, and sliced when paging client-side). */
  rows: DataRow[];
  total: number;
  columns: PageColumn[];
  numericFields: Set<string>;
  page: number;
  pageCount: number;
  setPage: Dispatch<SetStateAction<number>>;
  filterVals: Record<string, FilterValue>;
  setFilter: (name: string, value: string) => void;
  toggleFilter: (name: string, value: string) => void;
  setRangeFilter: (name: string, key: "lo" | "hi", value: string) => void;
  optionsFor: (f: PageFilter) => FilterOptions;
}

function initialFilters(filters: PageFilter[]): Record<string, FilterValue> {
  const init: Record<string, FilterValue> = {};
  for (const f of filters) {
    if (f.defaultValue != null && (f.type === "text" || f.type === "select" || f.type === "segmented")) {
      init[f.name] = f.defaultValue;
    }
  }
  return init;
}

export function useDataRows(config: PageListConfig): DataRows {
  const filters = config.filters ?? [];
  // Some list endpoints require a parent scope (e.g. /malware/families needs
  // ?workspace_id=). Resolve the first available parent id, then scope the URL.
  const scopeFrom = config.scopeFrom;
  const scopeQ = useQuery({
    queryKey: ["datapage-scope", scopeFrom?.endpoint ?? ""],
    queryFn: () => apiFetch<unknown>(scopeFrom?.endpoint ?? ""),
    enabled: Boolean(scopeFrom),
    retry: false,
  });
  const scopeIdField = scopeFrom?.idField ?? "id";
  const scopeParents = useMemo(
    () => (scopeFrom ? toRows(scopeQ.data, scopeFrom.endpoint.includes("items") ? "items" : undefined) : []),
    [scopeFrom, scopeQ.data],
  );
  const [scopeSel, setScopeSel] = useState("");
  const activeScope = scopeFrom ? scopeSel || String(scopeParents[0]?.[scopeIdField] ?? "") : "";
  const scopedEndpoint = !scopeFrom
    ? config.endpoint
    : !activeScope
      ? ""
      : config.endpoint.includes("{scope}")
        ? config.endpoint.replace("{scope}", encodeURIComponent(activeScope))
        : `${config.endpoint}?${scopeFrom.param ?? "id"}=${encodeURIComponent(activeScope)}`;
  const waitingForScope = Boolean(scopeFrom) && !scopedEndpoint && scopeQ.isLoading;

  // fetchAllPages pages through every page and merges the items arrays so
  // client-side filters + pagination see the full dataset. Server pagination
  // sends page/page_size (or offset/limit) and reads the envelope total.
  const fetchAllPages = Boolean(config.fetchAllPages);
  const pagination = Boolean(config.pagination);
  const offsetParams = config.paginationParams === "offset";
  const serverPaged = pagination && !fetchAllPages;
  const [page, setPage] = useState<number>(1);

  // One active value per configured filter. Any change resets to page 1.
  const [filterVals, setFilterVals] = useState<Record<string, FilterValue>>(() => initialFilters(filters));
  const setFilter = (name: string, value: string): void => {
    setFilterVals((cur) => ({ ...cur, [name]: value }));
    setPage(1);
  };
  const toggleFilter = (name: string, value: string): void => {
    setFilterVals((cur) => {
      const set = new Set(asList(cur[name]));
      if (set.has(value)) set.delete(value);
      else set.add(value);
      return { ...cur, [name]: [...set] };
    });
    setPage(1);
  };
  const setRangeFilter = (name: string, key: "lo" | "hi", value: string): void => {
    setFilterVals((cur) => ({ ...cur, [name]: { ...asRange(cur[name]), [key]: value } }));
    setPage(1);
  };
  const pageUrl = (endpoint: string, n: number, size: number): string => {
    const sep = endpoint.includes("?") ? "&" : "?";
    return offsetParams
      ? `${endpoint}${sep}offset=${(n - 1) * size}&limit=${size}`
      : `${endpoint}${sep}page=${n}&page_size=${size}`;
  };
  // Server-side filters go to the endpoint as query params so the backend
  // narrows the full dataset. Inputs are debounced ~250ms so a text search
  // issues one request per pause, not one per keystroke.
  const [debouncedVals, setDebouncedVals] = useState<Record<string, FilterValue>>({});
  useEffect(() => {
    const t = setTimeout(() => setDebouncedVals(filterVals), 250);
    return () => clearTimeout(t);
  }, [filterVals]);
  const serverQS = useMemo(() => serverFilterQuery(config.filters ?? [], debouncedVals), [config.filters, debouncedVals]);
  const endpoint =
    serverQS && scopedEndpoint ? `${scopedEndpoint}${scopedEndpoint.includes("?") ? "&" : "?"}${serverQS}` : scopedEndpoint;

  // Filters that source options from a live endpoint. `useQueries` takes the
  // variable-length list in one hook call, so it stays rule-of-hooks safe.
  const optionFilters = useMemo(() => (config.filters ?? []).filter((f) => f.optionsFrom), [config.filters]);
  const optionResults = useQueries({
    queries: optionFilters.map((f) => ({
      queryKey: ["filter-options", f.optionsFrom ?? "", f.optionsValueField ?? "", f.optionsLabelField ?? ""],
      queryFn: (): Promise<FieldOption[]> =>
        fetchFieldOptions({ endpoint: f.optionsFrom, valueField: f.optionsValueField, labelField: f.optionsLabelField }),
      staleTime: 30_000,
    })),
  });

  const itemsKey = config.itemsKey ?? "items";
  const fetchPage = serverPaged ? page : 1;
  const q = useQuery({
    queryKey: ["datapage", endpoint, fetchPage],
    queryFn: async () => {
      const firstUrl = pageUrl(endpoint, fetchPage, serverPaged ? PAGE_SIZE : FULL_PAGE);
      // Offset-paginated endpoints report the true total in a sibling `meta`
      // object; apiFetch unwraps to `data` and drops it, so read the full
      // envelope there and let toRows find rows under `data`.
      const first = await (serverPaged && offsetParams ? apiFetchEnvelope<unknown>(firstUrl) : apiFetch<unknown>(firstUrl));
      const firstObj = fetchAllPages ? asRecord(first) : null;
      const pages = firstObj ? readNum(firstObj, "pages") ?? 1 : 1;
      if (!firstObj || pages <= 1) return first;
      const rest = await Promise.all(
        Array.from({ length: pages - 1 }, (_, i) => apiFetch<unknown>(pageUrl(endpoint, i + 2, FULL_PAGE))),
      );
      const restObjs = rest.map((p) => asRecord(p) ?? {});
      const items = [firstObj, ...restObjs].flatMap((p) => readArray(p, itemsKey) ?? []);
      return { ...firstObj, ...restObjs.at(-1), [itemsKey]: items };
    },
    enabled: Boolean(endpoint),
    retry: false,
    refetchInterval: 15000,
  });
  const allRows = useMemo(() => toRows(q.data, config.itemsKey), [q.data, config.itemsKey]);

  // Options: static `options` win, then a live `optionsFrom` list, else the
  // distinct row values of the field (an honest zero-config enum filter).
  const optionsFor = (f: PageFilter): FilterOptions => {
    if (f.options && f.options.length > 0) return { options: f.options, loading: false };
    if (f.optionsFrom) {
      const r = optionResults[optionFilters.indexOf(f)];
      return r ? { options: r.data ?? [], loading: r.isLoading } : { options: [], loading: true };
    }
    return { options: deriveOptions(allRows, f.name), loading: false };
  };

  const filteredRows = useMemo(() => {
    const active = (config.filters ?? []).filter((f) => !f.server && filterHasValue(f, filterVals[f.name]));
    if (active.length === 0) return allRows;
    return allRows.filter((row) => active.every((f) => matchFilter(f, filterVals[f.name], row)));
  }, [allRows, config.filters, filterVals]);

  // fetchAllPages slices the client-side filtered set; server pagination
  // takes `total` from the envelope (or the fetched rows when absent).
  const { rows, total } = useMemo(() => {
    if (fetchAllPages) {
      return { rows: filteredRows.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE), total: filteredRows.length };
    }
    const envTotal = pagination ? envelopeTotal(q.data, PAGE_SIZE, offsetParams) : null;
    return { rows: filteredRows, total: envTotal ?? filteredRows.length };
  }, [fetchAllPages, pagination, offsetParams, filteredRows, page, q.data]);
  const pageCount = pagination ? Math.max(1, Math.ceil(total / PAGE_SIZE)) : 1;

  // A config with no explicit columns derives up to 8 scalar columns from the
  // first row so the table still renders something real.
  const columns = useMemo<PageColumn[]>(() => {
    if (config.columns.length) return config.columns;
    const first = rows[0];
    if (!first) return [];
    return Object.keys(first)
      .filter((k) => first[k] === null || typeof first[k] !== "object")
      .slice(0, 8)
      .map((k) => ({ field: k, label: k.replace(/_/g, " ") }));
  }, [config.columns, rows]);
  // Numeric columns get right alignment + tabular figures. Derived from the
  // first row's value type plus the cost semantic kind.
  const numericFields = useMemo(() => {
    const first = rows[0];
    const out = new Set<string>();
    for (const c of columns) {
      if (c.numeric === true || c.kind === "cost" || (first !== undefined && Number.isFinite(first[c.field]))) out.add(c.field);
    }
    return out;
  }, [columns, rows]);

  return {
    endpoint,
    activeScope,
    scopeParents,
    setScope: setScopeSel,
    isLoading: q.isLoading || waitingForScope,
    isError: q.isError,
    error: q.error,
    allRows,
    rows,
    total,
    columns,
    numericFields,
    page,
    pageCount,
    setPage,
    filterVals,
    setFilter,
    toggleFilter,
    setRangeFilter,
    optionsFor,
  };
}
