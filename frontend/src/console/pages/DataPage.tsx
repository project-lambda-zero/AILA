import { useEffect, useMemo, useState } from "react";
import type { ChangeEvent, JSX, ReactNode } from "react";

import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch, apiFetchEnvelope, API_BASE } from "../../api/client";
import { fetchFieldOptions } from "../../api/mutations";
import type { FieldOption } from "../../api/mutations";
import { asRecord, readArray } from "../../api/parse";
import type { ModulePageProps } from "../contract";
import { css } from "../css";
import { ConsoleWindow } from "../window";
import { semanticCell, statusRailColor, StatusBadge } from "./badges";
import { EventTimeline } from "./EventTimeline";
import FieldForm from "./FieldForm";
import type { FormSpec } from "./FieldForm";
import { CREATE_FORMS, EDIT_FORMS } from "./formSpecs";
import StructuredValue from "./StructuredValue";

/** A column projected from a list row. `render` overrides the default cell
 * text; `kind` selects a shared semantic renderer (status/severity/time/cost)
 * from badges.tsx. */
export interface PageColumn {
  field: string;
  label: string;
  kind?: "status" | "severity" | "time" | "cost";
  render?: (value: unknown, row: Record<string, unknown>) => ReactNode;
}

/** A filter control rendered under the page title. Filters apply to the
 * fetched rows before render; when the page also sets `fetchAllPages` the
 * filter sees the full dataset and pagination slices the filtered set. For
 * server-paginated pages without fetchAllPages, a client-side filter narrows
 * the current page only (documented limitation -- prefer fetchAllPages, or
 * `server: true` where the backend supports the param). */
export interface PageFilter {
  /** Row field the filter narrows; MUST be a rendered column so the control
   * always acts on visible data. For date/numeric ranges this is the field
   * compared; for server filters it is also the query-param base name. */
  name: string;
  label: string;
  /** text = case-insensitive substring; select = exact match (single);
   * multi-select = row value in the chosen set; segmented = exact match via a
   * button group; date-range = two ISO date inputs (inclusive of the end
   * day); numeric-range = two numeric bounds (inclusive). */
  type: "text" | "select" | "multi-select" | "segmented" | "date-range" | "numeric-range";
  /** Static options for select / multi-select / segmented. When omitted AND
   * `optionsFrom` is unset, the option list is derived from the distinct row
   * values of `name` in the fetched set (honest zero-config enum filter). */
  options?: { value: string; label: string }[];
  /** Source options from a live list endpoint (select / multi-select /
   * segmented), mirroring FormSpec.optionsFrom. Rows map to {value,label} via
   * `optionsValueField` / `optionsLabelField` (default id-like / name-like).
   * Overrides row-derived options; static `options` win over both. */
  optionsFrom?: string;
  optionsValueField?: string;
  optionsLabelField?: string;
  /** When true, the value is sent to the endpoint as a query param instead of
   * narrowing fetched rows client-side; the backend applies it across the full
   * dataset and returns the true `meta.total`, so it composes with server
   * pagination. Param encoding by type: text/select/segmented -> `name=value`;
   * multi-select -> repeated `name=v1&name=v2`; date-range ->
   * `name_since` / `name_until`; numeric-range -> `name_min` / `name_max`.
   * Inputs are debounced ~250ms. */
  server?: boolean;
}

/** A two-ended range value (date-range / numeric-range). `lo` is
 * since/min, `hi` is until/max. */
type RangeVal = { lo: string; hi: string };
/** The runtime value held for one filter: a scalar (text/select/segmented),
 * a set (multi-select), or a range (date-range/numeric-range). */
type FilterValue = string | string[] | RangeVal;

const asScalar = (v: FilterValue | undefined): string => (typeof v === "string" ? v : "");
const asList = (v: FilterValue | undefined): string[] => (Array.isArray(v) ? v : []);
const asRange = (v: FilterValue | undefined): RangeVal =>
  v != null && typeof v === "object" && !Array.isArray(v) ? v : { lo: "", hi: "" };

/** True when the filter currently holds a narrowing value. */
function filterHasValue(f: PageFilter, v: FilterValue | undefined): boolean {
  if (f.type === "multi-select") return asList(v).length > 0;
  if (f.type === "date-range" || f.type === "numeric-range") {
    const r = asRange(v);
    return r.lo.trim() !== "" || r.hi.trim() !== "";
  }
  return asScalar(v).trim() !== "";
}

/** Distinct non-empty row values for a field, as {value,label} options. */
function deriveOptions(rows: Record<string, unknown>[], field: string): FieldOption[] {
  const seen = new Set<string>();
  for (const row of rows) {
    const raw = row[field];
    if (raw === null || raw === undefined || typeof raw === "object") continue;
    const s = String(raw);
    if (s !== "") seen.add(s);
  }
  return [...seen].sort().map((v) => ({ value: v, label: v }));
}

/** Whether a single row passes one client-side filter. */
function matchFilter(f: PageFilter, v: FilterValue | undefined, row: Record<string, unknown>): boolean {
  const cell = row[f.name];
  if (f.type === "multi-select") {
    const sel = asList(v);
    return sel.length === 0 || sel.includes(String(cell ?? ""));
  }
  if (f.type === "numeric-range") {
    const r = asRange(v);
    const n = Number(cell);
    if (!Number.isFinite(n)) return false;
    if (r.lo.trim() !== "" && n < Number(r.lo)) return false;
    if (r.hi.trim() !== "" && n > Number(r.hi)) return false;
    return true;
  }
  if (f.type === "date-range") {
    const r = asRange(v);
    const t = Date.parse(String(cell ?? ""));
    if (Number.isNaN(t)) return false;
    if (r.lo.trim() !== "") {
      const loT = Date.parse(r.lo);
      if (!Number.isNaN(loT) && t < loT) return false;
    }
    if (r.hi.trim() !== "") {
      const hiT = Date.parse(r.hi);
      // Date inputs yield a bare day at UTC midnight; include the whole hi day.
      if (!Number.isNaN(hiT) && t > hiT + 86_399_999) return false;
    }
    return true;
  }
  const needle = asScalar(v).trim();
  if (f.type === "select" || f.type === "segmented") return String(cell ?? "") === needle;
  return String(cell ?? "").toLowerCase().includes(needle.toLowerCase());
}

/** One field collected in an action's pre-flight modal. Deliberately small:
 * an action body is a handful of scalars, not a full record -- that is what
 * the typed create/edit FormSpec is for. */
export interface ActionField {
  /** Body key the value is sent under. */
  name: string;
  label: string;
  /** Widget: `text` (default), `textarea` (multi-line, e.g. a revoke reason),
   * `number`, `select` (needs `options`), or `tags` (sent as a string[], e.g.
   * approver_ids). */
  type?: "text" | "textarea" | "number" | "select" | "tags";
  /** Choices for a `select` field. */
  options?: FieldOption[];
  placeholder?: string;
  required?: boolean;
  /** Prefill the field from this row field when the action opens on a row. */
  fromRow?: string;
}

/** One-shot reveal of an action's JSON response, shown once in a modal after
 * success -- for secrets the server never returns again. */
export interface ActionReveal {
  title?: string;
  /** Response keys to surface, in order. Empty -> the whole payload. */
  fields?: string[];
  /** Caption above the payload (e.g. "copy now -- not shown again"). */
  note?: string;
}

/** A row-level action rendered in the detail header (and optionally inline).
 * One action = one backend call with {id} substituted from the row. */
export interface PageAction {
  label: string;
  /** HTTP method for the call. */
  method: "POST" | "PATCH" | "PUT" | "DELETE" | "GET";
  /** Endpoint template with `{id}` (and `{scope}`) substituted from the row. */
  endpoint: string;
  /** Optional JSON body template; `{id}`/`{scope}` substitute like the path.
   * Values collected via `fields` merge OVER this template. */
  body?: Record<string, unknown>;
  /** Only show/enable when the gate field matches one of these (lowercased
   * compare). Empty means always available. The gate field is `whenField`
   * when set, else the row's `status` (with `is_active` fallback). */
  whenStatus?: string[];
  /** Row field the `whenStatus` gate reads. Defaults to `status`/`is_active`.
   * Set to gate on another state column (e.g. `approval_state`,
   * `analysis_state`). */
  whenField?: string;
  /** Confirmation prompt before firing (destructive or irreversible). Skipped
   * when `fields` is set -- the collection modal is the explicit confirm. */
  confirm?: string;
  /** Tone the control as destructive (warn color). */
  destructive?: boolean;
  /** GET + open the substituted URL in a new tab (server streams a file). */
  download?: boolean;
  /** Fields collected from the operator in a small pre-flight modal before the
   * call fires. Collected values are serialized (number -> Number, tags ->
   * string[], else string) and merged over `body`, then sent as the JSON
   * body. Use where the endpoint requires operator input (e.g. a revoke
   * `reason`, a promote `approver_ids`). */
  fields?: ActionField[];
  /** When set, the call's JSON response is shown once in a modal after
   * success (e.g. a freshly minted API key). */
  reveal?: ActionReveal;
}

/** Declarative config for a backend-backed list window. One of these per nav
 * item gives us a readable, real-data page without a bespoke component. */
export interface PageConfig {
  /** Window title shown in the footer. */
  title: string;
  /** GET path relative to the API root; envelope `{data}` is unwrapped. */
  endpoint: string;
  /** Table columns (subset of the row's fields). */
  columns: PageColumn[];
  /** Key under which the array lives when the response is an object
   * (e.g. "items", "findings"). Auto-detected from common keys otherwise. */
  itemsKey?: string;
  /** Row identity for React keys + selection. Defaults to "id". */
  idField?: string;
  /** Empty-state copy. */
  empty?: string;
  /** One-line description shown under the title. */
  blurb?: string;
  /** For endpoints that REQUIRE a parent scope. Resolve parents from
   * `scopeFrom.endpoint` and render a picker. If `config.endpoint` contains
   * `{scope}` the id is substituted into the path; otherwise it is appended as
   * `?<param>=<id>`. `labelField` names the option label (default idField). */
  scopeFrom?: { endpoint: string; param?: string; idField?: string; labelField?: string };
  /** DELETE endpoint template with `{id}` (and `{scope}`). Enables "delete". */
  delete?: string;
  /** When set, the query pages through every page (backend max 250/page)
   * and concatenates `items`, so client-side filters + pagination see the
   * full dataset (e.g. the 273-row config registry). */
  fetchAllPages?: boolean;
  /** Client-side filters rendered under the title. Each filter narrows the
   * fetched rows by substring (text) or exact match (select). */
  filters?: PageFilter[];
  /** Row-level actions rendered in the detail header. Each fires one backend
   * call with {id}/{scope} substituted; `whenStatus` gates by row status. */
  actions?: PageAction[];
  /** Page-level actions rendered in the filter bar (no row context): e.g.
   * "mark all read", "re-probe", "drain queue". */
  pageActions?: PageAction[];
  /** Bulk actions rendered in a bar when rows are selected. Each fires the
   * action once per selected row (the generic DataPage has no atomic bulk
   * endpoint), reporting per-row success/error. */
  bulkActions?: PageAction[];
  /** Server-side pagination chrome (prev/next, page N of M, total). Page size
   * is 50 and `page`/`page_size` are sent to the endpoint, which must return
   * a `total` (or `pages`) in the envelope. With `fetchAllPages` set,
   * pagination slices the client-side filtered full set instead. When the
   * endpoint paginates by `offset`/`limit` (and reports total in a `meta`
   * object or top-level), set `paginationParams: "offset"` to send
   * `offset`/`limit` and read `meta.total`. */
  pagination?: boolean;
  paginationParams?: "page" | "offset";
  /** Per-field custom detail renderers (keyed by row field). When present for a
   * field, the detail panel uses it instead of the generic <StructuredValue>
   * (e.g. the LLM-log prompt/response rendered as a chat transcript). */
  detailRenderers?: Record<string, (value: unknown, row: Record<string, unknown>) => ReactNode>;
  /** Detail fields that link out to another registered window. Keyed by the
   * detail field name; the value names the target section (moduleKey is this
   * page's module). Renders the field as a clickable "open" chip in the
   * detail grid, handing the row's id to onOpenPage. */
  detailLinks?: Record<string, { module?: string; section: string; label?: string }>;
  /** Event timeline shown under the detail grid. `endpoint` is fetched with
   * `{id}` substituted from the row; the envelope is a paginated list
   * ({items: [{created_at, stage, action, status, ...}], total}) like
   * /audit/events. Renders newest-first with semantic status badges. */
  detailEvents?: { endpoint: string; itemsKey?: string };
}

const ROW_KEYS = ["items", "results", "rows", "entries", "records", "data", "findings", "investigations", "targets", "workspaces"];

const wrap = (arr: unknown[]): Record<string, unknown>[] =>
  arr.map((x) => asRecord(x) ?? { value: x });

function toRows(data: unknown, itemsKey?: string): Record<string, unknown>[] {
  if (Array.isArray(data)) return wrap(data);
  const obj = asRecord(data);
  if (obj) {
    const preferred = itemsKey ? readArray(obj, itemsKey) : null;
    if (preferred) return wrap(preferred);
    for (const k of ROW_KEYS) {
      const arr = readArray(obj, k);
      if (arr) return wrap(arr);
    }
    return [obj];
  }
  return [];
}

function cellText(v: unknown): string {
  if (v === null || v === undefined) return "\u2014";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  if (Array.isArray(v)) return v.length ? `[${v.length}]` : "\u2014";
  const obj = asRecord(v);
  if (obj) {
    // Inline object summary for TABLE cells: never a raw JSON blob.
    // Detail panels use <StructuredValue> to render the actual shape.
    const n = Object.keys(obj).length;
    return n === 0 ? "\u2014" : `{${n} field${n === 1 ? "" : "s"}}`;
  }
  return String(v);
}

/** Turn a reveal action's response payload into ordered [label, value] pairs
 * for the one-shot reveal modal. Named `reveal.fields` win; otherwise every
 * top-level key of the payload object is shown. */
function revealEntries(r: { action: PageAction; payload: unknown }): [string, string][] {
  const obj = asRecord(r.payload);
  if (!obj) {
    const s = typeof r.payload === "string" ? r.payload : JSON.stringify(r.payload, null, 2);
    return [["result", s]];
  }
  const want = r.action.reveal?.fields;
  const keys = want && want.length > 0 ? want : Object.keys(obj);
  return keys.map((k) => {
    const v = obj[k];
    const s =
      v == null
        ? "\u2014"
        : typeof v === "string"
          ? v
          : typeof v === "number" || typeof v === "boolean"
            ? String(v)
            : JSON.stringify(v);
    return [k, s] as [string, string];
  });
}

export default function DataPage(
  props: ModulePageProps & {
    config: PageConfig;
    /** Registry key (`${moduleId}:${pageId}`) used to look up the matching
     * typed create/edit form. Every registry entry passes this explicitly;
     * without it, DataPage has no way to reach the correct form. */
    configKey: string;
    /** When set, the "+ new" button opens this instead of the typed form
     * modal (targets create is a multipart upload wizard, not a field form). */
    onNewClick?: () => void;
    /** When set, a row click opens a dedicated window (e.g. a forensics
     * project detail) instead of toggling the in-window detail panel. */
    onRowActivate?: (row: Record<string, unknown>) => void;
    /** When set, the in-window detail panel's body is this renderer instead
     * of the generic field grid. Receives the selected row. Used for
     * drill-down panels (e.g. a target row's investigations). */
    detailBody?: (row: Record<string, unknown>) => ReactNode;
  },
): JSX.Element {
  const { config, configKey, onNewClick, onRowActivate, detailBody, onBack, onMinimize, isFullscreen, onToggleFullscreen, onOpenPage, windowId, title: windowTitle, isFocused, onFocus } = props;
  const createSpec: FormSpec | undefined = (CREATE_FORMS as Record<string, FormSpec>)[configKey];
  const editSpec: FormSpec | undefined = (EDIT_FORMS as Record<string, FormSpec>)[configKey];
  const idField = config.idField ?? "id";
  // Some list endpoints require a parent scope (e.g. /malware/families needs
  // ?workspace_id=). Resolve the first available parent id, then scope the URL.
  const scopeQ = useQuery({
    queryKey: ["datapage-scope", config.scopeFrom?.endpoint ?? ""],
    queryFn: () => apiFetch<unknown>(config.scopeFrom!.endpoint),
    enabled: Boolean(config.scopeFrom),
    retry: false,
  });
  const scopeIdField = config.scopeFrom?.idField ?? "id";
  const scopeParents = useMemo(
    () => (config.scopeFrom ? toRows(scopeQ.data, config.scopeFrom.endpoint.includes("items") ? "items" : undefined) : []),
    [config.scopeFrom, scopeQ.data],
  );
  const [scopeSel, setScopeSel] = useState("");
  const activeScope = config.scopeFrom
    ? scopeSel || (scopeParents[0] ? String(scopeParents[0][scopeIdField] ?? "") : "")
    : "";
  const effectiveEndpoint = config.scopeFrom
    ? activeScope
      ? config.endpoint.includes("{scope}")
        ? config.endpoint.replace("{scope}", encodeURIComponent(activeScope))
        : `${config.endpoint}?${config.scopeFrom.param ?? "id"}=${encodeURIComponent(activeScope)}`
      : ""
    : config.endpoint;
  const waitingForScope = Boolean(config.scopeFrom) && !effectiveEndpoint && scopeQ.isLoading;
  // fetchAllPages: page through every page (backend max 250/page) and merge
  // the items arrays, so client-side filters + pagination see the full
  // dataset. The envelope shape ({items, pages, ...}) is preserved for
  // toRows, which reads config.itemsKey.
  const fetchAllPages = Boolean(config.fetchAllPages);
  // Server-side pagination chrome: when set, `page`/`page_size` go to the
  // endpoint and the envelope must carry `total` (or `pages`). With
  // fetchAllPages, the full set is fetched once and the page slices the
  // (possibly filtered) rows client-side instead.
  const pagination = Boolean(config.pagination);
  const pagParams = config.paginationParams ?? "page";
  const PAGE_SIZE = 50;
  const [page, setPage] = useState<number>(1);
  // One active value per configured filter. Scalars for text/select/segmented,
  // a string[] for multi-select, a {lo,hi} range for date/numeric ranges. Any
  // change resets pagination to page 1.
  const [filterVals, setFilterVals] = useState<Record<string, FilterValue>>({});
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
  const pageUrl = (endpoint: string, page: number, pageSize: number): string => {
    const sep = endpoint.includes("?") ? "&" : "?";
    if (pagParams === "offset") {
      return `${endpoint}${sep}offset=${(page - 1) * pageSize}&limit=${pageSize}`;
    }
    return `${endpoint}${sep}page=${page}&page_size=${pageSize}`;
  };
  // Server-side filters (filter.server === true) are sent to the endpoint as
  // query params so the backend narrows the full dataset and reports the true
  // meta.total. Debounce the raw input values ~250ms so a text search issues
  // one request per pause, not one per keystroke; selects ride the same delay.
  const [debouncedVals, setDebouncedVals] = useState<Record<string, FilterValue>>({});
  useEffect(() => {
    const t = setTimeout(() => setDebouncedVals(filterVals), 250);
    return () => clearTimeout(t);
  }, [filterVals]);
  const serverQS = useMemo(() => {
    const parts: string[] = [];
    const enc = encodeURIComponent;
    for (const f of config.filters ?? []) {
      if (!f.server) continue;
      const v = debouncedVals[f.name];
      if (f.type === "multi-select") {
        for (const item of asList(v)) {
          const s = item.trim();
          if (s) parts.push(`${enc(f.name)}=${enc(s)}`);
        }
      } else if (f.type === "date-range" || f.type === "numeric-range") {
        const r = asRange(v);
        const lo = r.lo.trim();
        const hi = r.hi.trim();
        const loSuf = f.type === "date-range" ? "since" : "min";
        const hiSuf = f.type === "date-range" ? "until" : "max";
        if (lo) parts.push(`${enc(f.name)}_${loSuf}=${enc(lo)}`);
        if (hi) parts.push(`${enc(f.name)}_${hiSuf}=${enc(hi)}`);
      } else {
        const s = asScalar(v).trim();
        if (s) parts.push(`${enc(f.name)}=${enc(s)}`);
      }
    }
    return parts.join("&");
  }, [config.filters, debouncedVals]);
  const queryEndpoint = serverQS && effectiveEndpoint
    ? `${effectiveEndpoint}${effectiveEndpoint.includes("?") ? "&" : "?"}${serverQS}`
    : effectiveEndpoint;
  // Filters that source their option list from a live endpoint. `useQueries`
  // handles the variable-length list in one hook call, so option fetches stay
  // rule-of-hooks safe regardless of how many filters a config declares.
  const optionFilters = useMemo(
    () => (config.filters ?? []).filter((f) => f.optionsFrom),
    [config.filters],
  );
  const optionResults = useQueries({
    queries: optionFilters.map((f) => ({
      queryKey: ["filter-options", f.optionsFrom ?? "", f.optionsValueField ?? "", f.optionsLabelField ?? ""],
      queryFn: (): Promise<FieldOption[]> =>
        fetchFieldOptions({ endpoint: f.optionsFrom, valueField: f.optionsValueField, labelField: f.optionsLabelField }),
      staleTime: 30_000,
    })),
  });
  const dynamicOptions: Record<string, { options: FieldOption[]; loading: boolean }> = {};
  optionFilters.forEach((f, i) => {
    dynamicOptions[f.name] = {
      options: optionResults[i]?.data ?? [],
      loading: optionResults[i]?.isLoading ?? false,
    };
  });
  const q = useQuery({
    queryKey: ["datapage", queryEndpoint, pagination && !fetchAllPages ? page : 1],
    queryFn: async () => {
      const firstUrl = pageUrl(queryEndpoint, pagination && !fetchAllPages ? page : 1, pagination && !fetchAllPages ? PAGE_SIZE : 250);
      // Offset-paginated endpoints report the true total in a sibling `meta`
      // object ({data, meta}); apiFetch unwraps to `data` and drops it, so read
      // the full envelope for that path and let toRows find rows under `data`.
      const first = (await (pagination && !fetchAllPages && pagParams === "offset"
        ? apiFetchEnvelope<unknown>(firstUrl)
        : apiFetch<unknown>(firstUrl))) as Record<string, unknown>;
      if (!fetchAllPages) return first;
      const pages = typeof first?.pages === "number" ? first.pages : 1;
      if (pages <= 1) return first;
      const rest = await Promise.all(
        Array.from({ length: pages - 1 }, (_, i) =>
          apiFetch<unknown>(pageUrl(queryEndpoint, i + 2, 250)),
        ),
      );
      const merged = (rest as Record<string, unknown>[]).reduce<Record<string, unknown>>(
        (acc, p) => {
          const items = readArray(p, config.itemsKey ?? "items") ?? [];
          const accItems = readArray(acc, config.itemsKey ?? "items") ?? [];
          return { ...p, [config.itemsKey ?? "items"]: [...accItems, ...items] };
        },
        { ...first },
      );
      return merged;
    },
    enabled: Boolean(effectiveEndpoint),
    retry: false,
    refetchInterval: 15000,
  });
  const allRows = useMemo(() => toRows(q.data, config.itemsKey), [q.data, config.itemsKey]);
  // Options for an option-bearing filter: static `options` win, then a live
  // `optionsFrom` list, else the distinct row values of the field (so a bare
  // `{type:"select"}` becomes an honest enum filter with no backend coupling).
  const optionsFor = (f: PageFilter): { options: FieldOption[]; loading: boolean } => {
    if (f.options && f.options.length > 0) return { options: f.options, loading: false };
    if (f.optionsFrom) return dynamicOptions[f.name] ?? { options: [], loading: true };
    return { options: deriveOptions(allRows, f.name), loading: false };
  };
  // Client-side filter pass. Every non-server filter narrows the fetched rows;
  // the result feeds both the table and (with fetchAllPages) the client-side
  // pagination slice.
  const filteredRows = useMemo(() => {
    const active = (config.filters ?? []).filter((f) => !f.server && filterHasValue(f, filterVals[f.name]));
    if (active.length === 0) return allRows;
    return allRows.filter((row) => active.every((f) => matchFilter(f, filterVals[f.name], row)));
  }, [allRows, config.filters, filterVals]);
  // Effective row set + total for display. fetchAllPages: the page slices the
  // client-side filtered set. Server pagination: rows come from the backend
  // and `total` comes from the envelope (or the fetched rows when absent).
  const { rows, total } = useMemo(() => {
    if (fetchAllPages) {
      const slice = filteredRows.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
      return { rows: slice, total: filteredRows.length };
    }
    if (pagination) {
      const envTotal = (() => {
        const obj = asRecord(q.data);
        if (!obj) return null;
        if (typeof obj["total"] === "number") return obj["total"];
        if (typeof obj["pages"] === "number") return obj["pages"] * PAGE_SIZE;
        // offset/limit endpoints report total inside a `meta` object
        // (e.g. VR findings: DataEnvelope[list] with meta{total,offset,limit}).
        if (pagParams === "offset") {
          const meta = asRecord(obj["meta"]);
          if (meta && typeof meta["total"] === "number") return meta["total"];
        }
        return null;
      })();
      return { rows: filteredRows, total: envTotal ?? filteredRows.length };
    }
    return { rows: filteredRows, total: filteredRows.length };
  }, [fetchAllPages, pagination, filteredRows, page, q.data]);
  const pageCount = pagination ? Math.max(1, Math.ceil(total / PAGE_SIZE)) : 1;
  // When a config ships no explicit columns (endpoints whose row shape we don't
  // hard-code), derive up to 8 scalar columns from the first row so the table
  // still renders something real.
  const columns = useMemo<PageColumn[]>(() => {
    if (config.columns.length) return config.columns;
    const first = rows[0];
    if (!first) return [];
    return Object.keys(first)
      .filter((k) => {
        const v = first[k];
        return v === null || typeof v !== "object";
      })
      .slice(0, 8)
      .map((k) => ({ field: k, label: k.replace(/_/g, " ") }));
  }, [config.columns, rows]);
  // Numeric columns get right alignment + monospace tabular figures so counts
  // and costs form clean vertical rulers the eye can scan. Derived from the
  // first row's value type plus the cost semantic kind.
  const numericFields = useMemo(() => {
    const first = rows[0];
    return new Set(
      columns
        .filter((c) => c.kind === "cost" || (first !== undefined && typeof first[c.field] === "number"))
        .map((c) => c.field),
    );
  }, [columns, rows]);
  const [sel, setSel] = useState<Record<string, unknown> | null>(null);
  // Which form is open (if any) and the row it's editing (null for create).
  const [formMode, setFormMode] = useState<"create" | "edit" | null>(null);

  // ---- delete only (create/update belong in real typed wizards) --------
  const qc = useQueryClient();
  const del = useMutation({
    mutationFn: (path: string) => apiFetch<unknown>(path, { method: "DELETE" }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["datapage", effectiveEndpoint] });
      setSel(null);
    },
  });
  const doDelete = (row: Record<string, unknown>): void => {
    if (!config.delete) return;
    if (!window.confirm("Delete this row? This cannot be undone.")) return;
    const path = config.delete
      .replace("{scope}", encodeURIComponent(activeScope))
      .replace("{id}", encodeURIComponent(String(row[idField] ?? "")));
    del.mutate(path);
  };

  // ---- row actions (PageAction) -----------------------------------------
  const action = useMutation({
    mutationFn: ({ path, method, body }: { path: string; method: string; body?: Record<string, unknown> }) =>
      apiFetch<unknown>(path, {
        method,
        headers: body ? { "Content-Type": "application/json" } : undefined,
        body: body ? JSON.stringify(body) : undefined,
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["datapage", effectiveEndpoint] });
    },
  });
  // Action-body collection + one-shot reveal state. `actionForm` holds the
  // action awaiting operator input (with its target row); `actionVals` are the
  // in-progress field values; `reveal` holds a completed action's response to
  // show once.
  const [actionForm, setActionForm] = useState<{ action: PageAction; row: Record<string, unknown> | null } | null>(null);
  const [actionVals, setActionVals] = useState<Record<string, string>>({});
  const [actionErr, setActionErr] = useState<string | null>(null);
  const [reveal, setReveal] = useState<{ action: PageAction; payload: unknown } | null>(null);
  const [copied, setCopied] = useState(false);

  // Fire one action call: path + static body substituted, collected `extra`
  // merged over the body, response captured when the action declares a reveal.
  const fireAction = (a: PageAction, row: Record<string, unknown> | null, extra?: Record<string, unknown>): void => {
    const sub = (s: string): string =>
      s
        .replace("{scope}", encodeURIComponent(activeScope))
        .replace("{id}", encodeURIComponent(String(row?.[idField] ?? "")));
    const base: Record<string, unknown> = a.body
      ? Object.fromEntries(Object.entries(a.body).map(([k, v]) => [k, typeof v === "string" ? sub(v) : v]))
      : {};
    const merged = { ...base, ...(extra ?? {}) };
    const body = Object.keys(merged).length > 0 ? merged : undefined;
    action.mutate(
      { path: sub(a.endpoint), method: a.method, body },
      a.reveal
        ? {
            onSuccess: (data: unknown) => {
              setReveal({ action: a, payload: data });
              setCopied(false);
            },
          }
        : undefined,
    );
  };

  const doAction = (a: PageAction, row: Record<string, unknown> | null): void => {
    if (a.download) {
      const url = a.endpoint
        .replace("{scope}", encodeURIComponent(activeScope))
        .replace("{id}", encodeURIComponent(String(row?.[idField] ?? "")));
      window.open(`${API_BASE}${url.startsWith("/") ? url : `/${url}`}`, "_blank", "noopener");
      return;
    }
    if (a.fields && a.fields.length > 0) {
      // Prefill declared fields from the row, then collect the rest in a modal
      // whose submit is the explicit confirm.
      const init: Record<string, string> = {};
      for (const f of a.fields) {
        if (f.fromRow && row && row[f.fromRow] != null) init[f.name] = String(row[f.fromRow]);
      }
      setActionVals(init);
      setActionErr(null);
      setActionForm({ action: a, row });
      return;
    }
    if (a.confirm && !window.confirm(a.confirm)) return;
    fireAction(a, row);
  };

  // Serialize the collected action fields (number/tags/string) and fire.
  const submitActionForm = (): void => {
    if (!actionForm) return;
    const { action: a, row } = actionForm;
    const out: Record<string, unknown> = {};
    for (const f of a.fields ?? []) {
      const s = (actionVals[f.name] ?? "").trim();
      if (s === "") {
        if (f.required) {
          setActionErr(`${f.label} is required`);
          return;
        }
        continue;
      }
      if (f.type === "number") {
        const n = Number(s);
        if (Number.isNaN(n)) {
          setActionErr(`${f.label} must be a number`);
          return;
        }
        out[f.name] = n;
      } else if (f.type === "tags") {
        out[f.name] = s.split(/[\s,]+/).filter(Boolean);
      } else {
        out[f.name] = s;
      }
    }
    setActionForm(null);
    fireAction(a, row, out);
  };

  const copyReveal = (v: string): void => {
    void navigator.clipboard?.writeText(v);
    setCopied(true);
  };
  const visibleActions = (row: Record<string, unknown>): PageAction[] =>
    (config.actions ?? []).filter((a) => {
      if (!a.whenStatus || a.whenStatus.length === 0) return true;
      const gate = a.whenField ? row[a.whenField] : (row["status"] ?? row["is_active"]);
      return a.whenStatus.includes(String(gate ?? "").toLowerCase());
    });

  // ---- bulk selection ----------------------------------------------------
  // One set of selected row identities (idField values). Checkboxes in the
  // first column toggle membership; the bulk bar fires each bulk action once
  // per selected row via doAction, reporting per-row errors.
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkResults, setBulkResults] = useState<string | null>(null);
  const toggleRow = (row: Record<string, unknown>): void => {
    const id = String(row[idField] ?? "");
    if (!id) return;
    setSelected((cur) => {
      const next = new Set(cur);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };
  const toggleAll = (): void => {
    setSelected((cur) => {
      if (cur.size === rows.length && rows.every((r) => cur.has(String(r[idField] ?? "")))) return new Set();
      return new Set(rows.map((r) => String(r[idField] ?? "")).filter(Boolean));
    });
  };
  const doBulk = async (a: PageAction): Promise<void> => {
    if (selected.size === 0) return;
    if (a.confirm && !window.confirm(`${a.confirm} (${selected.size} rows)`)) return;
    setBulkResults(null);
    const ids = Array.from(selected);
    const failures: string[] = [];
    for (const id of ids) {
      const row = rows.find((r) => String(r[idField] ?? "") === id);
      if (!row) continue;
      try {
        await action.mutateAsync({ path: a.endpoint.replace("{id}", encodeURIComponent(id)), method: a.method, body: a.body });
      } catch {
        failures.push(id);
      }
    }
    setBulkResults(failures.length === 0 ? `done: ${ids.length} rows` : `${ids.length - failures.length}/${ids.length} ok, failed: ${failures.join(", ")}`);
    setSelected(new Set());
  };

  // The list panel (header + "+ new" + row count) renders in every state so an
  // empty resource can still create its first record. Only the scroll area
  // swaps between loading / error / empty note and the table.
  const listInner: JSX.Element =
    q.isLoading || waitingForScope ? (
      <div style={emptyNote}>loading&#8230;</div>
    ) : q.isError ? (
      <div style={emptyNote}>could not load {config.endpoint} &mdash; {q.error instanceof Error ? q.error.message : "request failed"}</div>
    ) : rows.length === 0 ? (
      <div style={emptyNote}>{config.empty ?? "no records."}</div>
    ) : (
      <table className="dp-table" style={css("width:100%;border-collapse:collapse;font-size:11px;")}>
              <thead>
                <tr>
                  {config.bulkActions && config.bulkActions.length > 0 ? (
                    <th
                      style={css("position:sticky;top:0;z-index:1;background:var(--surface-sunk);padding:6px 8px;text-align:left;font-size:9px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);font-weight:400;width:28px;")}
                    >
                      <input
                        type="checkbox"
                        checked={rows.length > 0 && rows.every((r) => selected.has(String(r[idField] ?? "")))}
                        onChange={toggleAll}
                        title="select all rows on this page"
                      />
                    </th>
                  ) : null}
                  {columns.map((c) => (
                    <th
                      key={c.field}
                      style={css(
                        `position:sticky;top:0;text-align:${numericFields.has(c.field) ? "right" : "left"};padding:8px 12px;background:var(--surface-chrome);border-bottom:1px solid color-mix(in srgb,var(--accent) 32%,var(--border));font-family:var(--font-mono);font-size:9px;font-weight:500;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-muted);white-space:nowrap;z-index:1;`,
                      )}
                    >
                      {c.label}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((row, i) => {
                  const key = cellText(row[idField]) + i;
                  const active = sel === row;
                  // Status-toned left ribbon: a continuous vertical rail the eye
                  // follows down the table, encoding each row's state at the
                  // left edge. Rendered as an inset box-shadow (no layout shift)
                  // so hover/active are free to use a background tint. Active
                  // wins the ribbon in accent so the selected row still reads.
                  const rail = active ? "var(--accent)" : statusRailColor(row["status"]) ?? "transparent";
                  return (
                    <tr
                      key={key}
                      onClick={(e) => {
                        const target = e.target as HTMLElement;
                        if (target.tagName === "INPUT") return; // checkbox click handled by its own onChange
                        if (onRowActivate) onRowActivate(row);
                        else setSel((cur) => (cur === row ? null : row));
                      }}
                      style={css(
                        `cursor:pointer;border-bottom:1px solid var(--border-faint);box-shadow:inset 3px 0 0 ${rail};${active ? "background:color-mix(in srgb,var(--accent) 16%,transparent);" : ""}`,
                      )}
                    >
                      {config.bulkActions && config.bulkActions.length > 0 ? (
                        <td style={css("padding:6px 8px;width:28px;")}>
                          <input
                            type="checkbox"
                            checked={selected.has(String(row[idField] ?? ""))}
                            onChange={() => toggleRow(row)}
                            onClick={(e) => e.stopPropagation()}
                          />
                        </td>
                      ) : null}
                      {columns.map((c, ci) => {
                        const isNum = numericFields.has(c.field);
                        const isTitle = ci === 0 && !c.kind;
                        // Title column anchors the row (bright, semibold);
                        // numeric columns get mono tabular figures; everything
                        // else recedes to muted so the eye lands on the anchor
                        // and the status color, not a wall of even text.
                        const emphasis = isTitle
                          ? "color:var(--text-primary);font-weight:600;"
                          : isNum
                            ? "color:var(--text-muted);font-family:var(--font-mono);font-variant-numeric:tabular-nums;"
                            : "color:var(--text-muted);";
                        return (
                          <td
                            key={c.field}
                            style={css(
                              `padding:7px 12px;max-width:${isTitle ? 460 : 320}px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;text-align:${isNum ? "right" : "left"};${emphasis}`,
                            )}
                          >
                            {c.render ? c.render(row[c.field], row) : c.kind ? semanticCell(c.kind, row[c.field]) : cellText(row[c.field])}
                          </td>
                        );
                      })}
                    </tr>
                  );
                })}
              </tbody>
            </table>
    );

  const body: JSX.Element = (
    <div style={css("flex:1;min-height:0;display:flex;gap:10px;padding:12px;")}>
      <div style={css(`flex:${sel ? "1 1 62%" : "1 1 100%"};min-width:0;` + panelBox)}>
        <div style={panelTitle}>
          <span style={dot} />
          <span style={css("color:var(--text-primary);")}>{config.title}</span>
          {config.scopeFrom && scopeParents.length ? (
            <span style={css("display:inline-flex;align-items:center;gap:6px;")}>
              <span style={css("font-size:8.5px;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-faint);")}>scope</span>
              <select
                value={activeScope}
                onChange={(e: ChangeEvent<HTMLSelectElement>) => setScopeSel(e.target.value)}
                style={css("background:var(--surface-sunk);border:1px solid var(--border-soft);color:var(--text-muted);font-family:var(--font-mono);font-size:9px;padding:1px 5px;border-radius:2px;max-width:230px;text-transform:none;letter-spacing:normal;cursor:pointer;")}
              >
                {scopeParents.map((p, i) => {
                  const id = String(p[scopeIdField] ?? "");
                  const label = String(p[config.scopeFrom?.labelField ?? scopeIdField] ?? id);
                  return (
                    <option key={id + i} value={id}>{label}</option>
                  );
                })}
              </select>
            </span>
          ) : null}
          <span style={css("flex:1;")} />
          {onNewClick || createSpec ? (
            <button
              type="button"
              onClick={() => (onNewClick ? onNewClick() : setFormMode("create"))}
              style={css("padding:2px 8px;border:1px solid var(--accent);border-radius:2px;background:transparent;color:var(--accent);font-family:var(--font-mono);font-size:9px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;")}
              title="create a new record"
            >
              + new
            </button>
          ) : null}
          <span style={css("color:var(--text-faint);text-transform:none;letter-spacing:0.04em;")}>{rows.length} rows</span>
        </div>
        {(config.filters && config.filters.length > 0) || pagination ? (
          <div style={css("display:flex;align-items:center;gap:8px;padding:6px 12px;border-bottom:1px solid var(--border-soft);flex-wrap:wrap;")}>
            {config.filters && config.filters.length > 0 ? (
              <span style={css("font-size:10px;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-faint);")}>filter</span>
            ) : null}
            {config.filters?.map((f) => {
              if (f.type === "date-range" || f.type === "numeric-range") {
                const r = asRange(filterVals[f.name]);
                const inputType = f.type === "date-range" ? "date" : "number";
                return (
                  <span key={f.name} style={css("display:inline-flex;align-items:center;gap:4px;")}>
                    <input
                      type={inputType}
                      aria-label={`${f.label} from`}
                      value={r.lo}
                      onChange={(e: ChangeEvent<HTMLInputElement>) => setRangeFilter(f.name, "lo", e.target.value)}
                      style={css(FILTER_CTL + "max-width:130px;")}
                    />
                    <span style={css("color:var(--text-faint);font-size:10px;")}>{"\u2013"}</span>
                    <input
                      type={inputType}
                      aria-label={`${f.label} to`}
                      value={r.hi}
                      onChange={(e: ChangeEvent<HTMLInputElement>) => setRangeFilter(f.name, "hi", e.target.value)}
                      style={css(FILTER_CTL + "max-width:130px;")}
                    />
                  </span>
                );
              }
              if (f.type === "segmented") {
                const { options } = optionsFor(f);
                const cur = asScalar(filterVals[f.name]);
                return (
                  <span key={f.name} role="group" aria-label={f.label} style={css("display:inline-flex;border:1px solid var(--border-soft);border-radius:2px;overflow:hidden;")}>
                    {options.map((o) => {
                      const on = cur === o.value;
                      return (
                        <button
                          key={o.value}
                          type="button"
                          aria-pressed={on}
                          onClick={() => setFilter(f.name, on ? "" : o.value)}
                          style={css(`padding:3px 9px;border:0;border-right:1px solid var(--border-soft);background:${on ? "var(--accent)" : "transparent"};color:${on ? "var(--surface-sunk)" : "var(--text-muted)"};font-family:var(--font-mono);font-size:10px;letter-spacing:0.04em;text-transform:none;cursor:pointer;`)}
                        >
                          {o.label}
                        </button>
                      );
                    })}
                  </span>
                );
              }
              if (f.type === "multi-select") {
                const { options, loading } = optionsFor(f);
                const sel = asList(filterVals[f.name]);
                return (
                  <span key={f.name} role="group" aria-label={f.label} style={css("display:inline-flex;align-items:center;gap:4px;flex-wrap:wrap;")}>
                    <span style={css("font-size:10px;color:var(--text-faint);letter-spacing:0.04em;")}>{f.label}</span>
                    {loading ? <span style={css("font-size:10px;color:var(--text-faint);")}>loading{"\u2026"}</span> : null}
                    {options.map((o) => {
                      const on = sel.includes(o.value);
                      return (
                        <button
                          key={o.value}
                          type="button"
                          aria-pressed={on}
                          onClick={() => toggleFilter(f.name, o.value)}
                          style={css(`padding:2px 7px;border:1px solid ${on ? "var(--accent)" : "var(--border-soft)"};border-radius:2px;background:${on ? "color-mix(in srgb,var(--accent) 18%,transparent)" : "var(--surface-sunk)"};color:${on ? "var(--accent)" : "var(--text-muted)"};font-family:var(--font-mono);font-size:10px;letter-spacing:0.03em;text-transform:none;cursor:pointer;`)}
                        >
                          {o.label}
                        </button>
                      );
                    })}
                  </span>
                );
              }
              if (f.type === "select") {
                const { options, loading } = optionsFor(f);
                return (
                  <select
                    key={f.name}
                    aria-label={f.label}
                    value={asScalar(filterVals[f.name])}
                    onChange={(e: ChangeEvent<HTMLSelectElement>) => setFilter(f.name, e.target.value)}
                    style={css(FILTER_CTL + "max-width:180px;cursor:pointer;")}
                  >
                    <option value="">{loading ? "loading\u2026" : f.label}</option>
                    {options.map((o) => (
                      <option key={o.value} value={o.value}>{o.label}</option>
                    ))}
                  </select>
                );
              }
              return (
                <input
                  key={f.name}
                  type="text"
                  aria-label={f.label}
                  value={asScalar(filterVals[f.name])}
                  onChange={(e: ChangeEvent<HTMLInputElement>) => setFilter(f.name, e.target.value)}
                  placeholder={f.label}
                  style={css(FILTER_CTL + "max-width:160px;")}
                />
              );
            })}
            <span style={css("flex:1;")} />
            {config.pageActions?.map((a) => (
              <button
                key={a.label}
                type="button"
                onClick={() => doAction(a, null)}
                disabled={action.isPending}
                style={css(`padding:4px 10px;border:1px solid ${a.destructive ? H_WARN : "var(--accent)"}66;border-radius:2px;background:transparent;color:${a.destructive ? H_WARN : "var(--accent)"};font-family:var(--font-mono);font-size:10px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;`)}
              >
                {a.label}
              </button>
            ))}
            {pagination ? (
              <span style={css("display:inline-flex;align-items:center;gap:6px;")}>
                <button type="button" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1} style={css("border:0;background:transparent;color:var(--text-muted);cursor:pointer;font-size:11px;")}>{"\u25c0"}</button>
                <span style={css("font-size:10px;color:var(--text-faint);text-transform:none;letter-spacing:0.03em;")}>page {page} / {pageCount} {"\u00b7"} {total} total</span>
                <button type="button" onClick={() => setPage((p) => p + 1)} disabled={page >= pageCount} style={css("border:0;background:transparent;color:var(--text-muted);cursor:pointer;font-size:11px;")}>{"\u25b6"}</button>
              </span>
            ) : null}
          </div>
        ) : null}
        {config.bulkActions && config.bulkActions.length > 0 && selected.size > 0 ? (
          <div style={css("display:flex;align-items:center;gap:8px;padding:6px 12px;border-bottom:1px solid var(--border-soft);background:color-mix(in srgb,var(--accent) 6%,transparent);flex-wrap:wrap;")}>
            <span style={css("font-size:10px;color:var(--accent);letter-spacing:0.06em;text-transform:uppercase;")}>{selected.size} selected</span>
            {config.bulkActions.map((a) => (
              <button
                key={a.label}
                type="button"
                onClick={() => void doBulk(a)}
                disabled={action.isPending}
                style={css(`padding:4px 10px;border:1px solid ${a.destructive ? H_WARN : "var(--accent)"}66;border-radius:2px;background:transparent;color:${a.destructive ? H_WARN : "var(--accent)"};font-family:var(--font-mono);font-size:10px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;`)}
              >
                {a.label}
              </button>
            ))}
            <button
              type="button"
              onClick={() => setSelected(new Set())}
              style={css("padding:3px 8px;border:1px solid var(--border-soft);border-radius:2px;background:transparent;color:var(--text-muted);font-family:var(--font-mono);font-size:10px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;")}
            >
              clear
            </button>
            {bulkResults ? (
              <span style={css("font-size:10px;color:var(--text-muted);")}>{bulkResults}</span>
            ) : null}
          </div>
        ) : null}
        <div style={css("flex:1;min-height:0;overflow:auto;")}>{listInner}</div>
      </div>
      {sel ? (
        <div style={css("flex:1 1 38%;min-width:0;" + panelBox)}>
            <div style={panelTitle}>
              <span style={dot} />
              <span style={css("color:var(--text-primary);")}>detail</span>
              {sel && sel["status"] != null ? (
                <StatusBadge value={sel["status"]} />
              ) : null}
              <span style={css("flex:1;")} />
              {editSpec ? (
                <button
                  type="button"
                  onClick={() => setFormMode("edit")}
                  style={css("padding:3px 10px;border:1px solid var(--accent);border-radius:2px;background:transparent;color:var(--accent);font-family:var(--font-mono);font-size:10px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;")}
                >
                  edit
                </button>
              ) : null}
              {config.delete ? (
                <button type="button" onClick={() => sel && doDelete(sel)} style={css(`padding:3px 10px;border:1px solid ${H_WARN}66;border-radius:2px;background:transparent;color:${H_WARN};font-family:var(--font-mono);font-size:10px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;`)}>delete</button>
              ) : null}
              {sel ? (
                visibleActions(sel).map((a) => (
                  <button
                    key={a.label}
                    type="button"
                    onClick={() => doAction(a, sel)}
                    disabled={action.isPending}
                    style={css(`padding:3px 10px;border:1px solid ${a.destructive ? H_WARN : "var(--accent)"}66;border-radius:2px;background:transparent;color:${a.destructive ? H_WARN : "var(--accent)"};font-family:var(--font-mono);font-size:10px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;`)}
                  >
                    {a.label}
                  </button>
                ))
              ) : null}
              <button type="button" onClick={() => setSel(null)} style={css("background:transparent;border:0;color:var(--text-faint);cursor:pointer;font-size:13px;margin-left:4px;")}>{"\u2715"}</button>
            </div>
            <div style={css("flex:1;min-height:0;overflow:auto;padding:12px 14px;display:grid;grid-template-columns:140px 1fr;gap:6px 12px;font-size:11px;align-content:start;")}>
              {detailBody ? (
                detailBody(sel)
              ) : (
                <>
                  {Object.entries(sel).map(([k, v]) => {
                    const link = config.detailLinks?.[k];
                    const linkVal = link && v != null && String(v) !== "" ? String(v) : null;
                    return (
                      <span key={k} style={{ display: "contents" }}>
                        <span style={css("color:var(--text-faint);letter-spacing:0.04em;word-break:break-word;")}>{k}</span>
                        <span style={css("color:var(--text-primary);word-break:break-word;min-width:0;display:flex;align-items:center;gap:6px;flex-wrap:wrap;")}>
                          {config.detailRenderers?.[k]?.(v, sel) ?? <StructuredValue value={v} />}
                          {linkVal ? (
                            <button
                              type="button"
                              onClick={() => link && onOpenPage?.(link.module ?? "vr", link.section, link.label ?? link.section, linkVal)}
                              title={`open ${link?.section ?? ""} ${linkVal}`}
                              style={css("padding:2px 7px;border:1px solid var(--accent)55;border-radius:2px;background:transparent;color:var(--accent);font-family:var(--font-mono);font-size:9.5px;letter-spacing:0.06em;text-transform:uppercase;cursor:pointer;")}
                            >
                              {"open \u25b8"}
                            </button>
                          ) : null}
                        </span>
                      </span>
                    );
                  })}
                  {config.detailEvents ? (
                    <span style={{ display: "contents" }}>
                      <span style={css("color:var(--text-faint);letter-spacing:0.04em;")}>events</span>
                      <span style={css("min-width:0;")}>
                        <EventTimeline
                          endpoint={config.detailEvents.endpoint.replace(/{([a-zA-Z0-9_]+)}/g, (_m: string, f: string) => encodeURIComponent(String(sel[f] ?? "")))}
                          itemsKey={config.detailEvents.itemsKey}
                        />
                      </span>
                    </span>
                  ) : null}
                </>
              )}
            </div>
          </div>
        ) : null}
      </div>
    );

  const activeSpec: FormSpec | null =
    formMode === "create" ? createSpec ?? null : formMode === "edit" ? editSpec ?? null : null;

  const statusStrip = (
    <>
      <span style={{ display: "flex", alignItems: "center", padding: "0 11px", background: "var(--status-ok)", color: "var(--text-on-accent)", fontWeight: 700, letterSpacing: "0.14em" }}>{config.title}</span>
      {config.blurb ? (
        <span style={{ display: "flex", alignItems: "center", padding: "0 11px", textTransform: "none", letterSpacing: "0.03em", color: "var(--text-muted)" }}>{config.blurb}</span>
      ) : null}
      <span style={{ flex: 1 }} />
      <span style={{ display: "flex", alignItems: "center", padding: "0 11px", textTransform: "none" }}>{rows.length} records</span>
    </>
  );

  return (
    <ConsoleWindow
      id={windowId}
      kind="page"
      title={windowTitle}
      isFullscreen={isFullscreen}
      isFocused={isFocused}
      onFocus={onFocus}
      onClose={onBack}
      onMinimize={onMinimize}
      onToggleFullscreen={onToggleFullscreen}
      footerExtras={statusStrip}
    >
      <main style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>{body}</main>
      {activeSpec ? (
        <div
          role="dialog"
          aria-modal="true"
          onClick={() => setFormMode(null)}
          style={css("position:absolute;inset:0;background:rgba(0,0,0,0.55);display:flex;align-items:center;justify-content:center;padding:32px;z-index:20;")}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={css("width:min(560px,100%);max-height:100%;display:flex;")}
          >
            <FieldForm
              spec={activeSpec}
              initial={formMode === "edit" ? sel : null}
              onDone={() => setFormMode(null)}
              onCancel={() => setFormMode(null)}
              invalidateKey={["datapage", effectiveEndpoint]}
            />
          </div>
        </div>
      ) : null}
      {actionForm ? (
        <div
          role="dialog"
          aria-modal="true"
          aria-label={`${actionForm.action.label} details`}
          onClick={() => setActionForm(null)}
          style={css("position:absolute;inset:0;background:rgba(0,0,0,0.55);display:flex;align-items:center;justify-content:center;padding:32px;z-index:21;")}
        >
          <form
            onClick={(e) => e.stopPropagation()}
            onSubmit={(e) => {
              e.preventDefault();
              submitActionForm();
            }}
            style={css("width:min(460px,100%);max-height:100%;overflow:auto;display:flex;flex-direction:column;gap:12px;padding:18px;background:var(--surface-card);border:1px solid var(--border);border-radius:3px;")}
          >
            <div style={css("font-family:var(--font-mono);font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-primary);")}>{actionForm.action.label}</div>
            {(actionForm.action.fields ?? []).map((f) => (
              <label key={f.name} style={actionLabel}>
                <span>
                  {f.label}
                  {f.required ? " *" : ""}
                </span>
                {f.type === "textarea" ? (
                  <textarea
                    value={actionVals[f.name] ?? ""}
                    placeholder={f.placeholder}
                    onChange={(e: ChangeEvent<HTMLTextAreaElement>) => setActionVals((c) => ({ ...c, [f.name]: e.target.value }))}
                    style={css(ACTION_INPUT + "min-height:64px;resize:vertical;")}
                  />
                ) : f.type === "select" ? (
                  <select
                    value={actionVals[f.name] ?? ""}
                    onChange={(e: ChangeEvent<HTMLSelectElement>) => setActionVals((c) => ({ ...c, [f.name]: e.target.value }))}
                    style={css(ACTION_INPUT + "cursor:pointer;")}
                  >
                    <option value="">{f.placeholder ?? "select\u2026"}</option>
                    {(f.options ?? []).map((o) => (
                      <option key={o.value} value={o.value}>
                        {o.label}
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    type={f.type === "number" ? "number" : "text"}
                    value={actionVals[f.name] ?? ""}
                    placeholder={f.type === "tags" ? f.placeholder ?? "comma or space separated" : f.placeholder}
                    onChange={(e: ChangeEvent<HTMLInputElement>) => setActionVals((c) => ({ ...c, [f.name]: e.target.value }))}
                    style={css(ACTION_INPUT)}
                  />
                )}
              </label>
            ))}
            {actionErr ? <div style={actionErrBox}>{actionErr}</div> : null}
            <div style={css("display:flex;justify-content:flex-end;gap:8px;")}>
              <button type="button" onClick={() => setActionForm(null)} style={actionGhostBtn}>
                cancel
              </button>
              <button type="submit" disabled={action.isPending} style={actionPrimaryBtn}>
                {actionForm.action.label}
              </button>
            </div>
          </form>
        </div>
      ) : null}
      {reveal ? (
        <div
          role="dialog"
          aria-modal="true"
          aria-label={reveal.action.reveal?.title ?? "result"}
          onClick={() => setReveal(null)}
          style={css("position:absolute;inset:0;background:rgba(0,0,0,0.55);display:flex;align-items:center;justify-content:center;padding:32px;z-index:22;")}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={css("width:min(520px,100%);max-height:100%;overflow:auto;display:flex;flex-direction:column;gap:12px;padding:18px;background:var(--surface-card);border:1px solid var(--border);border-radius:3px;")}
          >
            <div style={css("font-family:var(--font-mono);font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-primary);")}>{reveal.action.reveal?.title ?? reveal.action.label}</div>
            {reveal.action.reveal?.note ? (
              <div style={css("font-family:var(--font-mono);font-size:10px;color:var(--status-ok);letter-spacing:0.03em;text-transform:none;")}>{reveal.action.reveal.note}</div>
            ) : null}
            {revealEntries(reveal).map(([k, v]) => (
              <div key={k} style={css("display:flex;flex-direction:column;gap:4px;")}>
                <span style={css("font-family:var(--font-mono);font-size:9px;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-faint);")}>{k}</span>
                <div style={css("display:flex;align-items:flex-start;gap:6px;")}>
                  <code style={css("flex:1;min-width:0;word-break:break-all;background:var(--surface-sunk);border:1px solid var(--border);border-radius:2px;padding:7px 8px;font-family:var(--font-mono);font-size:11px;color:var(--text-primary);")}>{v}</code>
                  <button type="button" onClick={() => copyReveal(v)} style={actionGhostBtn}>
                    {copied ? "copied" : "copy"}
                  </button>
                </div>
              </div>
            ))}
            <div style={css("display:flex;justify-content:flex-end;")}>
              <button type="button" onClick={() => setReveal(null)} style={actionPrimaryBtn}>
                done
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </ConsoleWindow>
  );
}

const emptyNote = css(
  "flex:1;display:flex;align-items:center;justify-content:center;padding:20px;font-family:var(--font-mono);font-size:11px;color:var(--text-faint);letter-spacing:0.04em;text-align:center;",
);
const panelBox = ";min-height:0;display:flex;flex-direction:column;border:1px solid var(--border);border-radius:var(--radius-md,3px);background:color-mix(in srgb,var(--surface-card) 84%,transparent);overflow:hidden;box-shadow:var(--bevel-raised,inset 1px 1px 0 rgba(255,255,255,0.03));";
const panelTitle = css(
  "flex:0 0 auto;display:flex;align-items:center;gap:10px;height:var(--panel-title-h,27px);padding:0 12px;background:var(--surface-chrome);border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:9.5px;text-transform:uppercase;letter-spacing:0.14em;color:var(--text-muted);",
);
const dot = css("width:8px;height:8px;border-radius:1px;background:var(--accent);box-shadow:0 0 6px var(--accent);flex:0 0 auto;");
const H_WARN = "#ffb85f";
const FILTER_CTL =
  "background:var(--surface-sunk);border:1px solid var(--border-soft);color:var(--text-muted);font-family:var(--font-mono);font-size:11px;padding:3px 8px;border-radius:2px;text-transform:none;letter-spacing:normal;";
// Action-body collection modal + one-shot reveal modal styling. ACTION_INPUT
// is a raw string (concatenated per-widget like FILTER_CTL); the rest are
// resolved style objects.
const ACTION_INPUT =
  "background:var(--surface-sunk);border:1px solid var(--border);border-radius:2px;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;padding:6px 8px;letter-spacing:0.02em;text-transform:none;outline:none;";
const actionLabel = css(
  "display:flex;flex-direction:column;gap:4px;font-family:var(--font-mono);font-size:10px;letter-spacing:0.06em;text-transform:uppercase;color:var(--text-muted);",
);
const actionErrBox = css(
  "border:1px solid #ffb85f;border-radius:2px;padding:7px 9px;background:color-mix(in srgb,#ffb85f 12%,transparent);color:#ffb85f;font-family:var(--font-mono);font-size:10px;letter-spacing:0.02em;text-transform:none;",
);
const actionPrimaryBtn = css(
  "padding:6px 14px;border:1px solid var(--accent);background:var(--accent);color:var(--text-on-accent);font-family:var(--font-mono);font-size:10px;letter-spacing:0.1em;text-transform:uppercase;cursor:pointer;border-radius:2px;",
);
const actionGhostBtn = css(
  "padding:6px 12px;border:1px solid var(--border);background:transparent;color:var(--text-muted);font-family:var(--font-mono);font-size:10px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;border-radius:2px;",
);
