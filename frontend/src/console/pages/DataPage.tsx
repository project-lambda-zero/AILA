import { useMemo, useState } from "react";
import type { ChangeEvent, JSX, ReactNode } from "react";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch, API_BASE } from "../../api/client";
import { asRecord, readArray } from "../../api/parse";
import type { ModulePageProps } from "../contract";
import { css } from "../css";
import { semanticCell, StatusBadge } from "./badges";
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

/** A client-side filter control. Filters apply to the fetched rows before
 * render; when the page also sets `fetchAllPages` the filter sees the full
 * dataset and pagination slices the filtered set. For server-paginated pages
 * without fetchAllPages, a filter narrows the current page only (documented
 * limitation -- prefer fetchAllPages for filterable catalogs). */
export interface PageFilter {
  name: string;
  label: string;
  type: "text" | "select";
  options?: { value: string; label: string }[];
}

/** A row-level action rendered in the detail header (and optionally inline).
 * One action = one backend call with {id} substituted from the row. */
export interface PageAction {
  label: string;
  /** HTTP method for the call. */
  method: "POST" | "PATCH" | "PUT" | "DELETE" | "GET";
  /** Endpoint template with `{id}` (and `{scope}`) substituted from the row. */
  endpoint: string;
  /** Optional JSON body template; `{id}`/`{scope}` substitute like the path. */
  body?: Record<string, unknown>;
  /** Only show/enable when the row's status field matches one of these
   * (lowercased compare). Empty means always available. */
  whenStatus?: string[];
  /** Confirmation prompt before firing (destructive or irreversible). */
  confirm?: string;
  /** Show the action only when the row is in this state -- used with
   * whenStatus to render a contextual "resume" instead of "pause", etc. */
  destructive?: boolean;
  /** GET + open the substituted URL in a new tab (server streams a file). */
  download?: boolean;
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

function ctlBtn(label: string, title: string, onClick: () => void): JSX.Element {
  return (
    <button
      type="button"
      title={title}
      onClick={onClick}
      style={css(
        "width:30px;flex:0 0 auto;display:flex;align-items:center;justify-content:center;border:0;border-left:1px solid var(--border-soft);background:transparent;color:var(--text-muted);cursor:pointer;font-family:inherit;font-size:12px;",
      )}
    >
      {label}
    </button>
  );
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
  const { config, configKey, onNewClick, onRowActivate, detailBody, onBack, onMinimize, isFullscreen, onToggleFullscreen, onOpenPage } = props;
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
  // Client-side filters: one active value per configured filter. Text matches
  // by substring (case-insensitive); select matches exactly.
  const [filterVals, setFilterVals] = useState<Record<string, string>>({});
  const setFilter = (name: string, value: string): void => {
    setFilterVals((cur) => ({ ...cur, [name]: value }));
    setPage(1);
  };
  const pageUrl = (endpoint: string, page: number, pageSize: number): string => {
    const sep = endpoint.includes("?") ? "&" : "?";
    if (pagParams === "offset") {
      return `${endpoint}${sep}offset=${(page - 1) * pageSize}&limit=${pageSize}`;
    }
    return `${endpoint}${sep}page=${page}&page_size=${pageSize}`;
  };
  const q = useQuery({
    queryKey: ["datapage", effectiveEndpoint, pagination && !fetchAllPages ? page : 1],
    queryFn: async () => {
      const first = (await apiFetch<unknown>(pageUrl(effectiveEndpoint, pagination && !fetchAllPages ? page : 1, pagination && !fetchAllPages ? PAGE_SIZE : 250))) as Record<string, unknown>;
      if (!fetchAllPages) return first;
      const pages = typeof first?.pages === "number" ? first.pages : 1;
      if (pages <= 1) return first;
      const rest = await Promise.all(
        Array.from({ length: pages - 1 }, (_, i) =>
          apiFetch<unknown>(pageUrl(effectiveEndpoint, i + 2, 250)),
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
  // Client-side filter pass. Every configured filter narrows the fetched
  // rows; the result feeds both the table and (with fetchAllPages) the
  // client-side pagination slice.
  const filteredRows = useMemo(() => {
    const active = (config.filters ?? []).filter((f) => (filterVals[f.name] ?? "").trim() !== "");
    if (active.length === 0) return allRows;
    return allRows.filter((row) =>
      active.every((f) => {
        const needle = filterVals[f.name].trim().toLowerCase();
        const hay = row[f.name];
        if (f.type === "select") return String(hay ?? "") === filterVals[f.name];
        return String(hay ?? "").toLowerCase().includes(needle);
      }),
    );
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
  const doAction = (a: PageAction, row: Record<string, unknown> | null): void => {
    if (a.download) {
      const url = a.endpoint
        .replace("{scope}", encodeURIComponent(activeScope))
        .replace("{id}", encodeURIComponent(String(row?.[idField] ?? "")));
      window.open(`${API_BASE}${url.startsWith("/") ? url : `/${url}`}`, "_blank", "noopener");
      return;
    }
    if (a.confirm && !window.confirm(a.confirm)) return;
    const sub = (s: string): string =>
      s
        .replace("{scope}", encodeURIComponent(activeScope))
        .replace("{id}", encodeURIComponent(String(row?.[idField] ?? "")));
    const body: Record<string, unknown> | undefined = a.body
      ? Object.fromEntries(Object.entries(a.body).map(([k, v]) => [k, typeof v === "string" ? sub(v) : v]))
      : undefined;
    action.mutate({ path: sub(a.endpoint), method: a.method, body });
  };
  const visibleActions = (row: Record<string, unknown>): PageAction[] =>
    (config.actions ?? []).filter((a) => {
      if (!a.whenStatus || a.whenStatus.length === 0) return true;
      const status = String(row["status"] ?? row["is_active"] ?? "").toLowerCase();
      return a.whenStatus.includes(status);
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
      <table style={css("width:100%;border-collapse:collapse;font-size:11px;")}>
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
                        "position:sticky;top:0;text-align:left;padding:7px 10px;background:var(--surface-chrome);border-bottom:1px solid var(--border);font-size:8.5px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);white-space:nowrap;z-index:1;",
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
                        `cursor:pointer;border-bottom:1px solid var(--border-faint);${active ? "background:color-mix(in srgb,var(--accent) 12%,transparent);" : ""}`,
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
                      {columns.map((c) => (
                        <td
                          key={c.field}
                          style={css(
                            "padding:6px 10px;color:var(--text-primary);max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;",
                          )}
                        >
                          {c.render ? c.render(row[c.field], row) : c.kind ? semanticCell(c.kind, row[c.field]) : cellText(row[c.field])}
                        </td>
                      ))}
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
            {config.filters?.map((f) =>
              f.type === "select" ? (
                <select
                  key={f.name}
                  value={filterVals[f.name] ?? ""}
                  onChange={(e: ChangeEvent<HTMLSelectElement>) => setFilter(f.name, e.target.value)}
                  style={css("background:var(--surface-sunk);border:1px solid var(--border-soft);color:var(--text-muted);font-family:var(--font-mono);font-size:11px;padding:3px 8px;border-radius:2px;max-width:180px;text-transform:none;letter-spacing:normal;cursor:pointer;")}
                >
                  <option value="">{f.label}</option>
                  {(f.options ?? []).map((o) => (
                    <option key={o.value} value={o.value}>{o.label}</option>
                  ))}
                </select>
              ) : (
                <input
                  key={f.name}
                  type="text"
                  value={filterVals[f.name] ?? ""}
                  onChange={(e: ChangeEvent<HTMLInputElement>) => setFilter(f.name, e.target.value)}
                  placeholder={f.label}
                  style={css("background:var(--surface-sunk);border:1px solid var(--border-soft);color:var(--text-muted);font-family:var(--font-mono);font-size:11px;padding:3px 8px;border-radius:2px;max-width:160px;text-transform:none;letter-spacing:normal;")}
                />
              ),
            )}
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
                <span style={css("font-size:10px;color:var(--text-faint);text-transform:none;letter-spacing:0.03em;")}>page {page} / {pageCount} \u00b7 {total} total</span>
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

  return (
    <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", background: "transparent", fontFamily: "var(--font-mono)", color: "var(--text-primary)" }}>
      <main style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>{body}</main>
      <footer style={{ flex: "0 0 24px", height: 24, display: "flex", alignItems: "stretch", background: "var(--surface-chrome)", borderTop: "2px solid var(--border)", fontSize: 9.5, letterSpacing: "0.1em", textTransform: "uppercase", color: "var(--text-faint)" }}>
        <span style={{ display: "flex", alignItems: "center", padding: "0 11px", background: "var(--status-ok)", color: "var(--text-on-accent)", fontWeight: 700, letterSpacing: "0.14em" }}>{config.title}</span>
        {config.blurb ? (
          <span style={{ display: "flex", alignItems: "center", padding: "0 11px", textTransform: "none", letterSpacing: "0.03em", color: "var(--text-muted)" }}>{config.blurb}</span>
        ) : null}
        <span style={{ flex: 1 }} />
        <span style={{ display: "flex", alignItems: "center", padding: "0 11px", textTransform: "none" }}>{rows.length} records</span>
        {onToggleFullscreen ? ctlBtn(isFullscreen ? "\u2921" : "\u2922", isFullscreen ? "exit fullscreen" : "fullscreen", onToggleFullscreen) : null}
        {ctlBtn("\u2014", "minimize", onMinimize)}
        {ctlBtn("\u2715", "close", onBack)}
      </footer>
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
    </div>
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
