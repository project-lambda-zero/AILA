import { useMemo, useState } from "react";
import type { ChangeEvent, JSX, ReactNode } from "react";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "../../api/client";
import { asRecord, readArray } from "../../api/parse";
import type { ModulePageProps } from "../contract";
import { css } from "../css";
import FieldForm from "./FieldForm";
import type { FormSpec } from "./FieldForm";
import { CREATE_FORMS, EDIT_FORMS } from "./formSpecs";
import StructuredValue from "./StructuredValue";

/** A column projected from a list row. `render` overrides the default cell text. */
export interface PageColumn {
  field: string;
  label: string;
  render?: (value: unknown, row: Record<string, unknown>) => ReactNode;
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
   * and concatenates `items`. For endpoints whose full row set exceeds the
   * default 50-row page (e.g. the 273-row config registry) -- the DataPage
   * grid has no pagination chrome, so without this the tail rows silently
   * never render. */
  fetchAllPages?: boolean;
  /** Per-field custom detail renderers (keyed by row field). When present for a
   * field, the detail panel uses it instead of the generic <StructuredValue>
   * (e.g. the LLM-log prompt/response rendered as a chat transcript). */
  detailRenderers?: Record<string, (value: unknown, row: Record<string, unknown>) => ReactNode>;
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
  const { config, configKey, onNewClick, onRowActivate, detailBody, onBack, onMinimize, isFullscreen, onToggleFullscreen } = props;
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
  // the items arrays, so a grid without pagination chrome still shows the
  // full dataset. The envelope shape ({items, pages, ...}) is preserved for
  // toRows, which reads config.itemsKey.
  const fetchAllPages = Boolean(config.fetchAllPages);
  const pageUrl = (endpoint: string, page: number): string => {
    const sep = endpoint.includes("?") ? "&" : "?";
    return `${endpoint}${sep}page=${page}&page_size=250`;
  };
  const q = useQuery({
    queryKey: ["datapage", effectiveEndpoint],
    queryFn: async () => {
      const first = (await apiFetch<unknown>(pageUrl(effectiveEndpoint, 1))) as Record<string, unknown>;
      if (!fetchAllPages) return first;
      const pages = typeof first?.pages === "number" ? first.pages : 1;
      if (pages <= 1) return first;
      const rest = await Promise.all(
        Array.from({ length: pages - 1 }, (_, i) =>
          apiFetch<unknown>(pageUrl(effectiveEndpoint, i + 2)),
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
  const rows = useMemo(() => toRows(q.data, config.itemsKey), [q.data, config.itemsKey]);
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
                      onClick={() => (onRowActivate ? onRowActivate(row) : setSel((cur) => (cur === row ? null : row)))}
                      style={css(
                        `cursor:pointer;border-bottom:1px solid var(--border-faint);${active ? "background:color-mix(in srgb,var(--accent) 12%,transparent);" : ""}`,
                      )}
                    >
                      {columns.map((c) => (
                        <td
                          key={c.field}
                          style={css(
                            "padding:6px 10px;color:var(--text-primary);max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;",
                          )}
                        >
                          {c.render ? c.render(row[c.field], row) : cellText(row[c.field])}
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
        <div style={css("flex:1;min-height:0;overflow:auto;")}>{listInner}</div>
      </div>
      {sel ? (
        <div style={css("flex:1 1 38%;min-width:0;" + panelBox)}>
            <div style={panelTitle}>
              <span style={dot} />
              <span style={css("color:var(--text-primary);")}>detail</span>
              <span style={css("flex:1;")} />
              {editSpec ? (
                <button
                  type="button"
                  onClick={() => setFormMode("edit")}
                  style={css("padding:2px 8px;border:1px solid var(--accent);border-radius:2px;background:transparent;color:var(--accent);font-family:var(--font-mono);font-size:9px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;")}
                >
                  edit
                </button>
              ) : null}
              {config.delete ? (
                <button type="button" onClick={() => sel && doDelete(sel)} style={css(`padding:2px 8px;border:1px solid ${H_WARN}66;border-radius:2px;background:transparent;color:${H_WARN};font-family:var(--font-mono);font-size:9px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;`)}>delete</button>
              ) : null}
              <button type="button" onClick={() => setSel(null)} style={css("background:transparent;border:0;color:var(--text-faint);cursor:pointer;font-size:12px;margin-left:4px;")}>{"\u2715"}</button>
            </div>
            <div style={css("flex:1;min-height:0;overflow:auto;padding:11px 13px;display:grid;grid-template-columns:130px 1fr;gap:6px 10px;font-size:10.5px;align-content:start;")}>
              {detailBody ? (
                detailBody(sel)
              ) : (
                Object.entries(sel).map(([k, v]) => (
                  <span key={k} style={{ display: "contents" }}>
                    <span style={css("color:var(--text-faint);letter-spacing:0.04em;word-break:break-word;")}>{k}</span>
                    <span style={css("color:var(--text-primary);word-break:break-word;min-width:0;")}>
                      {config.detailRenderers?.[k]?.(v, sel) ?? <StructuredValue value={v} />}
                    </span>
                  </span>
                ))
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
