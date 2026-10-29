/** Declarative DataPage contracts. A page config is composed from focused
 * parts (list, actions, detail, create) so each DataPage component reads only
 * the slice it renders. */

import type { ReactNode } from "react";

import type { FieldOption } from "../../../api/mutations";
import type { ColumnKind } from "../badges";

/** One row from a configured list endpoint. DataPage renders arbitrary
 * backend collections, so a row is an open JSON object whose cells are
 * narrowed at the render site (cellText, semanticCell, StructuredValue). */
export type DataRow = Record<string, unknown>;

/** A column projected from a list row. `render` overrides the default cell
 * text; `kind` selects a shared semantic renderer (status/severity/time/cost)
 * from badges.tsx. Set `numeric` to force right alignment + tabular figures on
 * a computed column whose value has no backing row field to auto-detect. */
export interface PageColumn {
  field: string;
  label: string;
  kind?: ColumnKind;
  numeric?: boolean;
  render?: (value: unknown, row: DataRow) => ReactNode;
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
  /** Compute the value this filter matches on from the whole row instead of
   * reading `row[name]` directly. Lets one control span multiple columns
   * (e.g. search `label` + `key_prefix` under one text box) or map derived
   * state (e.g. `revoked_at` presence -> "active"/"revoked"). When absent,
   * matching behavior is unchanged. `deriveOptions` still reads `row[name]`,
   * so pair `deriveValue` with static `options` for select/segmented. */
  deriveValue?: (row: DataRow) => string;
  /** Initial scalar value applied on mount (text / select / segmented). Use
   * when the backend requires a narrowing param and there is no meaningful
   * "all" -- e.g. `/agents/specialists?module_id=` is required, so the module
   * selector seeds with `vr`. Ignored for multi-select / range filters. */
  defaultValue?: string;
}

/** A two-ended range value (date-range / numeric-range). `lo` is
 * since/min, `hi` is until/max. */
export interface RangeVal {
  lo: string;
  hi: string;
}

/** The runtime value held for one filter: a scalar (text/select/segmented),
 * a set (multi-select), or a range (date-range/numeric-range). */
export type FilterValue = string | string[] | RangeVal;

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
  /** When true, the field is only shown and collected for a god-tier admin
   * (JWT with no `team_id`). Hidden and never submitted for team-scoped
   * callers; use for fields the backend only accepts from god-tier. */
  godTierOnly?: boolean;
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

/** A JSON scalar an action body template may carry. */
export type ActionBodyValue = string | number | boolean | null | string[];

/** JSON body sent with an action call: a static template merged with the
 * values collected in the pre-flight modal. */
export type ActionBody = Record<string, ActionBodyValue>;

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
  body?: ActionBody;
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

/** Parent scope for endpoints that REQUIRE one. Parents resolve from
 * `endpoint` and render a picker. If the list endpoint contains `{scope}` the
 * id is substituted into the path; otherwise it is appended as
 * `?<param>=<id>`. `labelField` names the option label (default idField). */
export interface PageScope {
  endpoint: string;
  param?: string;
  idField?: string;
  labelField?: string;
}

/** What to fetch and how to lay out the list: endpoint, columns, filters,
 * pagination, grouping. */
export interface PageListConfig {
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
  scopeFrom?: PageScope;
  /** When set, the query pages through every page (backend max 250/page)
   * and concatenates `items`, so client-side filters + pagination see the
   * full dataset (e.g. the 273-row config registry). */
  fetchAllPages?: boolean;
  /** Filters rendered under the title. Each filter narrows the fetched rows
   * client-side, or is sent to the endpoint when `server` is set. */
  filters?: PageFilter[];
  /** Server-side pagination chrome (prev/next, page N of M, total). Page size
   * is 50 and `page`/`page_size` are sent to the endpoint, which must return
   * a `total` (or `pages`) in the envelope. With `fetchAllPages` set,
   * pagination slices the client-side filtered full set instead. When the
   * endpoint paginates by `offset`/`limit` (and reports total in a `meta`
   * object or top-level), set `paginationParams: "offset"` to send
   * `offset`/`limit` and read `meta.total`. */
  pagination?: boolean;
  paginationParams?: "page" | "offset";
  /** When set, the rendered (filtered, paginated) rows are partitioned into
   * sections keyed by `row[groupBy]`. Group keys sort by localeCompare; within
   * each group, active rows (`status`/`is_active` == "active") float to the
   * top, then remaining rows sort by `created_at` ascending (oldest candidate
   * first). Unset -> flat rendering. */
  groupBy?: string;
}

/** Backend calls the operator can fire from the page. */
export interface PageActionsConfig {
  /** DELETE endpoint template with `{id}` (and `{scope}`). Enables "delete". */
  delete?: string;
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
}

/** Per-row floating viewer: a detail-header button opens a page-local
 * floater whose body is `render(row, close)`. DataPage owns the floater's
 * open/minimized/fullscreen state. */
export interface PageRowViewer {
  actionLabel: string;
  title: (row: DataRow) => string;
  render: (row: DataRow, close: () => void) => ReactNode;
}

/** How the selected row's detail panel renders. */
export interface PageDetailConfig {
  /** Per-field custom detail renderers (keyed by row field). When present for a
   * field, the detail panel uses it instead of the generic <StructuredValue>
   * (e.g. the LLM-log prompt/response rendered as a chat transcript). */
  detailRenderers?: Record<string, (value: unknown, row: DataRow) => ReactNode>;
  /** Detail fields that link out to another registered window. Keyed by the
   * detail field name; the value names the target section (moduleKey is this
   * page's module). Renders the field as a clickable "open" chip in the
   * detail grid, handing the row's id to onOpenPage. */
  detailLinks?: Record<string, { module?: string; section: string; label?: string }>;
  /** Event timeline shown under the detail grid. `endpoint` is fetched with
   * `{field}` placeholders substituted from the row; the envelope is a
   * paginated list ({items: [{created_at, stage, action, status, ...}], total})
   * like /audit/events. Renders newest-first with semantic status badges. */
  detailEvents?: { endpoint: string; itemsKey?: string };
  rowViewer?: PageRowViewer;
}

/** Behavior after the typed create form succeeds. */
export interface PageCreateConfig {
  /** When set, a successful create via the typed FieldForm modal auto-selects
   * the newest fetched row (rows are created_at DESC, so first of the fetched
   * set) and opens the detail panel. No effect when the config has no
   * `create` form or when creates come from a bespoke `onNewClick`. */
  selectCreatedRow?: boolean;
}

/** Declarative config for a backend-backed list window. One of these per nav
 * item gives a readable, real-data page without a bespoke component. */
export type PageConfig = PageListConfig & PageActionsConfig & PageDetailConfig & PageCreateConfig;
