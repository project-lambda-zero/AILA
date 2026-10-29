/** The declarative backend-backed list window. Thin composition over the
 * data/ split: useDataRows (fetch/filter/page), FilterBar, RowTable,
 * DetailPanel, the typed create/edit FieldForm modal, the action modals, and
 * the per-row floater viewer. Configs are declared in configs.ts as focused
 * parts (see data/types.ts). */

import { useEffect, useState } from "react";
import type { ChangeEvent, JSX, ReactNode } from "react";

import { useMutation, useQueryClient } from "@tanstack/react-query";

import { useAuth } from "../../api/auth";
import { apiFetch, API_BASE } from "../../api/client";
import type { WindowChromeProps, PageOpenerProps } from "../contract";
import { css } from "../css";
import { ConsoleWindow } from "../window";
import { ActionModals } from "./data/ActionModals";
import type { ActionFormState, RevealState } from "./data/ActionModals";
import { BulkBar } from "./data/BulkBar";
import { DetailPanel } from "./data/DetailPanel";
import { FilterBar } from "./data/FilterBar";
import { RowTable } from "./data/RowTable";
import { RowViewerWindow } from "./data/RowViewerWindow";
import { fillTemplate, visibleFields, visibleRowActions } from "./data/rows";
import { dot, emptyNote, PANEL_BOX, panelTitle } from "./data/styles";
import type { ActionBody, DataRow, PageAction, PageConfig } from "./data/types";
import { useDataRows } from "./data/useDataRows";
import FieldForm from "./FieldForm";
import type { FormSpec } from "./FieldForm";
import { CREATE_FORMS, EDIT_FORMS } from "./formSpecs";

export type { ActionField, PageAction, PageColumn, PageConfig, PageFilter } from "./data/types";

export interface DataPageProps extends WindowChromeProps, PageOpenerProps {
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
  onRowActivate?: (row: DataRow) => void;
  /** When set, the in-window detail panel's body is this renderer instead
   * of the generic field grid. Receives the selected row. Used for
   * drill-down panels (e.g. a target row's investigations). */
  detailBody?: (row: DataRow) => ReactNode;
  /** Node rendered in the filter/toolbar bar (right group, next to
   * pageActions). Lets a bespoke wrapper add a page-level control that
   * carries local React state -- e.g. a "preview applicable" button that
   * opens a query overlay -- without inventing a config-level capability. */
  toolbarExtra?: ReactNode;
}

export default function DataPage(props: DataPageProps): JSX.Element {
  const { config, configKey, onNewClick, onRowActivate, detailBody, toolbarExtra, onBack, onMinimize, isFullscreen, onToggleFullscreen, onOpenPage, windowId, title: windowTitle, isFocused, onFocus } = props;
  // SAFETY: every CREATE_FORMS/EDIT_FORMS literal is FormSpec-shaped; the cast
  // narrows the literal map to the shared contract for a dynamic registry key.
  const createSpec: FormSpec | undefined = (CREATE_FORMS as Record<string, FormSpec>)[configKey];
  const editSpec: FormSpec | undefined = (EDIT_FORMS as Record<string, FormSpec>)[configKey];
  const idField = config.idField ?? "id";
  const isGodTier = useAuth((s) => s.user?.role === "admin" && !s.user?.team_id);
  const data = useDataRows(config);
  const { endpoint, activeScope, scopeParents, setScope, isLoading, isError, error, rows, total, columns, numericFields, page, pageCount, setPage, filterVals, setFilter, toggleFilter, setRangeFilter, optionsFor } = data;
  const filters = config.filters ?? [];
  const pagination = Boolean(config.pagination);
  const bulkActions = config.bulkActions ?? [];

  const [sel, setSel] = useState<DataRow | null>(null);
  // Which form is open (if any); the edit form targets the selected row.
  const [formMode, setFormMode] = useState<"create" | "edit" | null>(null);
  // config.selectCreatedRow: flag set on create-success; the effect below
  // consumes it once the next fetched dataset lands and auto-selects the
  // newest row (rows come back created_at DESC, so index 0 of the fetched
  // set is the just-created record).
  const [pendingSelectFirst, setPendingSelectFirst] = useState(false);
  // Consume the create-success flag once the next fetched set lands. Clearing
  // the flag before setSel avoids re-firing on the 15s poll.
  useEffect(() => {
    if (!pendingSelectFirst) return;
    if (data.allRows.length === 0) return;
    setPendingSelectFirst(false);
    setSel(data.allRows[0]);
  }, [pendingSelectFirst, data.allRows]);

  // Optional page-local floater viewer (config.rowViewer). Holds the row
  // whose content is being shown; the window state lives in RowViewerWindow.
  const [viewerRow, setViewerRow] = useState<DataRow | null>(null);
  const openViewer = (row: DataRow): void => setViewerRow(row);
  const closeViewer = (): void => setViewerRow(null);

  const qc = useQueryClient();
  const invalidateList = (): void => {
    void qc.invalidateQueries({ queryKey: ["datapage", endpoint] });
  };

  // ---- delete only (create/update belong in real typed wizards) --------
  const del = useMutation({
    mutationFn: (path: string) => apiFetch<unknown>(path, { method: "DELETE" }),
    onSuccess: () => {
      invalidateList();
      setSel(null);
    },
  });
  const doDelete = (row: DataRow): void => {
    if (!config.delete) return;
    if (!window.confirm("Delete this row? This cannot be undone.")) return;
    del.mutate(fillTemplate(config.delete, activeScope, String(row[idField] ?? "")));
  };

  // ---- row + page + bulk actions (PageAction) ---------------------------

  const action = useMutation({
    mutationFn: ({ path, method, body }: { path: string; method: string; body?: ActionBody }) =>
      apiFetch<unknown>(path, {
        method,
        headers: body ? { "Content-Type": "application/json" } : undefined,
        body: body ? JSON.stringify(body) : undefined,
      }),
    onSuccess: invalidateList,
  });
  // Action-body collection + one-shot reveal state. `actionForm` holds the
  // action awaiting operator input (with its target row); `actionVals` are the
  // in-progress field values; `reveal` holds a completed action's response to
  // show once.
  const [actionForm, setActionForm] = useState<ActionFormState | null>(null);
  const [actionVals, setActionVals] = useState<Record<string, string>>({});
  const [actionErr, setActionErr] = useState<string | null>(null);
  const [reveal, setReveal] = useState<RevealState | null>(null);

  // Fire one action call: path + static body substituted, collected `extra`
  // merged over the body, response captured when the action declares a reveal.
  const fireAction = (a: PageAction, row: DataRow | null, extra?: ActionBody): void => {
    const sub = (s: string): string => fillTemplate(s, activeScope, String(row?.[idField] ?? ""));
    const base: ActionBody = a.body
      ? Object.fromEntries(Object.entries(a.body).map(([k, v]): [string, ActionBody[string]] => [k, typeof v === "string" ? sub(v) : v]))
      : {};
    const merged: ActionBody = { ...base, ...extra };
    const body = Object.keys(merged).length > 0 ? merged : undefined;
    action.mutate(
      { path: sub(a.endpoint), method: a.method, body },
      a.reveal
        ? {
            onSuccess: (data: unknown) => {
              setReveal({ action: a, payload: data });
            },
          }
        : undefined,
    );
  };

  const doAction = (a: PageAction, row: DataRow | null): void => {
    if (a.download) {
      const url = fillTemplate(a.endpoint, activeScope, String(row?.[idField] ?? ""));
      window.open(`${API_BASE}${url.startsWith("/") ? url : `/${url}`}`, "_blank", "noopener");
      return;
    }
    const shown = visibleFields(a, isGodTier);
    if (shown.length > 0) {
      // Prefill declared fields from the row, then collect the rest in a modal
      // whose submit is the explicit confirm.
      const init: Record<string, string> = {};
      for (const f of shown) {
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
    const out: ActionBody = {};
    for (const f of visibleFields(a, isGodTier)) {
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

  // ---- bulk selection ----------------------------------------------------
  // One set of selected row identities (idField values). Checkboxes in the
  // first column toggle membership; the bulk bar fires each bulk action once
  // per selected row via the action mutation, reporting per-row errors.
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkResults, setBulkResults] = useState<string | null>(null);
  const toggleRow = (row: DataRow): void => {
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
  const listInner: JSX.Element = isLoading ? (
    <div style={emptyNote}>loading&#8230;</div>
  ) : isError ? (
    <div style={emptyNote}>could not load {config.endpoint} &mdash; {error instanceof Error ? error.message : "request failed"}</div>
  ) : rows.length === 0 ? (
    <div style={emptyNote}>{config.empty ?? "no records."}</div>
  ) : (
    <RowTable
      rows={rows}
      columns={columns}
      numericFields={numericFields}
      idField={idField}
      sel={sel}
      setSel={setSel}
      selected={selected}
      toggleRow={toggleRow}
      toggleAll={toggleAll}
      bulkEnabled={bulkActions.length > 0}
      groupBy={config.groupBy}
      onRowActivate={onRowActivate}
    />
  );

  const scopeIdField = config.scopeFrom?.idField ?? "id";
  const body: JSX.Element = (
    <div style={css("flex:1;min-height:0;display:flex;gap:10px;padding:12px;")}>
      <div style={css(`flex:${sel ? "1 1 62%" : "1 1 100%"};min-width:0;` + PANEL_BOX)}>
        <div style={panelTitle}>
          <span style={dot} />
          <span style={css("color:var(--text-primary);font-family:var(--font-display);font-weight:400;")}>{config.title}</span>
          {config.scopeFrom && scopeParents.length ? (
            <span style={css("display:inline-flex;align-items:center;gap:6px;")}>
              <span style={css("font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-faint);")}>scope</span>
              <select
                value={activeScope}
                onChange={(e: ChangeEvent<HTMLSelectElement>) => setScope(e.target.value)}
                style={css("min-height:28px;background:var(--surface-sunk);border:1px solid var(--border-soft);color:var(--text-muted);font-family:var(--font-mono);font-size:11px;padding:1px 5px;border-radius:2px;max-width:230px;text-transform:none;letter-spacing:normal;cursor:pointer;")}
              >
                {scopeParents.map((p, i) => {
                  const id = String(p[scopeIdField] ?? "");
                  const label = String(p[config.scopeFrom?.labelField ?? scopeIdField] ?? id);
                  return (
                    <option key={id + i} value={id}>
                      {label}
                    </option>
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
              style={css("min-height:28px;padding:2px 8px;border:1px solid var(--accent);border-radius:2px;background:transparent;color:var(--accent);font-family:var(--font-mono);font-size:11px;letter-spacing:0.08em;text-transform:uppercase;cursor:pointer;")}
              title="create a new record"
            >
              + new
            </button>
          ) : null}
          <span style={css("color:var(--text-faint);text-transform:none;letter-spacing:0.04em;")}>{rows.length} rows</span>
        </div>
        {filters.length > 0 || pagination || toolbarExtra ? (
          <FilterBar
            filters={filters}
            filterVals={filterVals}
            setFilter={setFilter}
            toggleFilter={toggleFilter}
            setRangeFilter={setRangeFilter}
            optionsFor={optionsFor}
            toolbarExtra={toolbarExtra}
            pageActions={config.pageActions ?? []}
            onPageAction={(a) => doAction(a, null)}
            actionPending={action.isPending}
            pagination={pagination}
            page={page}
            pageCount={pageCount}
            total={total}
            setPage={setPage}
          />
        ) : null}
        <BulkBar
          selectedCount={selected.size}
          bulkActions={bulkActions}
          actionPending={action.isPending}
          onBulk={(a) => void doBulk(a)}
          onClear={() => setSelected(new Set())}
          results={bulkResults}
        />
        <div style={css("flex:1;min-height:0;overflow:auto;")}>{listInner}</div>
      </div>
      {sel ? (
        <DetailPanel
          row={sel}
          detail={config}
          detailBody={detailBody}
          rowActions={visibleRowActions(config.actions, sel)}
          onAction={doAction}
          actionPending={action.isPending}
          actionError={action.error instanceof Error ? action.error : action.error ? new Error("action failed") : null}
          canEdit={Boolean(editSpec)}
          onEdit={() => setFormMode("edit")}
          canDelete={Boolean(config.delete)}
          onDelete={doDelete}
          onOpenViewer={openViewer}
          onOpenPage={onOpenPage}
          onClose={() => setSel(null)}
        />
      ) : null}
    </div>
  );

  const activeSpec: FormSpec | null =
    formMode === "create" ? createSpec ?? null : formMode === "edit" ? editSpec ?? null : null;

  const statusStrip = (
    <>
      <span style={{ display: "flex", alignItems: "center", padding: "0 11px", background: "var(--status-ok)", color: "var(--text-on-accent)", fontWeight: 700, letterSpacing: "0.14em" }}>{config.title}</span>
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
          <div onClick={(e) => e.stopPropagation()} style={css("width:min(560px,100%);max-height:100%;display:flex;")}>
            <FieldForm
              spec={activeSpec}
              initial={formMode === "edit" ? sel : null}
              onDone={() => {
                if (formMode === "create" && config.selectCreatedRow) {
                  setPendingSelectFirst(true);
                }
                setFormMode(null);
              }}
              onCancel={() => setFormMode(null)}
              invalidateKey={["datapage", endpoint]}
            />
          </div>
        </div>
      ) : null}
      <ActionModals
        actionForm={actionForm}
        actionVals={actionVals}
        setActionVals={setActionVals}
        actionErr={actionErr}
        visibleFields={(a) => visibleFields(a, isGodTier)}
        onSubmit={submitActionForm}
        onCancel={() => setActionForm(null)}
        actionPending={action.isPending}
        reveal={reveal}
        onRevealClose={() => setReveal(null)}
      />
      {config.rowViewer && viewerRow ? (
        <RowViewerWindow viewer={config.rowViewer} row={viewerRow} windowId={windowId} onClose={closeViewer} />
      ) : null}
    </ConsoleWindow>
  );
}
