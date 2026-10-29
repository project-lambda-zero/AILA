/** The knowledge ENTRIES BROWSER panel: GET /platform/knowledge/entries
 * (paged) with namespace/source/content filters, operator-note quick chips,
 * and the in-panel entry detail. */

import { useState } from "react";
import type { ChangeEvent, FormEvent, JSX } from "react";

import { useKnowledgeEntries } from "../../../api/knowledge";
import type { KnowledgeEntry } from "../../../api/knowledge";
import { css } from "../../css";
import StructuredValue from "../StructuredValue";
import { ContentBody, ellipsize, fmtInt } from "./helpers";
import {
  btnGhost,
  btnGhostDisabled,
  btnPrimary,
  chip,
  chipAccent,
  chipFaint,
  dot,
  emptyNote,
  H_WARN,
  inputStyle,
  kvGrid,
  kvLabel,
  kvVal,
  labelStyle,
  PAGE_SIZE,
  pad,
  panelBox,
  panelTitle,
  scroll,
  tableEl,
  tdStyle,
  thStyle,
} from "./styles";

interface EntriesFilters {
  namespace: string;
  source_type: string;
  q: string;
}

export function EntriesPanel(): JSX.Element {
  const [filters, setFilters] = useState<EntriesFilters>({ namespace: "", source_type: "", q: "" });
  const [applied, setApplied] = useState<EntriesFilters>({ namespace: "", source_type: "", q: "" });
  const [offset, setOffset] = useState(0);
  const [sel, setSel] = useState<KnowledgeEntry | null>(null);

  const q = useKnowledgeEntries({
    namespace: applied.namespace || undefined,
    source_type: applied.source_type || undefined,
    q: applied.q || undefined,
    limit: PAGE_SIZE,
    offset,
  });

  const applyFilters = (e: FormEvent<HTMLFormElement>): void => {
    e.preventDefault();
    setApplied({ ...filters });
    setOffset(0);
    setSel(null);
  };

  const clearFilters = (): void => {
    setFilters({ namespace: "", source_type: "", q: "" });
    setApplied({ namespace: "", source_type: "", q: "" });
    setOffset(0);
    setSel(null);
  };

  const items = q.data?.items ?? [];
  const total = q.data?.total ?? 0;
  const canPrev = offset > 0;
  const canNext = offset + items.length < total;
  const pageStart = total === 0 ? 0 : offset + 1;
  const pageEnd = offset + items.length;

  return (
    <div style={panelBox}>
      <div style={panelTitle}>
        <span style={dot} />
        <span style={css("color:var(--text-primary);")}>entries</span>
        <span style={css("flex:1;")} />
        <span style={css("color:var(--text-faint);text-transform:none;letter-spacing:0.04em;")}>
          {q.isLoading && !q.data
            ? "loading\u2026"
            : total === 0
              ? "0 entries"
              : `${pageStart}\u2013${pageEnd} of ${fmtInt(total)}`}
        </span>
      </div>
      <div style={{ ...pad, display: "flex", flexDirection: "column", gap: 10, minHeight: 0, flex: 1 }}>
        <div style={css("display:flex;align-items:center;gap:6px;flex-wrap:wrap;")}>
          <span style={css("font-family:var(--font-mono);font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);")}>
            operator notes
          </span>
          {[
            { label: "vr", ns: "vr.operator_note." },
            { label: "malware", ns: "malware.operator_note." },
          ].map((qf) => {
            const active = applied.namespace === `${qf.ns}*`;
            return (
              <button
                key={qf.ns}
                type="button"
                style={active ? chipAccent : chip}
                onClick={() => {
                  const nf = { namespace: `${qf.ns}*`, source_type: "", q: "" };
                  setFilters(nf);
                  setApplied(nf);
                  setOffset(0);
                  setSel(null);
                }}
              >
                {qf.label}
              </button>
            );
          })}
        </div>
        <form onSubmit={applyFilters} style={css("display:grid;grid-template-columns:1fr 1fr 2fr auto auto;gap:8px;align-items:end;")}>
          <label style={labelStyle}>
            namespace
            <input
              type="text"
              value={filters.namespace}
              onChange={(e: ChangeEvent<HTMLInputElement>) => setFilters((f) => ({ ...f, namespace: e.target.value }))}
              placeholder="exact or prefix"
              style={inputStyle}
              autoComplete="off"
            />
          </label>
          <label style={labelStyle}>
            source type
            <input
              type="text"
              value={filters.source_type}
              onChange={(e: ChangeEvent<HTMLInputElement>) => setFilters((f) => ({ ...f, source_type: e.target.value }))}
              style={inputStyle}
              autoComplete="off"
            />
          </label>
          <label style={labelStyle}>
            content search
            <input
              type="text"
              value={filters.q}
              onChange={(e: ChangeEvent<HTMLInputElement>) => setFilters((f) => ({ ...f, q: e.target.value }))}
              placeholder="substring / tsquery"
              style={inputStyle}
              autoComplete="off"
            />
          </label>
          <button type="submit" style={btnPrimary}>apply</button>
          <button type="button" onClick={clearFilters} style={btnGhost}>reset</button>
        </form>

        <div style={{ ...panelBox, flex: 1, minHeight: 0 }}>
          <div style={{ ...scroll }}>
            {q.isLoading && !q.data ? (
              <div style={emptyNote}>loading entries&#8230;</div>
            ) : q.isError ? (
              <div style={{ ...emptyNote, color: H_WARN }}>
                could not load /platform/knowledge/entries &mdash;{" "}
                {q.error instanceof Error ? q.error.message : "request failed"}
              </div>
            ) : items.length === 0 ? (
              <div style={emptyNote}>no entries match these filters.</div>
            ) : (
              <table style={tableEl}>
                <thead>
                  <tr>
                    <th style={thStyle}>namespace</th>
                    <th style={thStyle}>source</th>
                    <th style={thStyle}>model</th>
                    <th style={thStyle}>content</th>
                    <th style={thStyle}>created</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((row) => {
                    const active = sel?.id === row.id;
                    return (
                      <tr
                        key={row.id}
                        onClick={() => setSel((cur) => (cur?.id === row.id ? null : row))}
                        style={css(
                          `cursor:pointer;border-bottom:1px solid var(--border-faint);${active ? "background:color-mix(in srgb,var(--accent) 12%,transparent);" : ""}`,
                        )}
                      >
                        <td style={tdStyle} title={row.namespace}>{row.namespace || "\u2014"}</td>
                        <td style={tdStyle}>{row.source_type ?? "\u2014"}</td>
                        <td style={tdStyle} title={row.model_id ?? undefined}>{row.model_id ?? "\u2014"}</td>
                        <td style={tdStyle}>{ellipsize(row.content ?? "", 140)}</td>
                        <td style={tdStyle}>{row.created_at ?? "\u2014"}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>

        <div style={css("display:flex;align-items:center;gap:8px;")}>
          <button
            type="button"
            onClick={() => canPrev && setOffset(Math.max(0, offset - PAGE_SIZE))}
            style={canPrev ? btnGhost : btnGhostDisabled}
            disabled={!canPrev}
          >
            {"\u25c0 prev"}
          </button>
          <button
            type="button"
            onClick={() => canNext && setOffset(offset + PAGE_SIZE)}
            style={canNext ? btnGhost : btnGhostDisabled}
            disabled={!canNext}
          >
            {"next \u25b6"}
          </button>
          <span style={css("flex:1;")} />
          <span style={css("font-family:var(--font-mono);font-size:11px;color:var(--text-faint);letter-spacing:0.06em;text-transform:uppercase;")}>
            page size {PAGE_SIZE}
          </span>
        </div>

        {sel ? <EntryDetail entry={sel} onClose={() => setSel(null)} /> : null}
      </div>
    </div>
  );
}

function EntryDetail({ entry, onClose }: { entry: KnowledgeEntry; onClose: () => void }): JSX.Element {
  return (
    <div style={{ ...panelBox, flex: "0 0 auto", maxHeight: 360 }}>
      <div style={panelTitle}>
        <span style={dot} />
        <span style={css("color:var(--text-primary);")}>entry detail</span>
        <span style={css("flex:1;")} />
        <span style={css("font-family:var(--font-mono);font-size:11px;color:var(--text-faint);letter-spacing:0.04em;")}>
          {entry.id}
        </span>
        <button
          type="button"
          onClick={onClose}
          style={css("background:transparent;border:0;color:var(--text-faint);cursor:pointer;min-height:28px;display:inline-flex;align-items:center;font-size:12px;margin-left:6px;")}
          title="close detail"
        >
          {"\u2715"}
        </button>
      </div>
      <div style={{ ...scroll, ...pad }}>
        <div style={kvGrid}>
          <span style={kvLabel}>namespace</span>
          <span style={kvVal}>
            <span style={chip}>{entry.namespace || "\u2014"}</span>
          </span>
          <span style={kvLabel}>source type</span>
          <span style={kvVal}>{entry.source_type ? <span style={chipAccent}>{entry.source_type}</span> : "\u2014"}</span>
          <span style={kvLabel}>model</span>
          <span style={kvVal}>{entry.model_id ? <span style={chipFaint}>{entry.model_id}</span> : "\u2014"}</span>
          <span style={kvLabel}>created</span>
          <span style={kvVal}>{entry.created_at ?? "\u2014"}</span>
          <span style={kvLabel}>content</span>
          <span style={kvVal}>
            <ContentBody text={entry.content ?? ""} />
          </span>
          <span style={kvLabel}>metadata</span>
          <span style={kvVal}>
            <StructuredValue value={entry.entry_metadata ?? null} />
          </span>
        </div>
      </div>
    </div>
  );
}
