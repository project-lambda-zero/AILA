/**
 * KnowledgePage -- bespoke admin window over the platform RAG corpus
 * (KnowledgeEntryRecord + KnowledgeEntryEdge).
 *
 * Three panels, all backed by real endpoints, honest empty/loading/error:
 *   SEARCH          POST /platform/knowledge/search   (mutation)
 *   CORPUS STATS    GET  /platform/knowledge/stats    (query)
 *   ENTRIES BROWSER GET  /platform/knowledge/entries  (paged query)
 *
 * Renders content the way an operator wants to read it: a mono block for
 * long / code / JSON-shaped bodies, plain paragraph text otherwise.
 * Structured metadata renders via <StructuredValue>, never as a raw JSON
 * blob. Follows the DataPage window-chrome convention: absolute-fill
 * body + a footer strip that carries the min / fullscreen / close
 * controls the shell wired through ModulePageProps.
 */

import { useMemo, useState } from "react";
import type { ChangeEvent, CSSProperties, FormEvent, JSX } from "react";

import {
  useIngestKnowledge,
  useKnowledgeEntries,
  useKnowledgeSearch,
  useKnowledgeStats,
} from "../../api/knowledge";
import type {
  KnowledgeBucket,
  KnowledgeEntry,
  KnowledgeHit,
} from "../../api/knowledge";
import { useWorkspaces } from "../../api/intake";
import type { ModulePageProps } from "../contract";
import { css } from "../css";
import StructuredValue from "./StructuredValue";

/* ------------------------------ constants -------------------------------- */

const PAGE_SIZE = 50;
const CODE_LOOK_MAX = 240;
const H_WARN = "#ffb85f";

/* ------------------------------- styles ---------------------------------- */

const panelBox: CSSProperties = css(
  "min-height:0;display:flex;flex-direction:column;border:1px solid var(--border);border-radius:var(--radius-md,3px);background:color-mix(in srgb,var(--surface-card) 84%,transparent);overflow:hidden;box-shadow:var(--bevel-raised,inset 1px 1px 0 rgba(255,255,255,0.03));",
);
const panelTitle: CSSProperties = css(
  "flex:0 0 auto;display:flex;align-items:center;gap:10px;height:var(--panel-title-h,27px);padding:0 12px;background:var(--surface-chrome);border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:9.5px;text-transform:uppercase;letter-spacing:0.14em;color:var(--text-muted);",
);
const dot: CSSProperties = css(
  "width:8px;height:8px;border-radius:1px;background:var(--accent);box-shadow:0 0 6px var(--accent);flex:0 0 auto;",
);
const scroll: CSSProperties = css("flex:1;min-height:0;overflow:auto;");
const pad: CSSProperties = css("padding:12px 13px;");
const stack: CSSProperties = css("display:flex;flex-direction:column;gap:10px;");
const emptyNote: CSSProperties = css(
  "flex:1;display:flex;align-items:center;justify-content:center;padding:20px;font-family:var(--font-mono);font-size:11px;color:var(--text-faint);letter-spacing:0.04em;text-align:center;",
);
const inputStyle: CSSProperties = css(
  "background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:2px;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;padding:5px 8px;min-width:0;outline:none;",
);
const labelStyle: CSSProperties = css(
  "display:flex;flex-direction:column;gap:3px;font-family:var(--font-mono);font-size:9px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);min-width:0;",
);
const btnPrimary: CSSProperties = css(
  "padding:5px 12px;border:1px solid var(--accent);border-radius:2px;background:transparent;color:var(--accent);font-family:var(--font-mono);font-size:10px;letter-spacing:0.1em;text-transform:uppercase;cursor:pointer;",
);
const btnGhost: CSSProperties = css(
  "padding:4px 10px;border:1px solid var(--border-soft);border-radius:2px;background:transparent;color:var(--text-muted);font-family:var(--font-mono);font-size:10px;letter-spacing:0.1em;text-transform:uppercase;cursor:pointer;",
);
const btnGhostDisabled: CSSProperties = css(
  "padding:4px 10px;border:1px solid var(--border-faint);border-radius:2px;background:transparent;color:var(--text-faint);font-family:var(--font-mono);font-size:10px;letter-spacing:0.1em;text-transform:uppercase;cursor:not-allowed;",
);
const chip: CSSProperties = css(
  "display:inline-block;padding:1px 6px;border:1px solid var(--border-soft);border-radius:2px;font-family:var(--font-mono);font-size:9.5px;line-height:1.5;color:var(--text-primary);background:var(--surface-sunk);word-break:break-word;",
);
const chipAccent: CSSProperties = css(
  "display:inline-block;padding:1px 6px;border:1px solid color-mix(in srgb,var(--accent) 55%,transparent);border-radius:2px;font-family:var(--font-mono);font-size:9.5px;line-height:1.5;color:var(--accent);background:color-mix(in srgb,var(--accent) 10%,transparent);word-break:break-word;",
);
const chipFaint: CSSProperties = css(
  "display:inline-block;padding:1px 6px;border:1px solid var(--border-faint);border-radius:2px;font-family:var(--font-mono);font-size:9.5px;line-height:1.5;color:var(--text-faint);background:transparent;word-break:break-word;",
);
const chipRow: CSSProperties = css(
  "display:inline-flex;flex-wrap:wrap;gap:5px;max-width:100%;align-items:center;",
);
const monoBlock: CSSProperties = css(
  "margin:0;padding:8px 10px;border:1px solid var(--border-soft);border-radius:2px;background:var(--surface-sunk);font-family:var(--font-mono);font-size:10.5px;line-height:1.5;color:var(--text-primary);white-space:pre-wrap;word-break:break-word;max-height:280px;overflow:auto;",
);
const proseBlock: CSSProperties = css(
  "margin:0;font-family:var(--font-mono);font-size:11px;line-height:1.55;color:var(--text-primary);white-space:pre-wrap;word-break:break-word;max-height:200px;overflow:auto;",
);
const hitCard: CSSProperties = css(
  "display:flex;flex-direction:column;gap:6px;padding:9px 11px;border:1px solid var(--border-soft);border-left:2px solid color-mix(in srgb,var(--accent) 55%,transparent);border-radius:2px;background:color-mix(in srgb,var(--surface-card) 60%,transparent);min-width:0;",
);
const hitHeader: CSSProperties = css(
  "display:flex;align-items:center;gap:8px;flex-wrap:wrap;",
);
const scoreChip: CSSProperties = css(
  "display:inline-flex;align-items:center;gap:4px;padding:1px 7px;border:1px solid color-mix(in srgb,var(--status-ok) 55%,transparent);border-radius:2px;font-family:var(--font-mono);font-size:9.5px;line-height:1.5;color:var(--status-ok);background:color-mix(in srgb,var(--status-ok) 10%,transparent);font-variant-numeric:tabular-nums;",
);
const twoUp: CSSProperties = css(
  "display:grid;grid-template-columns:1fr 1fr;gap:12px;min-height:0;min-width:0;",
);
const statFigure: CSSProperties = css(
  "display:flex;flex-direction:column;gap:2px;padding:12px 14px;border:1px solid var(--border-soft);border-radius:2px;background:var(--surface-sunk);min-width:0;",
);
const statValue: CSSProperties = css(
  "font-family:var(--font-mono);font-size:22px;line-height:1.1;color:var(--accent);font-variant-numeric:tabular-nums;letter-spacing:0.02em;",
);
const statLabel: CSSProperties = css(
  "font-family:var(--font-mono);font-size:9px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-faint);",
);
const bucketRow: CSSProperties = css(
  "display:grid;grid-template-columns:1fr 40px 90px;gap:8px;align-items:center;padding:3px 0;font-family:var(--font-mono);font-size:10.5px;color:var(--text-primary);min-width:0;",
);
const bucketLabelCell: CSSProperties = css(
  "min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text-primary);",
);
const bucketCountCell: CSSProperties = css(
  "text-align:right;font-variant-numeric:tabular-nums;color:var(--text-muted);",
);
const barTrack: CSSProperties = css(
  "position:relative;height:6px;background:var(--surface-sunk);border:1px solid var(--border-faint);border-radius:1px;overflow:hidden;",
);
const kvGrid: CSSProperties = css(
  "display:grid;grid-template-columns:minmax(120px,140px) 1fr;gap:5px 12px;font-size:10.5px;font-family:var(--font-mono);color:var(--text-primary);align-content:start;",
);
const kvLabel: CSSProperties = css(
  "color:var(--text-faint);letter-spacing:0.04em;text-transform:uppercase;font-size:9px;",
);
const kvVal: CSSProperties = css("color:var(--text-primary);word-break:break-word;min-width:0;");
const tableEl: CSSProperties = css(
  "width:100%;border-collapse:collapse;font-family:var(--font-mono);font-size:11px;",
);
const thStyle: CSSProperties = css(
  "position:sticky;top:0;text-align:left;padding:7px 10px;background:var(--surface-chrome);border-bottom:1px solid var(--border);font-size:8.5px;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-faint);white-space:nowrap;z-index:1;",
);
const tdStyle: CSSProperties = css(
  "padding:6px 10px;border-bottom:1px solid var(--border-faint);color:var(--text-primary);vertical-align:top;max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;",
);
const modalBackdrop: CSSProperties = css(
  "position:fixed;inset:0;z-index:60;display:flex;align-items:center;justify-content:center;padding:24px;background:color-mix(in srgb,var(--surface-base,#0b0b0b) 62%,transparent);backdrop-filter:blur(2px);",
);
const modalCard: CSSProperties = css(
  "width:min(560px,94vw);max-height:88vh;display:flex;flex-direction:column;border:1px solid var(--border);border-radius:var(--radius-md,3px);background:var(--surface-card);overflow:hidden;box-shadow:0 18px 48px rgba(0,0,0,0.5);",
);
const textareaStyle: CSSProperties = css(
  "background:var(--surface-sunk);border:1px solid var(--border-soft);border-radius:2px;color:var(--text-primary);font-family:var(--font-mono);font-size:11px;line-height:1.55;padding:8px 10px;min-width:0;outline:none;resize:vertical;min-height:120px;",
);
const headerBtn: CSSProperties = css(
  "padding:4px 11px;border:1px solid var(--accent);border-radius:2px;background:color-mix(in srgb,var(--accent) 10%,transparent);color:var(--accent);font-family:var(--font-mono);font-size:9.5px;letter-spacing:0.12em;text-transform:uppercase;cursor:pointer;",
);

/* ----------------------------- small helpers ----------------------------- */

/** Match StructuredValue's code-shape heuristic locally so we can render
 *  content bodies (search hits + entry detail) with the right treatment
 *  without forcing every field into <StructuredValue>. */
function looksLikeCode(text: string): boolean {
  const head = text.trimStart();
  return (
    text.length > CODE_LOOK_MAX ||
    text.indexOf("\n") !== -1 ||
    head.startsWith("{") ||
    head.startsWith("[") ||
    head.startsWith("```")
  );
}

function ContentBody({ text }: { text: string }): JSX.Element {
  if (text === "") return <span style={css("color:var(--text-faint);")}>{"\u2014"}</span>;
  if (looksLikeCode(text)) return <pre style={monoBlock}>{text}</pre>;
  return <div style={proseBlock}>{text}</div>;
}

function fmtScore(score: number): string {
  if (!Number.isFinite(score)) return "\u2014";
  return score.toFixed(3);
}

function fmtInt(n: number): string {
  if (!Number.isFinite(n)) return "\u2014";
  return n.toLocaleString();
}

function ellipsize(text: string, max = 140): string {
  const single = text.replace(/\s+/g, " ").trim();
  return single.length <= max ? single : `${single.slice(0, max - 1)}\u2026`;
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

/* ----------------------------- SEARCH panel ------------------------------ */

interface SearchState {
  query: string;
  namespacePrefix: string;
  topK: number;
}

function SearchPanel(): JSX.Element {
  const [state, setState] = useState<SearchState>({
    query: "",
    namespacePrefix: "",
    topK: 10,
  });
  const search = useKnowledgeSearch();

  const submit = (e: FormEvent<HTMLFormElement>): void => {
    e.preventDefault();
    const query = state.query.trim();
    if (query === "") return;
    const topK = Number.isFinite(state.topK) && state.topK > 0 ? Math.min(state.topK, 100) : 10;
    const body = {
      query,
      top_k: topK,
      ...(state.namespacePrefix.trim() ? { namespace_prefix: state.namespacePrefix.trim() } : {}),
    };
    search.mutate(body);
  };

  return (
    <div style={panelBox}>
      <div style={panelTitle}>
        <span style={dot} />
        <span style={css("color:var(--text-primary);")}>search</span>
        <span style={css("flex:1;")} />
        <span style={css("color:var(--text-faint);text-transform:none;letter-spacing:0.04em;")}>
          {search.data ? `${search.data.length} hit${search.data.length === 1 ? "" : "s"}` : ""}
        </span>
      </div>
      <div style={{ ...scroll, ...pad, display: "flex", flexDirection: "column", gap: 12 }}>
        <form onSubmit={submit} style={css("display:flex;flex-direction:column;gap:9px;")}>
          <label style={labelStyle}>
            query
            <input
              type="text"
              value={state.query}
              onChange={(e: ChangeEvent<HTMLInputElement>) =>
                setState((s) => ({ ...s, query: e.target.value }))
              }
              placeholder="what should the corpus surface?"
              style={inputStyle}
              autoComplete="off"
            />
          </label>
          <div style={css("display:grid;grid-template-columns:1fr 120px auto;gap:9px;align-items:end;")}>
            <label style={labelStyle}>
              namespace prefix (optional)
              <input
                type="text"
                value={state.namespacePrefix}
                onChange={(e: ChangeEvent<HTMLInputElement>) =>
                  setState((s) => ({ ...s, namespacePrefix: e.target.value }))
                }
                placeholder="e.g. vulnerability/"
                style={inputStyle}
                autoComplete="off"
              />
            </label>
            <label style={labelStyle}>
              top k
              <input
                type="number"
                min={1}
                max={100}
                value={state.topK}
                onChange={(e: ChangeEvent<HTMLInputElement>) => {
                  const parsed = Number.parseInt(e.target.value, 10);
                  setState((s) => ({ ...s, topK: Number.isFinite(parsed) ? parsed : 10 }));
                }}
                style={inputStyle}
              />
            </label>
            <button type="submit" style={btnPrimary} disabled={state.query.trim() === "" || search.isPending}>
              {search.isPending ? "searching\u2026" : "search"}
            </button>
          </div>
        </form>

        {search.isPending ? (
          <div style={emptyNote}>routing query&#8230;</div>
        ) : search.isError ? (
          <div style={{ ...emptyNote, color: H_WARN }}>
            search failed &mdash; {search.error instanceof Error ? search.error.message : "request error"}
          </div>
        ) : search.data ? (
          search.data.length === 0 ? (
            <div style={emptyNote}>no entries cleared the retrieval floor for this query.</div>
          ) : (
            <div style={stack}>{search.data.map((hit) => <HitCard key={hit.id} hit={hit} />)}</div>
          )
        ) : (
          <div style={emptyNote}>enter a query above to route the corpus.</div>
        )}
      </div>
    </div>
  );
}

function HitCard({ hit }: { hit: KnowledgeHit }): JSX.Element {
  return (
    <div style={hitCard}>
      <div style={hitHeader}>
        <span style={scoreChip} title="post-routing similarity score">
          score {fmtScore(hit.score)}
        </span>
        <span style={chip} title="namespace">
          {hit.namespace || "\u2014"}
        </span>
        {hit.source_type ? <span style={chipAccent}>{hit.source_type}</span> : null}
        {hit.model_id ? <span style={chipFaint}>model {hit.model_id}</span> : null}
        <span style={css("flex:1;")} />
        <span style={css("font-family:var(--font-mono);font-size:9px;color:var(--text-faint);letter-spacing:0.04em;")}>
          {hit.id}
        </span>
      </div>
      <ContentBody text={hit.content ?? ""} />
    </div>
  );
}

/* --------------------------- CORPUS STATS panel -------------------------- */

function StatsPanel(): JSX.Element {
  const stats = useKnowledgeStats();

  return (
    <div style={panelBox}>
      <div style={panelTitle}>
        <span style={dot} />
        <span style={css("color:var(--text-primary);")}>corpus stats</span>
        <span style={css("flex:1;")} />
      </div>
      <div style={{ ...scroll, ...pad }}>
        {stats.isLoading ? (
          <div style={emptyNote}>loading corpus stats&#8230;</div>
        ) : stats.isError ? (
          <div style={{ ...emptyNote, color: H_WARN }}>
            could not load /platform/knowledge/stats &mdash;{" "}
            {stats.error instanceof Error ? stats.error.message : "request failed"}
          </div>
        ) : !stats.data ? (
          <div style={emptyNote}>no stats returned.</div>
        ) : (
          <div style={css("display:flex;flex-direction:column;gap:14px;min-width:0;")}>
            <div style={css("display:grid;grid-template-columns:1fr 1fr;gap:10px;")}>
              <div style={statFigure}>
                <span style={statValue}>{fmtInt(stats.data.total_entries)}</span>
                <span style={statLabel}>total entries</span>
              </div>
              <div style={statFigure}>
                <span style={statValue}>{fmtInt(stats.data.edge_count)}</span>
                <span style={statLabel}>knowledge edges</span>
              </div>
            </div>
            <BucketPanel label="by namespace" buckets={stats.data.by_namespace} />
            <BucketPanel label="by source type" buckets={stats.data.by_source_type} />
            <BucketPanel label="by model" buckets={stats.data.by_model} />
          </div>
        )}
      </div>
    </div>
  );
}

function BucketPanel({ label, buckets }: { label: string; buckets: KnowledgeBucket[] }): JSX.Element {
  const max = useMemo(() => buckets.reduce((m, b) => (b.count > m ? b.count : m), 0), [buckets]);
  return (
    <div style={css("display:flex;flex-direction:column;gap:5px;min-width:0;")}>
      <div style={css("font-family:var(--font-mono);font-size:9px;letter-spacing:0.14em;text-transform:uppercase;color:var(--text-faint);")}>
        {label}
      </div>
      {buckets.length === 0 ? (
        <div style={css("font-family:var(--font-mono);font-size:10.5px;color:var(--text-faint);letter-spacing:0.04em;")}>
          &mdash; empty &mdash;
        </div>
      ) : (
        <div>
          {buckets.map((b) => {
            const pct = max > 0 ? Math.max(2, Math.round((b.count / max) * 100)) : 0;
            return (
              <div key={b.key} style={bucketRow}>
                <span style={bucketLabelCell} title={b.key}>{b.key || "\u2014"}</span>
                <span style={bucketCountCell}>{fmtInt(b.count)}</span>
                <div style={barTrack} aria-hidden="true">
                  <div
                    style={{
                      position: "absolute",
                      left: 0,
                      top: 0,
                      bottom: 0,
                      width: `${pct}%`,
                      background: "color-mix(in srgb,var(--accent) 55%,transparent)",
                    }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

/* -------------------------- ENTRIES BROWSER panel ------------------------ */

interface EntriesFilters {
  namespace: string;
  source_type: string;
  q: string;
}

function EntriesPanel(): JSX.Element {
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
          <span style={css("font-family:var(--font-mono);font-size:8.5px;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-faint);")}>
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
          <span style={css("font-family:var(--font-mono);font-size:9px;color:var(--text-faint);letter-spacing:0.06em;text-transform:uppercase;")}>
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
        <span style={css("font-family:var(--font-mono);font-size:9px;color:var(--text-faint);letter-spacing:0.04em;")}>
          {entry.id}
        </span>
        <button
          type="button"
          onClick={onClose}
          style={css("background:transparent;border:0;color:var(--text-faint);cursor:pointer;font-size:12px;margin-left:6px;")}
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

/* ------------------------------ INGEST modal ----------------------------- */

const SCOPES = [
  { value: "workspace", label: "workspace" },
  { value: "team", label: "team" },
  { value: "global", label: "global" },
  { value: "agent", label: "agent" },
] as const;

type IngestScope = (typeof SCOPES)[number]["value"];

/** Live preview of the write namespace the backend will resolve, so the
 *  operator sees exactly where the note lands before submitting. Mirrors
 *  `_resolve_operator_namespace` in the router. */
function previewNamespace(module: string, scope: IngestScope, scopeId: string): string {
  const id = scopeId.trim();
  if (scope === "agent") return id ? `agent:${id}` : "agent:<name>";
  if (scope === "global") return `${module}.operator_note.global`;
  return `${module}.operator_note.${scope}.${id || "<id>"}`;
}

function IngestModal({ onClose }: { onClose: () => void }): JSX.Element {
  const [module, setModule] = useState<"vr" | "malware">("vr");
  const [scope, setScope] = useState<IngestScope>("workspace");
  const [scopeId, setScopeId] = useState("");
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");

  const ingest = useIngestKnowledge();
  const ws = useWorkspaces(module);

  const needsId = scope !== "global";
  const showWsSelect = scope === "workspace";
  const canSubmit =
    content.trim().length > 0 &&
    (!needsId || scopeId.trim().length > 0) &&
    !ingest.isPending;

  const submit = (e: FormEvent<HTMLFormElement>): void => {
    e.preventDefault();
    if (!canSubmit) return;
    ingest.mutate({
      module,
      scope,
      scope_id: needsId ? scopeId.trim() : undefined,
      title: title.trim() || undefined,
      content,
    });
  };

  const result = ingest.data;

  return (
    <div style={modalBackdrop} onClick={onClose}>
      <div style={modalCard} onClick={(e) => e.stopPropagation()}>
        <div style={panelTitle}>
          <span style={dot} />
          <span style={css("color:var(--text-primary);")}>add operator note</span>
          <span style={css("flex:1;")} />
          <button type="button" style={btnGhost} onClick={onClose}>
            {"\u2715 close"}
          </button>
        </div>

        {result ? (
          <div style={{ ...pad, ...stack, overflow: "auto" }}>
            <div style={css("font-family:var(--font-mono);font-size:11px;color:var(--status-ok);")}>
              note {result.operation} &mdash; entry #{result.entry_id ?? "?"}
            </div>
            <label style={labelStyle}>
              landed namespace
              <span style={chipAccent}>{result.namespace}</span>
            </label>
            <div style={css("font-family:var(--font-mono);font-size:10px;color:var(--text-faint);line-height:1.55;")}>
              agents in this scope recall it on their next turn.
            </div>
            <div style={css("display:flex;gap:8px;")}>
              <button type="button" style={btnPrimary} onClick={() => ingest.reset()}>
                add another
              </button>
              <button type="button" style={btnGhost} onClick={onClose}>
                done
              </button>
            </div>
          </div>
        ) : (
          <form onSubmit={submit} style={{ ...pad, ...stack, overflow: "auto" }}>
            <div style={css("display:grid;grid-template-columns:1fr 1fr;gap:10px;")}>
              <label style={labelStyle}>
                module
                <select
                  style={inputStyle}
                  value={module}
                  disabled={scope === "agent"}
                  onChange={(e: ChangeEvent<HTMLSelectElement>) =>
                    setModule(e.target.value === "malware" ? "malware" : "vr")
                  }
                >
                  <option value="vr">vr</option>
                  <option value="malware">malware</option>
                </select>
              </label>
              <label style={labelStyle}>
                scope
                <select
                  style={inputStyle}
                  value={scope}
                  onChange={(e: ChangeEvent<HTMLSelectElement>) => {
                    setScope(e.target.value as IngestScope);
                    setScopeId("");
                  }}
                >
                  {SCOPES.map((s) => (
                    <option key={s.value} value={s.value}>
                      {s.label}
                    </option>
                  ))}
                </select>
              </label>
            </div>

            {needsId ? (
              <label style={labelStyle}>
                {scope === "workspace" ? "workspace" : scope === "team" ? "team id" : "agent name"}
                {showWsSelect ? (
                  <select
                    style={inputStyle}
                    value={scopeId}
                    onChange={(e: ChangeEvent<HTMLSelectElement>) => setScopeId(e.target.value)}
                  >
                    <option value="">
                      {ws.isLoading ? "loading\u2026" : ws.isError ? "workspaces unavailable" : "select workspace\u2026"}
                    </option>
                    {(ws.data ?? []).map((w) => (
                      <option key={w.id} value={w.id}>
                        {w.name} ({w.id.slice(0, 8)})
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    type="text"
                    style={inputStyle}
                    value={scopeId}
                    onChange={(e: ChangeEvent<HTMLInputElement>) => setScopeId(e.target.value)}
                    placeholder={scope === "team" ? "team id" : "agent name"}
                    autoComplete="off"
                  />
                )}
              </label>
            ) : null}

            <label style={labelStyle}>
              title (optional)
              <input
                type="text"
                style={inputStyle}
                value={title}
                onChange={(e: ChangeEvent<HTMLInputElement>) => setTitle(e.target.value)}
                maxLength={200}
                autoComplete="off"
              />
            </label>

            <label style={labelStyle}>
              content
              <textarea
                style={textareaStyle}
                value={content}
                onChange={(e: ChangeEvent<HTMLTextAreaElement>) => setContent(e.target.value)}
                placeholder="knowledge the agents should recall in this scope\u2026"
                rows={7}
              />
            </label>

            <label style={labelStyle}>
              target namespace
              <span style={chip}>{previewNamespace(module, scope, scopeId)}</span>
            </label>

            {ingest.isError ? (
              <div style={css("font-family:var(--font-mono);font-size:10.5px;color:#ffb85f;line-height:1.5;")}>
                {ingest.error instanceof Error ? ingest.error.message : "ingest failed"}
              </div>
            ) : null}

            <div style={css("display:flex;gap:8px;align-items:center;")}>
              <button type="submit" style={canSubmit ? btnPrimary : btnGhostDisabled} disabled={!canSubmit}>
                {ingest.isPending ? "storing\u2026" : "store note"}
              </button>
              <button type="button" style={btnGhost} onClick={onClose}>
                cancel
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

/* --------------------------------- page ---------------------------------- */

export default function KnowledgePage(props: ModulePageProps): JSX.Element {
  const { onBack, onMinimize, isFullscreen, onToggleFullscreen } = props;
  const [ingestOpen, setIngestOpen] = useState(false);

  return (
    <div
      style={{
        position: "absolute",
        inset: 0,
        display: "flex",
        flexDirection: "column",
        background: "transparent",
        fontFamily: "var(--font-mono)",
        color: "var(--text-primary)",
      }}
    >
      {ingestOpen ? <IngestModal onClose={() => setIngestOpen(false)} /> : null}
      <header
        style={{
          flex: "0 0 auto",
          display: "flex",
          alignItems: "center",
          gap: 10,
          padding: "8px 14px",
          background: "var(--surface-chrome)",
          borderBottom: "1px solid var(--border)",
          fontSize: 10.5,
          letterSpacing: "0.12em",
          textTransform: "uppercase",
          color: "var(--text-muted)",
        }}
      >
        <span
          style={{
            width: 9,
            height: 9,
            borderRadius: 1,
            background: "var(--accent)",
            boxShadow: "0 0 7px var(--accent)",
          }}
        />
        <span style={{ color: "var(--text-primary)", fontWeight: 700, letterSpacing: "0.16em" }}>
          admin &middot; knowledge
        </span>
        <span style={{ color: "var(--text-faint)", textTransform: "none", letterSpacing: "0.04em" }}>
          platform RAG corpus &mdash; entries, retrieval, edges
        </span>
        <span style={{ flex: 1 }} />
        <button type="button" style={headerBtn} onClick={() => setIngestOpen(true)}>
          + operator note
        </button>
      </header>

      <main
        style={{
          flex: 1,
          minHeight: 0,
          display: "grid",
          gridTemplateRows: "minmax(260px,42%) minmax(260px,58%)",
          gap: 10,
          padding: 12,
        }}
      >
        <div style={twoUp}>
          <SearchPanel />
          <StatsPanel />
        </div>
        <EntriesPanel />
      </main>

      <footer
        style={{
          flex: "0 0 24px",
          height: 24,
          display: "flex",
          alignItems: "stretch",
          background: "var(--surface-chrome)",
          borderTop: "2px solid var(--border)",
          fontSize: 9.5,
          letterSpacing: "0.1em",
          textTransform: "uppercase",
          color: "var(--text-faint)",
        }}
      >
        <span
          style={{
            display: "flex",
            alignItems: "center",
            padding: "0 11px",
            background: "var(--status-ok)",
            color: "var(--text-on-accent)",
            fontWeight: 700,
            letterSpacing: "0.14em",
          }}
        >
          admin &middot; knowledge
        </span>
        <span
          style={{
            display: "flex",
            alignItems: "center",
            padding: "0 11px",
            textTransform: "none",
            letterSpacing: "0.03em",
            color: "var(--text-muted)",
          }}
        >
          KnowledgeEntryRecord &middot; KnowledgeEntryEdge &middot; retrieve_routed
        </span>
        <span style={{ flex: 1 }} />
        {onToggleFullscreen
          ? ctlBtn(isFullscreen ? "\u2921" : "\u2922", isFullscreen ? "exit fullscreen" : "fullscreen", onToggleFullscreen)
          : null}
        {ctlBtn("\u2014", "minimize", onMinimize)}
        {ctlBtn("\u2715", "close", onBack)}
      </footer>
    </div>
  );
}
