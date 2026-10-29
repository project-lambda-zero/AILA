/** The knowledge SEARCH panel: POST /platform/knowledge/search with the
 * namespace-prefix and top-k controls, backed by the mutation hook. */

import { useState } from "react";
import type { ChangeEvent, FormEvent, JSX } from "react";

import { useKnowledgeSearch } from "../../../api/knowledge";
import type { KnowledgeHit } from "../../../api/knowledge";
import { css } from "../../css";
import { ContentBody, fmtScore } from "./helpers";
import {
  btnPrimary,
  chip,
  chipAccent,
  chipFaint,
  dot,
  emptyNote,
  H_WARN,
  hitCard,
  hitHeader,
  inputStyle,
  labelStyle,
  pad,
  panelBox,
  panelTitle,
  scoreChip,
  scroll,
  stack,
} from "./styles";

interface SearchState {
  query: string;
  namespacePrefix: string;
  topK: number;
}

export function SearchPanel(): JSX.Element {
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
    const body: { query: string; top_k: number; namespace_prefix?: string } = { query, top_k: topK };
    const namespacePrefix = state.namespacePrefix.trim();
    if (namespacePrefix !== "") body.namespace_prefix = namespacePrefix;
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
        <span style={css("font-family:var(--font-mono);font-size:11px;color:var(--text-faint);letter-spacing:0.04em;")}>
          {hit.id}
        </span>
      </div>
      <ContentBody text={hit.content ?? ""} />
    </div>
  );
}
