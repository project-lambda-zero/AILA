/**
 * SearchPage -- dedicated global search surface backed by GET /search.
 *
 * Bare content: protectPage() in router.tsx already wraps the page in
 * PageFrame (title bar + corner brackets). See CLAUDE.md #16.
 *
 * Permalinkable: `q`, `types`, and `offset` all live in the URL search
 * params so any hit list can be linked or bookmarked directly.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router";

import { WindowPanel } from "@/components/aila/WindowPanel";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import {
  SectionHeader,
  DataGrid,
  MonoBadge,
  FilterChip,
  toneColor,
} from "@/components/aila/mock";
import { ApiHttpError } from "@platform/api/http";

import {
  entityRoute,
  entityTypeLabel,
  entityTypeSeverity,
  useGlobalSearch,
  type SearchResult,
} from "./searchQueries";

// ---------------------------------------------------------------------------
// Facet chip catalog. `entity_type` values are backend-defined
// (see aila/api/routers/search.py). Modules extend the set via their
// `latest_findings` contribution -- we display any type that shows up in
// the current result set even if it's not pre-registered here.
// ---------------------------------------------------------------------------

const KNOWN_FACETS: readonly string[] = [
  "system",
  "finding",
  "session",
  "cve",
  "task",
  "investigation",
];

const PAGE_SIZE = 25;

// ---------------------------------------------------------------------------
// Style tokens
// ---------------------------------------------------------------------------

const ACTION_BUTTON_STYLE: React.CSSProperties = {
  height: 26,
  fontSize: 9.5,
  padding: "0 11px",
  textTransform: "uppercase",
  letterSpacing: "0.1em",
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  cursor: "pointer",
  fontFamily: "var(--font-mono)",
};

const SEARCH_INPUT_STYLE: React.CSSProperties = {
  height: 32,
  fontSize: 12,
  padding: "0 12px",
  minWidth: 380,
  background: "var(--surface-sunk)",
  color: "var(--text-primary)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  outline: "none",
  fontFamily: "var(--font-mono)",
};

// ---------------------------------------------------------------------------
// URL <-> state helpers
// ---------------------------------------------------------------------------

function parseFacetParam(raw: string | null): string[] {
  if (!raw) return [];
  return raw
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function SearchPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();

  const urlQuery = searchParams.get("q") ?? "";
  const activeFacets = useMemo(
    () => parseFacetParam(searchParams.get("types")),
    [searchParams],
  );
  const offset = Number.parseInt(searchParams.get("offset") ?? "0", 10) || 0;

  // Local input state so typing feels immediate; URL commits on submit
  // or after a short idle window.
  const [inputValue, setInputValue] = useState(urlQuery);
  const debounceRef = useRef<number | null>(null);

  useEffect(() => {
    // Reflect back-nav (URL change) into the input.
    setInputValue(urlQuery);
  }, [urlQuery]);

  useEffect(() => {
    if (inputValue === urlQuery) return;
    if (debounceRef.current !== null) {
      window.clearTimeout(debounceRef.current);
    }
    debounceRef.current = window.setTimeout(() => {
      const next = new URLSearchParams(searchParams);
      if (inputValue.trim().length === 0) {
        next.delete("q");
      } else {
        next.set("q", inputValue);
      }
      next.delete("offset");
      setSearchParams(next, { replace: true });
    }, 250);
    return () => {
      if (debounceRef.current !== null) {
        window.clearTimeout(debounceRef.current);
        debounceRef.current = null;
      }
    };
  }, [inputValue, urlQuery, searchParams, setSearchParams]);

  const searchQuery = useGlobalSearch({
    q: urlQuery,
    entityTypes: activeFacets,
    limit: PAGE_SIZE,
    offset,
  });

  function toggleFacet(type: string) {
    const next = new URLSearchParams(searchParams);
    const current = new Set(activeFacets);
    if (current.has(type)) {
      current.delete(type);
    } else {
      current.add(type);
    }
    if (current.size === 0) {
      next.delete("types");
    } else {
      next.set("types", Array.from(current).sort().join(","));
    }
    next.delete("offset");
    setSearchParams(next, { replace: true });
  }

  function clearFacets() {
    const next = new URLSearchParams(searchParams);
    next.delete("types");
    next.delete("offset");
    setSearchParams(next, { replace: true });
  }

  function changeOffset(nextOffset: number) {
    const next = new URLSearchParams(searchParams);
    if (nextOffset <= 0) {
      next.delete("offset");
    } else {
      next.set("offset", String(nextOffset));
    }
    setSearchParams(next, { replace: true });
  }

  function handleResultClick(result: SearchResult) {
    navigate(entityRoute(result));
  }

  const results = searchQuery.data?.results ?? [];
  const total = searchQuery.data?.total ?? 0;
  const hasQuery = urlQuery.trim().length > 0;
  const isLoading = searchQuery.isLoading && hasQuery;
  const isFetching = searchQuery.isFetching && hasQuery;

  // Union of pre-registered facets with types actually returned so a
  // module-contributed type still gets a chip once results come back.
  const facetList = useMemo(() => {
    const set = new Set<string>(KNOWN_FACETS);
    for (const item of results) set.add(item.entity_type);
    for (const type of activeFacets) set.add(type);
    return Array.from(set);
  }, [results, activeFacets]);

  // Bucket results per entity_type so each scope renders in its own panel.
  const resultsByScope = useMemo(() => {
    const buckets = new Map<string, SearchResult[]>();
    for (const r of results) {
      const list = buckets.get(r.entity_type);
      if (list) list.push(r);
      else buckets.set(r.entity_type, [r]);
    }
    return Array.from(buckets.entries());
  }, [results]);

  const pageStart = results.length === 0 ? 0 : offset + 1;
  const pageEnd = offset + results.length;
  const canPrev = offset > 0;
  const canNext = offset + PAGE_SIZE < total;

  const errorMessage = useMemo(() => {
    const err = searchQuery.error;
    if (!err) return null;
    if (err instanceof ApiHttpError) {
      return err.envelope?.message ?? err.detail ?? err.message;
    }
    return err instanceof Error ? err.message : "Search failed.";
  }, [searchQuery.error]);

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <SectionHeader
        icon={"\u25ce"}
        title="global search"
        actions={
          <input
            type="search"
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            placeholder="search systems, findings, sessions, module entities..."
            className="font-mono"
            autoFocus
            aria-label="Global search query"
            style={SEARCH_INPUT_STYLE}
          />
        }
      />

      {/* Facet chip row */}
      <div className="flex items-center flex-wrap" style={{ gap: 8 }}>
        <span
          className="font-mono"
          style={{
            fontSize: 10,
            color: "var(--text-muted)",
            textTransform: "uppercase",
            letterSpacing: "0.14em",
            marginRight: 4,
          }}
        >
          facets
        </span>
        {facetList.map((facet) => (
          <FilterChip
            key={facet}
            active={activeFacets.includes(facet)}
            color={toneColor(
              entityTypeSeverity(facet) === "neutral"
                ? "muted"
                : entityTypeSeverity(facet),
            )}
            onClick={() => toggleFacet(facet)}
          >
            {entityTypeLabel(facet)}
          </FilterChip>
        ))}
        {activeFacets.length > 0 && (
          <button
            type="button"
            onClick={clearFacets}
            style={ACTION_BUTTON_STYLE}
          >
            clear
          </button>
        )}
      </div>

      {/* Results */}
      {!hasQuery ? (
        <WindowPanel title="global search" tone="muted">
          <div
            className="flex flex-col items-center justify-center"
            style={{ gap: 8, padding: 32, textAlign: "center", minHeight: 120 }}
          >
            <div
              className="font-mono uppercase"
              style={{ fontSize: 11, letterSpacing: "0.14em", color: "var(--text-primary)" }}
            >
              Type to search across the platform
            </div>
            <div
              className="font-mono"
              style={{ fontSize: 10.5, color: "var(--text-muted)", maxWidth: 440 }}
            >
              Systems, findings, sessions, and any module-contributed entities are searched in a single pass. Facet chips narrow by entity type.
            </div>
          </div>
        </WindowPanel>
      ) : isLoading ? (
        <WindowPanel title="results" status="LOADING" tone="muted">
          <LoadingSkeletonGroup lines={5} />
        </WindowPanel>
      ) : errorMessage ? (
        <WindowPanel title="results" tone="warn">
          <div
            className="font-mono"
            style={{
              color: "var(--status-warn)",
              fontSize: 12,
              padding: "6px 2px",
            }}
          >
            search failed: {errorMessage}
          </div>
        </WindowPanel>
      ) : results.length === 0 ? (
        <WindowPanel title="results" tone="muted">
          <div
            className="flex flex-col items-center justify-center"
            style={{ gap: 8, padding: 32, textAlign: "center", minHeight: 120 }}
          >
            <div
              className="font-mono uppercase"
              style={{ fontSize: 11, letterSpacing: "0.14em", color: "var(--text-primary)" }}
            >
              {`No results for "${urlQuery}"`}
            </div>
            <div
              className="font-mono"
              style={{ fontSize: 10.5, color: "var(--text-muted)", maxWidth: 440 }}
            >
              Try a shorter query, remove active facets, or check spelling.
            </div>
          </div>
        </WindowPanel>
      ) : (
        <>
          {/* Pager row */}
          <div
            className="flex items-center justify-between font-mono"
            style={{
              fontSize: 11,
              color: "var(--text-muted)",
            }}
          >
            <span>
              showing {pageStart}--{pageEnd} of {total}
              {isFetching && !searchQuery.isLoading
                ? " (refreshing...)"
                : ""}
            </span>
            <div className="flex items-center" style={{ gap: 6 }}>
              <button
                type="button"
                disabled={!canPrev}
                onClick={() =>
                  changeOffset(Math.max(0, offset - PAGE_SIZE))
                }
                style={{
                  ...ACTION_BUTTON_STYLE,
                  opacity: canPrev ? 1 : 0.35,
                  cursor: canPrev ? "pointer" : "not-allowed",
                }}
              >
                {"\u2039"} prev
              </button>
              <button
                type="button"
                disabled={!canNext}
                onClick={() => changeOffset(offset + PAGE_SIZE)}
                style={{
                  ...ACTION_BUTTON_STYLE,
                  opacity: canNext ? 1 : 0.35,
                  cursor: canNext ? "pointer" : "not-allowed",
                }}
              >
                next {"\u203a"}
              </button>
            </div>
          </div>

          {/* Per-scope result panels */}
          {resultsByScope.map(([scope, rows]) => (
            <WindowPanel
              key={scope}
              title={entityTypeLabel(scope).toLowerCase()}
              status={`${rows.length} HIT${rows.length === 1 ? "" : "S"}`}
              tone="muted"
              flush
            >
              <DataGrid<SearchResult>
                columns={[
                  { label: "TYPE", width: "120px" },
                  { label: "TITLE / ID", width: "minmax(200px, 1fr)" },
                  { label: "MODULE", width: "130px" },
                  { label: "SCORE", width: "80px", align: "right" },
                ]}
                rows={rows}
                getKey={(r) =>
                  `${r.entity_type}:${r.module_id ?? "-"}:${r.entity_id}`
                }
                onRowClick={handleResultClick}
                renderCells={(r) => [
                  <MonoBadge
                    tone={
                      entityTypeSeverity(r.entity_type) === "neutral"
                        ? "muted"
                        : entityTypeSeverity(r.entity_type)
                    }
                  >
                    {entityTypeLabel(r.entity_type)}
                  </MonoBadge>,
                  <div
                    className="flex flex-col"
                    style={{ gap: 2, minWidth: 0 }}
                  >
                    <span
                      className="font-mono truncate"
                      style={{
                        color: "var(--text-primary)",
                        fontSize: 12,
                      }}
                    >
                      {r.title || r.entity_id}
                    </span>
                    {r.snippet && (
                      <span
                        className="font-mono truncate"
                        style={{
                          color: "var(--text-muted)",
                          fontSize: 10,
                        }}
                      >
                        {r.snippet}
                      </span>
                    )}
                    <span
                      className="font-mono truncate"
                      style={{
                        color: "var(--text-faint)",
                        fontSize: 9.5,
                        textTransform: "uppercase",
                        letterSpacing: "0.1em",
                      }}
                    >
                      id {r.entity_id}
                    </span>
                  </div>,
                  <span
                    className="font-mono"
                    style={{ color: "var(--text-muted)", fontSize: 11 }}
                  >
                    {r.module_id ?? "\u2014"}
                  </span>,
                  <span
                    className="font-mono tabular-nums"
                    style={{ color: "var(--accent)", fontSize: 11 }}
                  >
                    {r.score.toFixed(2)}
                  </span>,
                ]}
              />
            </WindowPanel>
          ))}
        </>
      )}
    </div>
  );
}
