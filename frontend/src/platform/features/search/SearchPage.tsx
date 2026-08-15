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
import { MagnifyingGlass } from "@phosphor-icons/react/dist/csr/MagnifyingGlass";
import { X } from "@phosphor-icons/react/dist/csr/X";
import { CaretLeft } from "@phosphor-icons/react/dist/csr/CaretLeft";
import { CaretRight } from "@phosphor-icons/react/dist/csr/CaretRight";

import { AilaCard } from "@/components/aila/AilaCard";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { EmptyState } from "@/components/aila/EmptyState";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
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
// Facet chip
// ---------------------------------------------------------------------------

function FacetChip({
  label,
  active,
  onToggle,
}: {
  label: string;
  active: boolean;
  onToggle: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onToggle}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-[2px] border px-2 py-1 font-mono text-[11px] uppercase tracking-wider transition-colors",
        active
          ? "border-accent bg-accent/10 text-accent"
          : "border-border bg-surface text-text-muted hover:border-accent/50 hover:text-text",
      )}
      aria-pressed={active}
    >
      <span>{entityTypeLabel(label)}</span>
      {active && <X size={11} weight="bold" />}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Result card
// ---------------------------------------------------------------------------

function ResultCard({
  result,
  onSelect,
}: {
  result: SearchResult;
  onSelect: (result: SearchResult) => void;
}) {
  return (
    <button
      type="button"
      onClick={() => onSelect(result)}
      className="group w-full text-left"
    >
      <AilaCard
        variant="default"
        padding="md"
        className="transition-colors group-hover:border-accent/60"
      >
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <AilaBadge severity={entityTypeSeverity(result.entity_type)} size="sm">
                {entityTypeLabel(result.entity_type)}
              </AilaBadge>
              {result.module_id && (
                <AilaBadge severity="neutral" size="sm">
                  {result.module_id}
                </AilaBadge>
              )}
              <span className="font-mono text-[10px] uppercase tracking-wider text-text-muted">
                score {result.score.toFixed(2)}
              </span>
            </div>
            <h3 className="mt-2 truncate font-mono text-sm font-semibold text-text">
              {result.title || result.entity_id}
            </h3>
            {result.snippet && (
              <p className="mt-1 line-clamp-2 font-mono text-xs text-text-muted">
                {result.snippet}
              </p>
            )}
            <p className="mt-1 font-mono text-[10px] uppercase tracking-wider text-text-muted">
              id {result.entity_id}
            </p>
          </div>
        </div>
      </AilaCard>
    </button>
  );
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
    <div className="flex flex-col gap-6">
      {/* Query input */}
      <WindowPanel title="Search" tone="muted">
        <div className="flex flex-col gap-3">
          <div className="relative">
            <MagnifyingGlass
              className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-muted"
              aria-hidden="true"
            />
            <Input
              type="search"
              value={inputValue}
              onChange={(event) => setInputValue(event.target.value)}
              placeholder="Search systems, findings, sessions, module entities…"
              className="pl-9 font-mono"
              autoFocus
              aria-label="Global search query"
            />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[10px] uppercase tracking-wider text-text-muted">
              Facets
            </span>
            {facetList.map((facet) => (
              <FacetChip
                key={facet}
                label={facet}
                active={activeFacets.includes(facet)}
                onToggle={() => toggleFacet(facet)}
              />
            ))}
            {activeFacets.length > 0 && (
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={clearFacets}
                className="h-6 px-2 font-mono text-[10px] uppercase tracking-wider"
              >
                Clear
              </Button>
            )}
          </div>
        </div>
      </WindowPanel>

      {/* Results */}
      {!hasQuery ? (
        <EmptyState
          icon={<MagnifyingGlass className="h-10 w-10" />}
          title="Type to search across the platform"
          description="Systems, findings, sessions, and any module-contributed entities are searched in a single pass. Facet chips narrow by entity type."
        />
      ) : isLoading ? (
        <LoadingSkeletonGroup lines={5} />
      ) : errorMessage ? (
        <EmptyState
          icon={<X className="h-10 w-10" />}
          title="Search failed"
          description={errorMessage}
        />
      ) : results.length === 0 ? (
        <EmptyState
          icon={<MagnifyingGlass className="h-10 w-10" />}
          title={`No results for "${urlQuery}"`}
          description="Try a shorter query, remove active facets, or check spelling."
        />
      ) : (
        <>
          <div className="flex items-center justify-between font-mono text-[11px] text-text-muted">
            <span>
              Showing {pageStart}--{pageEnd} of {total}
              {isFetching && !searchQuery.isLoading ? " (refreshing…)" : ""}
            </span>
            <div className="flex items-center gap-1">
              <Button
                type="button"
                variant="ghost"
                size="sm"
                disabled={!canPrev}
                onClick={() => changeOffset(Math.max(0, offset - PAGE_SIZE))}
              >
                <CaretLeft className="h-3.5 w-3.5" />
                Prev
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                disabled={!canNext}
                onClick={() => changeOffset(offset + PAGE_SIZE)}
              >
                Next
                <CaretRight className="h-3.5 w-3.5" />
              </Button>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
            {results.map((result) => (
              <ResultCard
                key={`${result.entity_type}:${result.module_id ?? "-"}:${result.entity_id}`}
                result={result}
                onSelect={handleResultClick}
              />
            ))}
          </div>
        </>
      )}
    </div>
  );
}
