/**
 * JqlFilterBar -- pragmatic JQL-inspired chip-based filter input.
 *
 * Design intent (Plan 176e P3):
 *   - No parser. Each chip is a single `field op value` triple or a plain-text
 *     search clause.
 *   - Operators: `:` (equality), `>` (numeric greater-than), `<` (numeric less-than).
 *   - Plain text with no operator becomes a `search` clause.
 *   - Filter state is URL-synced so operators can share links. A single
 *     `f` query param is repeated once per filter (e.g. `?f=module:vuln&f=user:admin`).
 *
 * Reused by AuditLogsPage and LLMLogPage -- the caller supplies which fields
 * are available and emits `onChange` whenever the filter set changes.
 */
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type KeyboardEvent,
} from "react";
import { X } from "@phosphor-icons/react/dist/csr/X";
import { Funnel } from "@phosphor-icons/react/dist/csr/Funnel";
import { MagnifyingGlass } from "@phosphor-icons/react/dist/csr/MagnifyingGlass";
import { useSearchParams } from "react-router";

import { MonoBadge } from "@/components/aila/mock";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type JqlOperator = ":" | ">" | "<";

export interface JqlFilter {
  field: string;
  operator: JqlOperator;
  value: string;
}

export interface JqlFieldSpec {
  key: string;
  label: string;
  operators: JqlOperator[];
  /** Optional async provider for autocomplete value suggestions. */
  suggestions?: () => Promise<string[]>;
}

export interface JqlFilterBarProps {
  fields: JqlFieldSpec[];
  /** Uncontrolled initial value; subsequent updates come from URL. */
  initialFilters?: JqlFilter[];
  onChange: (filters: JqlFilter[]) => void;
  /** When true (default), sync filters to the `?f=` URL query param. */
  urlSync?: boolean;
  placeholder?: string;
}

// ---------------------------------------------------------------------------
// Parsing / serialization
// ---------------------------------------------------------------------------

const SEARCH_FIELD = "search";

/**
 * Parse a single raw chip string into a JqlFilter.
 * Returns null for empty input. Falls back to a plain-text `search` filter
 * when no operator is present.
 */
export function parseFilterToken(raw: string): JqlFilter | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;

  // Match the FIRST operator only so values like `cost>0.5` parse cleanly
  // without stripping trailing characters that happen to match other operators.
  const match = trimmed.match(/^([a-zA-Z_][a-zA-Z0-9_.-]*)([:><])(.*)$/);
  if (!match) {
    return { field: SEARCH_FIELD, operator: ":", value: trimmed };
  }
  const [, field, op, value] = match;
  const cleanValue = value.trim();
  if (!cleanValue) {
    // `field:` with empty value is not a useful chip.
    return null;
  }
  return {
    field,
    operator: op as JqlOperator,
    value: cleanValue,
  };
}

export function serializeFilter(filter: JqlFilter): string {
  if (filter.field === SEARCH_FIELD && filter.operator === ":") {
    return filter.value;
  }
  return `${filter.field}${filter.operator}${filter.value}`;
}

function filtersEqual(a: JqlFilter[], b: JqlFilter[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    const x = a[i];
    const y = b[i];
    if (x.field !== y.field || x.operator !== y.operator || x.value !== y.value) {
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// Filter -> query param helpers (re-exported for backend callers)
// ---------------------------------------------------------------------------

/**
 * Convert a list of JqlFilters into a backend query parameter record.
 *
 * Mapping rules:
 *   - `field:value`  -> key = field, value = value
 *   - `field>value`  -> key = `min_{field}`, value = value
 *   - `field<value`  -> key = `max_{field}`, value = value
 *   - `search:value` -> key = "search", value = value
 *
 * Multiple chips on the same field collapse via comma-join (existing
 * backend convention -- audit and llm-log both accept comma-OR).
 */
export function filtersToQueryParams(
  filters: JqlFilter[],
): Record<string, string> {
  const out: Record<string, string[]> = {};
  for (const f of filters) {
    let key: string;
    if (f.operator === ">") key = `min_${f.field}`;
    else if (f.operator === "<") key = `max_${f.field}`;
    else key = f.field;
    const bucket = out[key] ?? [];
    bucket.push(f.value);
    out[key] = bucket;
  }
  const collapsed: Record<string, string> = {};
  for (const [key, values] of Object.entries(out)) {
    collapsed[key] = values.join(",");
  }
  return collapsed;
}

// ---------------------------------------------------------------------------
// Mock-kit shared styles
// ---------------------------------------------------------------------------

const BAR_STYLE: CSSProperties = {
  display: "flex",
  flexWrap: "wrap",
  alignItems: "center",
  gap: 6,
  padding: 6,
  background: "var(--surface-card)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
};

const CHIP_STYLE: CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  gap: 4,
  height: 22,
  padding: "0 4px 0 8px",
  fontFamily: "var(--font-mono)",
  fontSize: 10.5,
  letterSpacing: "0.02em",
  color: "var(--text-primary)",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  borderRadius: 2,
};

const CHIP_REMOVE_STYLE: CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  justifyContent: "center",
  width: 16,
  height: 16,
  padding: 0,
  marginLeft: 2,
  color: "var(--text-muted)",
  background: "transparent",
  border: "none",
  cursor: "pointer",
  borderRadius: 2,
};

const INPUT_STYLE: CSSProperties = {
  flex: 1,
  minWidth: 180,
  height: 24,
  padding: "0 4px",
  fontFamily: "var(--font-mono)",
  fontSize: 11,
  color: "var(--text-primary)",
  background: "transparent",
  border: "none",
  outline: "none",
};

const CLEAR_BUTTON_STYLE: CSSProperties = {
  height: 24,
  padding: "0 10px",
  fontFamily: "var(--font-mono)",
  fontSize: 9.5,
  textTransform: "uppercase",
  letterSpacing: "0.1em",
  color: "var(--text-muted)",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  cursor: "pointer",
};

const HINT_STYLE: CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: 6,
  fontFamily: "var(--font-mono)",
  fontSize: 10,
  color: "var(--text-muted)",
};

// ---------------------------------------------------------------------------
// Chip pill
// ---------------------------------------------------------------------------

interface ChipProps {
  filter: JqlFilter;
  onRemove: () => void;
}

function Chip({ filter, onRemove }: ChipProps) {
  const label = serializeFilter(filter);
  const isSearch = filter.field === SEARCH_FIELD && filter.operator === ":";
  return (
    <span style={CHIP_STYLE}>
      {isSearch ? (
        <MagnifyingGlass
          aria-hidden
          style={{ width: 10, height: 10, color: "var(--text-muted)" }}
        />
      ) : null}
      <span>{label}</span>
      <button
        type="button"
        onClick={onRemove}
        aria-label={`Remove filter ${label}`}
        style={CHIP_REMOVE_STYLE}
      >
        <X style={{ width: 10, height: 10 }} />
      </button>
    </span>
  );
}

// ---------------------------------------------------------------------------
// Public component
// ---------------------------------------------------------------------------

export function JqlFilterBar({
  fields,
  initialFilters,
  onChange,
  urlSync = true,
  placeholder,
}: JqlFilterBarProps) {
  const [searchParams, setSearchParams] = useSearchParams();
  const firstRenderRef = useRef(true);

  const initialFromUrl = useMemo<JqlFilter[]>(() => {
    if (!urlSync) return initialFilters ?? [];
    const raw = searchParams.getAll("f");
    if (raw.length === 0) return initialFilters ?? [];
    return raw
      .map((r) => parseFilterToken(r))
      .filter((x): x is JqlFilter => x !== null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const [filters, setFilters] = useState<JqlFilter[]>(initialFromUrl);
  const [draft, setDraft] = useState("");

  // Emit initial filters on mount, then only on change.
  useEffect(() => {
    onChange(filters);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters]);

  // URL sync: write current filter state into ?f=... params.
  useEffect(() => {
    if (!urlSync) return;
    if (firstRenderRef.current) {
      firstRenderRef.current = false;
      return;
    }
    const next = new URLSearchParams(searchParams);
    next.delete("f");
    for (const f of filters) {
      next.append("f", serializeFilter(f));
    }
    // Only update if something actually changed -- avoids a re-navigation
    // loop when the existing URL already reflects our state.
    const prev = searchParams.getAll("f");
    const current = filters.map(serializeFilter);
    if (
      prev.length === current.length &&
      prev.every((p, i) => p === current[i])
    ) {
      return;
    }
    setSearchParams(next, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters, urlSync]);

  const addFilter = useCallback((raw: string) => {
    const parsed = parseFilterToken(raw);
    if (!parsed) return;
    setFilters((prev) => {
      // De-duplicate identical chips.
      if (
        prev.some(
          (f) =>
            f.field === parsed.field &&
            f.operator === parsed.operator &&
            f.value === parsed.value,
        )
      ) {
        return prev;
      }
      const next = [...prev, parsed];
      return filtersEqual(prev, next) ? prev : next;
    });
    setDraft("");
  }, []);

  const removeFilter = useCallback((index: number) => {
    setFilters((prev) => prev.filter((_, i) => i !== index));
  }, []);

  const clearAll = useCallback(() => {
    setFilters([]);
  }, []);

  const handleKeyDown = useCallback(
    (event: KeyboardEvent<HTMLInputElement>) => {
      if (event.key === "Enter") {
        event.preventDefault();
        addFilter(draft);
      } else if (event.key === "Backspace" && draft === "" && filters.length > 0) {
        // Backspace on empty input pops the last chip -- JQL-like feel.
        removeFilter(filters.length - 1);
      }
    },
    [draft, filters.length, addFilter, removeFilter],
  );

  const fieldHint = useMemo(() => {
    return fields.map((f) => f.key).join(", ");
  }, [fields]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      <div style={BAR_STYLE}>
        <Funnel
          aria-hidden
          style={{ width: 14, height: 14, color: "var(--text-muted)", flexShrink: 0 }}
        />
        {filters.map((f, i) => (
          <Chip
            key={`${f.field}${f.operator}${f.value}-${i}`}
            filter={f}
            onRemove={() => removeFilter(i)}
          />
        ))}
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={
            placeholder ??
            `Filter (e.g. ${fields[0]?.key ?? "module"}:value, cost>0.5)`
          }
          style={INPUT_STYLE}
          aria-label="Add filter"
        />
        {filters.length > 0 && (
          <button type="button" onClick={clearAll} style={CLEAR_BUTTON_STYLE}>
            Clear
          </button>
        )}
      </div>
      <p style={HINT_STYLE}>
        <span>Fields:</span>
        <MonoBadge tone="muted">{fieldHint || "search"}</MonoBadge>
        <span>{"\u00b7 Operators: : > <"}</span>
      </p>
    </div>
  );
}

export default JqlFilterBar;
