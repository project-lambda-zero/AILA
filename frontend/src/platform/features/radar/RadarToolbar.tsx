/**
 * RadarToolbar -- mock rebuild.
 *
 * Mono chip row: Segmented colorBy | search input | severity FilterChips |
 * subnet-grouping FilterChip | node count. Data props unchanged.
 */
import * as React from "react";
import { MagnifyingGlass as SearchIcon } from "@phosphor-icons/react/dist/csr/MagnifyingGlass";

import { FilterChip, Segmented } from "@/components/aila/mock";
import type { ColorByMode, RadarFilter } from "./types";

interface RadarToolbarProps {
  colorBy: ColorByMode;
  onColorByChange: (mode: ColorByMode) => void;
  filter: RadarFilter;
  onFilterChange: (filter: RadarFilter) => void;
  subnetGrouping: boolean;
  onSubnetGroupingChange: (enabled: boolean) => void;
  nodeCount: number;
  filteredCount: number;
}

const SEVERITIES = ["critical", "high", "medium", "low"] as const;

const SEVERITY_COLOR: Record<(typeof SEVERITIES)[number], string> = {
  critical: "var(--accent)",
  high: "var(--status-warn)",
  medium: "var(--status-info)",
  low: "var(--status-ok)",
};

const COLOR_BY_OPTIONS: { value: ColorByMode; label: string }[] = [
  { value: "vulnerabilities", label: "VULNS" },
  { value: "services", label: "SVCS" },
  { value: "distro", label: "DISTRO" },
  { value: "connectivity", label: "CONN" },
];

export function RadarToolbar({
  colorBy,
  onColorByChange,
  filter,
  onFilterChange,
  subnetGrouping,
  onSubnetGroupingChange,
  nodeCount,
  filteredCount,
}: RadarToolbarProps) {
  const handleSeverityToggle = (severity: string) => {
    const current = filter.severities;
    const updated = current.includes(severity)
      ? current.filter((s) => s !== severity)
      : [...current, severity];
    onFilterChange({ ...filter, severities: updated });
  };

  const hasActiveFilters =
    filter.search.trim() !== "" || filter.severities.length > 0;

  return (
    <div className="flex items-center flex-wrap" style={{ gap: 10 }}>
      <span
        className="font-mono uppercase"
        style={{ fontSize: 9, letterSpacing: "0.14em", color: "var(--text-faint)" }}
      >
        color by
      </span>
      <Segmented<ColorByMode>
        options={COLOR_BY_OPTIONS}
        value={colorBy}
        onChange={onColorByChange}
      />

      <span style={{ width: 1, height: 18, background: "var(--border-faint)" }} />

      {/* Search input */}
      <div style={{ position: "relative", display: "flex", alignItems: "center" }}>
        <SearchIcon
          size={12}
          style={{
            position: "absolute",
            left: 8,
            color: "var(--text-faint)",
            pointerEvents: "none",
          }}
        />
        <input
          aria-label="Search systems"
          type="text"
          placeholder="search systems..."
          value={filter.search}
          onChange={(e) => onFilterChange({ ...filter, search: e.target.value })}
          className="font-mono"
          style={{
            height: 26,
            width: 200,
            fontSize: 10.5,
            paddingLeft: 24,
            paddingRight: 8,
            border: "1px solid var(--border-soft)",
            background: "var(--surface-sunk)",
            color: "var(--text-primary)",
            borderRadius: 3,
            outline: "none",
          }}
        />
      </div>

      <span style={{ width: 1, height: 18, background: "var(--border-faint)" }} />

      {/* Severity filter chips */}
      <div className="flex items-center" style={{ gap: 6 }}>
        {SEVERITIES.map((sev) => (
          <FilterChip
            key={sev}
            active={filter.severities.includes(sev)}
            color={SEVERITY_COLOR[sev]}
            onClick={() => handleSeverityToggle(sev)}
          >
            {sev}
          </FilterChip>
        ))}
      </div>

      {hasActiveFilters && (
        <button
          type="button"
          onClick={() => onFilterChange({ search: "", severities: [] })}
          className="font-mono uppercase"
          style={{
            fontSize: 9,
            letterSpacing: "0.12em",
            color: "var(--text-muted)",
            background: "transparent",
            border: "none",
            cursor: "pointer",
            textDecoration: "underline",
            textUnderlineOffset: 3,
          }}
        >
          clear
        </button>
      )}

      <span style={{ width: 1, height: 18, background: "var(--border-faint)" }} />

      <FilterChip
        active={subnetGrouping}
        color="var(--accent)"
        onClick={() => onSubnetGroupingChange(!subnetGrouping)}
      >
        subnet groups
      </FilterChip>

      <span style={{ flex: 1 }} />

      <span
        className="font-mono uppercase"
        style={{ fontSize: 9, letterSpacing: "0.14em", color: "var(--text-faint)" }}
      >
        {filteredCount === nodeCount
          ? `${nodeCount} SYSTEMS`
          : `${filteredCount} / ${nodeCount} SYSTEMS`}
      </span>
    </div>
  );
}
