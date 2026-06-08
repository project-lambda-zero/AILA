/**
 * RadarToolbar.tsx — Toolbar for the Network Radar page (Phase 144).
 *
 * Provides:
 * - Color-by Select dropdown (Vulnerabilities / Services / Distro / Connectivity)
 * - System name search input
 * - Severity filter toggle chips (CRITICAL / HIGH / MEDIUM / LOW)
 * - Subnet grouping toggle
 * - Node count display (filtered / total)
 */
import * as React from "react";
import { MagnifyingGlass as SearchIcon } from "@phosphor-icons/react/dist/csr/MagnifyingGlass";

import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";
import type { ColorByMode, RadarFilter } from "./types";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Severity chip
// ---------------------------------------------------------------------------

const SEVERITY_CHIP_STYLES: Record<string, { active: string; inactive: string }> = {
  critical: {
    active: "bg-[var(--color-critical)] text-white border-[var(--color-critical)]",
    inactive: "border-border text-muted-foreground hover:border-[var(--color-critical)] hover:text-[var(--color-critical)]",
  },
  high: {
    active: "bg-[var(--color-high)] text-white border-[var(--color-high)]",
    inactive: "border-border text-muted-foreground hover:border-[var(--color-high)] hover:text-[var(--color-high)]",
  },
  medium: {
    active: "bg-[var(--color-medium)] text-white border-[var(--color-medium)]",
    inactive: "border-border text-muted-foreground hover:border-[var(--color-medium)] hover:text-[var(--color-medium)]",
  },
  low: {
    active: "bg-[var(--color-low)] text-white border-[var(--color-low)]",
    inactive: "border-border text-muted-foreground hover:border-[var(--color-low)] hover:text-[var(--color-low)]",
  },
};

const SEVERITIES = ["critical", "high", "medium", "low"] as const;
type Severity = (typeof SEVERITIES)[number];

interface SeverityChipProps {
  severity: Severity;
  active: boolean;
  onToggle: () => void;
}

function SeverityChip({ severity, active, onToggle }: SeverityChipProps) {
  const styles = SEVERITY_CHIP_STYLES[severity];
  return (
    <button
      type="button"
      onClick={onToggle}
      className={cn(
        "px-2 py-0.5 rounded border font-mono text-[10px] uppercase tracking-wider transition-colors",
        active ? styles.active : styles.inactive,
      )}
    >
      {severity}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Subnet toggle
// ---------------------------------------------------------------------------

interface SubnetToggleProps {
  enabled: boolean;
  onChange: (v: boolean) => void;
}

function SubnetToggle({ enabled, onChange }: SubnetToggleProps) {
  return (
    <button
      type="button"
      onClick={() => onChange(!enabled)}
      className={cn(
        "flex items-center gap-1.5 px-2 py-0.5 rounded border font-mono text-[10px] transition-colors",
        enabled
          ? "bg-[var(--color-accent)] text-white border-[var(--color-accent)]"
          : "border-border text-muted-foreground hover:border-[var(--color-accent)]",
      )}
    >
      <span className={cn("w-3 h-3 rounded-sm border", enabled ? "bg-white border-white" : "border-border")} />
      Subnet groups
    </button>
  );
}

// ---------------------------------------------------------------------------
// Main toolbar
// ---------------------------------------------------------------------------

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

  const hasActiveFilters = filter.search.trim() !== "" || filter.severities.length > 0;

  return (
    <div className="flex flex-wrap items-center gap-2 px-4 py-2 border-b border-border bg-elevated">
      {/* Color by selector */}
      <div className="flex items-center gap-1.5">
        <span className="font-mono text-[10px] text-muted-foreground uppercase tracking-wider">
          Color by:
        </span>
        <Select value={colorBy} onValueChange={(v) => onColorByChange(v as ColorByMode)}>
          <SelectTrigger className="h-7 w-[140px] font-mono text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="vulnerabilities" className="font-mono text-xs">
              Vulnerabilities
            </SelectItem>
            <SelectItem value="services" className="font-mono text-xs">
              Services
            </SelectItem>
            <SelectItem value="distro" className="font-mono text-xs">
              Distro
            </SelectItem>
            <SelectItem value="connectivity" className="font-mono text-xs">
              Connectivity
            </SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Divider */}
      <div className="w-px h-5 bg-border" />

      {/* Search input */}
      <div className="relative flex items-center">
        <SearchIcon
          size={14}
          className="absolute left-2 text-muted-foreground pointer-events-none"
        />
        <Input
          type="text"
          placeholder="Search systems..."
          value={filter.search}
          onChange={(e) => onFilterChange({ ...filter, search: e.target.value })}
          className="h-7 pl-7 w-[180px] font-mono text-xs"
        />
      </div>

      {/* Divider */}
      <div className="w-px h-5 bg-border" />

      {/* Severity filter chips */}
      <div className="flex items-center gap-1">
        {SEVERITIES.map((sev) => (
          <SeverityChip
            key={sev}
            severity={sev}
            active={filter.severities.includes(sev)}
            onToggle={() => handleSeverityToggle(sev)}
          />
        ))}
      </div>

      {/* Clear filters */}
      {hasActiveFilters && (
        <button
          type="button"
          onClick={() => onFilterChange({ search: "", severities: [] })}
          className="font-mono text-[10px] text-muted-foreground hover:text-foreground transition-colors underline-offset-2 hover:underline"
        >
          Clear
        </button>
      )}

      {/* Divider */}
      <div className="w-px h-5 bg-border" />

      {/* Subnet grouping toggle */}
      <SubnetToggle enabled={subnetGrouping} onChange={onSubnetGroupingChange} />

      {/* Spacer */}
      <div className="flex-1" />

      {/* Node count */}
      <span className="font-mono text-[10px] text-muted-foreground">
        {filteredCount === nodeCount
          ? `${nodeCount} systems`
          : `${filteredCount} / ${nodeCount} systems`}
      </span>
    </div>
  );
}
