/**
 * chartColors -- shared theme-aware color resolver for Recharts.
 *
 * Recharts renders into SVG and applies color props as SVG presentation
 * attributes (e.g. `<path fill="...">`). Browsers do NOT resolve CSS
 * `var(--token)` inside SVG presentation attributes -- only inside CSS
 * properties via inline `style` or stylesheets. The result: any chart that
 * passed `fill="var(--color-critical)"` rendered as an empty box.
 *
 * `useThemeChartColors` reads the resolved CSS custom properties from
 * `<html>` at runtime and re-reads when the active theme/mode changes.
 * Hex fallbacks match the SystemHeatmap palette so charts still render
 * usefully outside a ThemeProvider (Storybook, tests).
 */
import * as React from "react";

import { useTheme } from "@/providers/ThemeProvider";

const FALLBACK = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#9ca3af",
  accent: "#3b82f6",
  border: "#3f3f46",
  textMuted: "#71717a",
} as const;

export type ChartColorKey = keyof typeof FALLBACK;
export type ChartColors = Record<ChartColorKey, string>;

function readVar(name: string, fallback: string): string {
  if (typeof window === "undefined") return fallback;
  const raw = getComputedStyle(document.documentElement)
    .getPropertyValue(name)
    .trim();
  return raw || fallback;
}

function snapshot(): ChartColors {
  return {
    critical: readVar("--color-critical", FALLBACK.critical),
    high: readVar("--color-high", FALLBACK.high),
    medium: readVar("--color-medium", FALLBACK.medium),
    low: readVar("--color-low", FALLBACK.low),
    accent: readVar("--color-accent", FALLBACK.accent),
    border: readVar("--color-border", FALLBACK.border),
    textMuted: readVar("--color-text-muted", FALLBACK.textMuted),
  };
}

/**
 * Resolves theme colors to hex strings safe for SVG presentation attributes.
 * Re-evaluates on theme/mode change so chart colors track the active theme.
 */
export function useThemeChartColors(): ChartColors {
  const { theme, mode } = useTheme();
  const [colors, setColors] = React.useState<ChartColors>(() => snapshot());
  React.useEffect(() => {
    setColors(snapshot());
  }, [theme, mode]);
  return colors;
}
