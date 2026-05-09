import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  LineChart,
  Line,
  AreaChart,
  Area,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
} from "recharts"

import { cn } from "@/lib/utils"

/**
 * CVA variant definition for AilaChart container sizing.
 */
const ailaChartVariants = cva("w-full", {
  variants: {
    /**
     * Chart height.
     */
    size: {
      sm: "h-48",
      md: "h-64",
      lg: "h-80",
    },
  },
  defaultVariants: {
    size: "md",
  },
})

export type AilaChartVariants = VariantProps<typeof ailaChartVariants>

/**
 * Default AILA color palette — uses CSS variables from globals.css design tokens.
 * Colors adapt automatically between light and dark themes via CSS custom properties.
 */
const DEFAULT_COLORS = [
  "var(--color-accent)",     // amber primary
  "var(--color-critical)",   // red
  "var(--color-high)",       // orange
  "var(--color-medium)",     // yellow
  "var(--color-lavender)",   // purple accent
  "var(--color-mint)",       // mint/teal
  "var(--color-low)",        // gray
]

/** Chart tooltip style — dark surface, border, 4px radius matching AilaCard */
const TOOLTIP_STYLE: React.CSSProperties = {
  backgroundColor: "var(--color-elevated)",
  border: "1px solid var(--color-border)",
  borderRadius: "4px",
  fontFamily: "var(--font-mono)",
  fontSize: "12px",
  color: "var(--color-text)",
}

/** Cartesian grid style — border color, dashed */
const GRID_STYLE = {
  stroke: "var(--color-border)",
  strokeDasharray: "3 3",
}

/** Axis style — monospace font per D-03 */
const AXIS_STYLE = {
  fontFamily: "var(--font-mono)",
  fontSize: 11,
  fill: "var(--color-text-muted)",
}

export interface AilaChartProps extends AilaChartVariants {
  /**
   * Chart type — determines which Recharts chart is rendered.
   */
  type: "bar" | "line" | "area" | "pie"
  /**
   * Data array for the chart. Each item is a plain object.
   * Example: [{ name: "Critical", count: 12 }]
   */
  data: Array<Record<string, unknown>>
  /**
   * Key in each data item to use as the Y-axis value (for bar/line/area)
   * or as the numeric value for pie slices.
   */
  dataKey: string
  /**
   * Key in each data item to use as the X-axis label (for bar/line/area)
   * or as the label for pie slices. Defaults to "name".
   */
  xKey?: string
  /**
   * Override the color palette. Defaults to AILA CSS variable colors.
   */
  colors?: string[]
  /**
   * Additional class name for the container div.
   */
  className?: string
  /**
   * Chart title for accessibility (aria-label on container).
   */
  ariaLabel?: string
}

/**
 * AilaChart — Recharts wrapper with AILA design token colors (D-17).
 *
 * All color references use CSS variables (`var(--color-*)`) so they
 * adapt automatically to dark/light mode without any JS.
 * XAxis/YAxis use JetBrains Mono per D-03.
 * Tooltip uses dark surface bg, border, 4px radius matching AilaCard.
 *
 * @example
 * ```tsx
 * <AilaChart
 *   type="bar"
 *   data={[{ name: "Critical", count: 5 }]}
 *   dataKey="count"
 *   xKey="name"
 *   size="md"
 * />
 * ```
 */
function AilaChart({
  type,
  data,
  dataKey,
  xKey = "name",
  size,
  colors = DEFAULT_COLORS,
  className,
  ariaLabel,
}: AilaChartProps) {
  const containerClass = cn(ailaChartVariants({ size }), className)

  if (type === "bar") {
    return (
      <div className={containerClass} role="img" aria-label={ariaLabel ?? `Bar chart: ${dataKey}`}>
        <ResponsiveContainer width="100%" height="100%" minWidth={1} minHeight={1}>
          <BarChart data={data} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
            <CartesianGrid {...GRID_STYLE} />
            <XAxis dataKey={xKey} tick={AXIS_STYLE} axisLine={{ stroke: "var(--color-border)" }} tickLine={false} />
            <YAxis tick={AXIS_STYLE} axisLine={false} tickLine={false} />
            <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: "var(--color-elevated)", opacity: 0.5 }} />
            <Legend wrapperStyle={{ fontFamily: "var(--font-mono)", fontSize: 11 }} />
            <Bar dataKey={dataKey} fill={colors[0]} radius={[2, 2, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    )
  }

  if (type === "line") {
    return (
      <div className={containerClass} role="img" aria-label={ariaLabel ?? `Line chart: ${dataKey}`}>
        <ResponsiveContainer width="100%" height="100%" minWidth={1} minHeight={1}>
          <LineChart data={data} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
            <CartesianGrid {...GRID_STYLE} />
            <XAxis dataKey={xKey} tick={AXIS_STYLE} axisLine={{ stroke: "var(--color-border)" }} tickLine={false} />
            <YAxis tick={AXIS_STYLE} axisLine={false} tickLine={false} />
            <Tooltip contentStyle={TOOLTIP_STYLE} />
            <Legend wrapperStyle={{ fontFamily: "var(--font-mono)", fontSize: 11 }} />
            <Line
              type="monotone"
              dataKey={dataKey}
              stroke={colors[0]}
              strokeWidth={2}
              dot={{ fill: colors[0], r: 3, strokeWidth: 0 }}
              activeDot={{ fill: colors[0], r: 5, strokeWidth: 0 }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    )
  }

  if (type === "area") {
    return (
      <div className={containerClass} role="img" aria-label={ariaLabel ?? `Area chart: ${dataKey}`}>
        <ResponsiveContainer width="100%" height="100%" minWidth={1} minHeight={1}>
          <AreaChart data={data} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="aila-area-gradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={colors[0]} stopOpacity={0.3} />
                <stop offset="95%" stopColor={colors[0]} stopOpacity={0.02} />
              </linearGradient>
            </defs>
            <CartesianGrid {...GRID_STYLE} />
            <XAxis dataKey={xKey} tick={AXIS_STYLE} axisLine={{ stroke: "var(--color-border)" }} tickLine={false} />
            <YAxis tick={AXIS_STYLE} axisLine={false} tickLine={false} />
            <Tooltip contentStyle={TOOLTIP_STYLE} />
            <Legend wrapperStyle={{ fontFamily: "var(--font-mono)", fontSize: 11 }} />
            <Area
              type="monotone"
              dataKey={dataKey}
              stroke={colors[0]}
              strokeWidth={2}
              fill="url(#aila-area-gradient)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    )
  }

  if (type === "pie") {
    return (
      <div className={containerClass} role="img" aria-label={ariaLabel ?? `Pie chart: ${dataKey}`}>
        <ResponsiveContainer width="100%" height="100%" minWidth={1} minHeight={1}>
          <PieChart>
            <Pie
              data={data}
              dataKey={dataKey}
              nameKey={xKey}
              cx="50%"
              cy="50%"
              outerRadius="75%"
              strokeWidth={0}
            >
              {data.map((_entry, index) => (
                <Cell key={`cell-${index}`} fill={colors[index % colors.length]} />
              ))}
            </Pie>
            <Tooltip contentStyle={TOOLTIP_STYLE} />
            <Legend wrapperStyle={{ fontFamily: "var(--font-mono)", fontSize: 11 }} />
          </PieChart>
        </ResponsiveContainer>
      </div>
    )
  }

  return null
}

export { AilaChart, ailaChartVariants, DEFAULT_COLORS }
