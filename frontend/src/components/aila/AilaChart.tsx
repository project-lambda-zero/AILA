import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

import { LoadingSkeleton } from "./LoadingSkeleton"

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
 * Lazy boundary — keeps recharts (~430 KB) out of the root entry.
 * Vite chunk-splits ./AilaChart.view together with the vendor-recharts
 * chunk; both arrive only when an AilaChart instance first renders.
 */
const AilaChartView = React.lazy(() =>
  import("./AilaChart.view").then((m) => ({ default: m.AilaChartView })),
)

/** Height-matched skeleton fallback while the chart chunk arrives. */
function AilaChartFallback({
  size,
  className,
  ariaLabel,
}: {
  size?: AilaChartVariants["size"]
  className?: string
  ariaLabel?: string
}) {
  return (
    <div
      className={cn(ailaChartVariants({ size }), className)}
      role="img"
      aria-label={ariaLabel ?? "Loading chart"}
      aria-busy="true"
    >
      <LoadingSkeleton size="full" width="full" className="h-full" />
    </div>
  )
}

/**
 * AilaChart — Recharts wrapper with AILA design token colors (D-17).
 *
 * The implementation lives in ./AilaChart.view and is loaded lazily so
 * the recharts library stays out of the initial bundle. Render the
 * component normally — the suspense boundary is internal.
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
function AilaChart(props: AilaChartProps) {
  return (
    <React.Suspense
      fallback={
        <AilaChartFallback
          size={props.size}
          className={props.className}
          ariaLabel={props.ariaLabel}
        />
      }
    >
      <AilaChartView {...props} />
    </React.Suspense>
  )
}

export { AilaChart, ailaChartVariants, DEFAULT_COLORS }
