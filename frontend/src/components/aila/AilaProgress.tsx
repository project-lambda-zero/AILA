import * as React from "react"

import { cn } from "@/lib/utils"

/**
 * AilaProgress — cyber-tech progress bar with leading light sweep.
 *
 * Structural treatment lifted from the dashboard spec, AILA colour
 * tokens applied:
 *   - Container: 6px tall, --color-elevated background, --color-border
 *     hairline, sharp 2px radius (D-05).
 *   - Fill: linear gradient from --color-accent-muted to --color-accent.
 *   - Light sweep: 16px-wide white-tinted glare with 2px blur at the
 *     leading edge of the fill, fades over the right 12% of the bar.
 *
 * Theme-adaptive automatically — synthwave shows pink fill, vaporwave
 * navy, aero blue, ps2 cyan, cyberpunk yellow, etc.
 *
 * The base bar respects prefers-reduced-motion via the standard CSS
 * transition stack — the fill width animates, the sweep does not move.
 *
 * @example
 * ```tsx
 * <AilaProgress value={67} label="Indexing firefox" />
 * ```
 */
export interface AilaProgressProps extends React.HTMLAttributes<HTMLDivElement> {
  /** 0-100 numeric value. Clamped on render. */
  value: number
  /** Optional ariaLabel for accessibility. */
  label?: string
  /** Show the monospace `XX%` on the right. */
  showValue?: boolean
}

export function AilaProgress({
  value,
  label,
  showValue = false,
  className,
  ...props
}: AilaProgressProps) {
  const clamped = Math.max(0, Math.min(100, value))

  return (
    <div className={cn("flex items-center gap-2", className)} {...props}>
      <div
        role="progressbar"
        aria-valuenow={clamped}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={label}
        className="relative h-1.5 flex-1 overflow-hidden rounded-[2px] border border-border bg-elevated"
      >
        <div
          className="relative h-full transition-[width] duration-300 ease-out"
          style={{
            width: `${clamped}%`,
            background:
              "linear-gradient(to right, color-mix(in srgb, var(--color-accent) 60%, transparent), var(--color-accent))",
          }}
        >
          {/* Leading-edge light sweep — 16px wide, blurred, sits at the
              right edge of the fill so it tracks the progress front. */}
          <span
            aria-hidden
            className="pointer-events-none absolute top-0 right-0 h-full w-4"
            style={{
              background:
                "linear-gradient(to right, transparent, color-mix(in srgb, var(--color-accent) 90%, white))",
              filter: "blur(2px)",
              opacity: 0.6,
            }}
          />
        </div>
      </div>
      {showValue && (
        <span className="font-mono text-xs text-text-muted tabular-nums">
          {clamped.toFixed(0)}%
        </span>
      )}
    </div>
  )
}
