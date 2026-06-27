import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

/**
 * CVA variant definition for AilaBadge.
 * Implements WCAG-compliant severity colors (D-04, D-07) and sharp corners (D-05).
 *
 * WCAG note: All severity backgrounds use transparent bg with colored text --
 * text-critical, text-high, text-medium, text-low are bright on dark base.
 * Solid variant uses text-badge-text (dark #131313) on solid colored bg.
 */
const ailaBadgeVariants = cva(
  "inline-flex items-center rounded-[2px] font-mono uppercase tracking-wider border font-medium transition-colors duration-150",
  {
    variants: {
      /**
       * Severity level -- determines background, text, and border colors.
       * Uses WCAG-compliant text colors for both transparent and solid variants.
       */
      severity: {
        /** Critical -- red, with pulsing animation support */
        critical:
          "bg-critical/15 text-critical border-critical/40",
        /** High -- orange */
        high:
          "bg-high/15 text-high border-high/40",
        /** Medium -- yellow */
        medium:
          "bg-medium/15 text-medium border-medium/40",
        /** Low -- gray (#9ca3af, WCAG-fixed from #6b7280 per D-04) */
        low:
          "bg-low/15 text-low border-low/40",
        /** Info -- lavender accent (D-04b midnight-cloud-8) */
        info:
          "bg-lavender/15 text-lavender border-lavender/40",
        /** Neutral -- muted text, no severity */
        neutral:
          "bg-surface text-text-muted border-border",
      },
      /**
       * Badge size controlling text size and padding.
       */
      size: {
        sm: "text-xs px-1.5 py-0.5",
        md: "text-xs px-2 py-0.5",
        lg: "text-sm px-2.5 py-1",
      },
      /**
       * Solid variant uses opaque background with dark badge text (WCAG AA).
       * text-badge-text (#131313 dark / #1c1917 light) ensures contrast on colored bg.
       */
      solid: {
        true: "",
        false: "",
      },
    },
    compoundVariants: [
      {
        severity: "critical",
        solid: true,
        class: "bg-critical text-badge-text border-critical",
      },
      {
        severity: "high",
        solid: true,
        class: "bg-high text-badge-text border-high",
      },
      {
        severity: "medium",
        solid: true,
        class: "bg-medium text-badge-text border-medium",
      },
      {
        severity: "low",
        solid: true,
        class: "bg-low text-badge-text border-low",
      },
      {
        severity: "info",
        solid: true,
        class: "bg-lavender text-badge-text border-lavender",
      },
    ],
    defaultVariants: {
      severity: "neutral",
      size: "md",
      solid: false,
    },
  }
)

export type AilaBadgeVariants = VariantProps<typeof ailaBadgeVariants>

/**
 * Task status namespace -- distinct from severity tokens (D-05, D-21, D-22).
 * Backed by --status-* CSS variables in globals.css.
 */
export type TaskStatus =
  | "completed"
  | "running"
  | "failed"
  | "queued"
  | "waiting"
  | "paused"

export interface AilaBadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    AilaBadgeVariants {
  /**
   * When true, applies the severity-pulse CSS animation (D-18).
   * Meaningful primarily on critical severity.
   */
  pulse?: boolean
  /**
   * Task status variant -- resolves to `aila-badge-status-${status}` class
   * which uses `var(--status-${status})` for colours. Distinct from
   * `severity` so theme palettes don't collide (D-21). When `status` is
   * set, `severity` is ignored.
   */
  status?: TaskStatus
  /**
   * Render a 6px pulse dot inside the badge before the children. Tinted
   * with `currentColor` so it inherits the severity / status text colour
   * automatically. Independent of `pulse` (which animates the whole
   * badge): use `dot` for the pill-with-live-indicator pattern,
   * `pulse` for the call-attention-now pattern. Both can be set.
   */
  dot?: boolean
}

/**
 * AilaBadge -- severity indicator with WCAG-compliant colors.
 *
 * Implements severity color system (D-04, D-04b), sharp 2px corners (D-05),
 * and optional CSS-only severity pulse animation (D-18).
 *
 * @example
 * ```tsx
 * <AilaBadge severity="critical" pulse>CRITICAL</AilaBadge>
 * <AilaBadge severity="high" size="lg">HIGH</AilaBadge>
 * <AilaBadge severity="medium" solid>MEDIUM</AilaBadge>
 * ```
 */
function AilaBadge({
  className,
  severity,
  size,
  solid,
  pulse = false,
  status,
  dot = false,
  children,
  ...props
}: AilaBadgeProps) {
  // When `status` is provided, route through the status-* token namespace
  // instead of severity. This keeps task-status colours independent from
  // severity-low green (D-21 collision avoidance).
  const statusClass = status ? `aila-badge-status-${status}` : undefined

  return (
    <span
      className={cn(
        ailaBadgeVariants({
          severity: status ? "neutral" : severity,
          size,
          solid: status ? false : solid,
        }),
        statusClass,
        pulse && "animate-severity-pulse",
        dot && "gap-1.5",
        className
      )}
      {...props}
    >
      {dot && (
        <span
          aria-hidden
          className="inline-block size-1.5 rounded-full bg-current animate-pulse"
        />
      )}
      {children}
    </span>
  )
}

export { AilaBadge, ailaBadgeVariants }
