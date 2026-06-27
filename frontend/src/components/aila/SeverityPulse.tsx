import * as React from "react"

import { cn } from "@/lib/utils"

export interface SeverityPulseProps extends React.HTMLAttributes<HTMLSpanElement> {
  /**
   * When true, applies the severity-pulse CSS animation (D-18).
   * Animation is pure CSS keyframe (opacity 1 -> 0.5 -> 1), no JS involved.
   * Respects prefers-reduced-motion via globals.css media query.
   */
  active?: boolean
}

/**
 * SeverityPulse -- wrapper that conditionally applies the severity-pulse animation.
 *
 * Pure CSS animation wrapper (D-18). When `active` is true, adds the
 * `animate-severity-pulse` class which triggers the CSS keyframe defined in globals.css.
 * The animation automatically respects prefers-reduced-motion.
 *
 * @example
 * ```tsx
 * <SeverityPulse active>
 *   <AilaBadge severity="critical">CRITICAL</AilaBadge>
 * </SeverityPulse>
 * ```
 */
function SeverityPulse({
  active = false,
  className,
  children,
  ...props
}: SeverityPulseProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center",
        active && "animate-severity-pulse",
        className
      )}
      {...props}
    >
      {children}
    </span>
  )
}

export { SeverityPulse }
