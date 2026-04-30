import * as React from "react"
import { motion, useInView } from "motion/react"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"
import { useReducedMotion } from "@/hooks/useReducedMotion"

/**
 * CVA variant definition for AilaCard.
 * Implements border-based surface elevation (D-06) with 4px radius (D-05).
 */
const ailaCardVariants = cva(
  "rounded-[4px] border transition-colors duration-150",
  {
    variants: {
      /**
       * Visual variant controlling background and hover behavior.
       * - `default`: surface background, static border
       * - `elevated`: elevated background, static border
       * - `interactive`: surface background with amber border glow on hover
       */
      variant: {
        default: "bg-surface border-border",
        elevated: "bg-elevated border-border",
        interactive:
          "bg-surface border-border hover:border-border-hover cursor-pointer",
      },
      /**
       * Internal padding size.
       */
      padding: {
        none: "p-0",
        sm: "p-3",
        md: "p-4",
        lg: "p-6",
      },
    },
    defaultVariants: {
      variant: "default",
      padding: "md",
    },
  }
)

export type AilaCardVariants = VariantProps<typeof ailaCardVariants>

export interface AilaCardProps
  extends React.HTMLAttributes<HTMLDivElement>,
    AilaCardVariants {
  /**
   * When true, the card animates in on scroll entry (fade-up, D-21).
   * Defaults to false — opt-in to avoid unnecessary motion on static cards.
   */
  animate?: boolean
  /**
   * Stagger delay in seconds added to the reveal animation start (D-21).
   * Useful for cascading card grids. Only applies when `animate` is true.
   */
  delay?: number
}

/**
 * AilaCard — surface container with cyberpunk border elevation.
 *
 * Uses 4px sharp radius (D-05), border-based elevation with no drop shadows (D-06),
 * and amber border glow on interactive hover.
 *
 * Supports opt-in scroll-triggered reveal animation (D-21):
 * - `animate` prop enables fade-up entrance on scroll entry
 * - `delay` prop staggers multiple cards (e.g. 0, 0.1, 0.2 s)
 * - Respects prefers-reduced-motion: instant reveal, no y shift
 *
 * @example
 * ```tsx
 * <AilaCard variant="interactive" padding="lg" animate delay={0.1}>
 *   <h2>CVE-2024-1234</h2>
 * </AilaCard>
 * ```
 */
function AilaCard({
  className,
  variant,
  padding,
  animate = false,
  delay = 0,
  children,
  ...props
}: AilaCardProps) {
  const prefersReducedMotion = useReducedMotion()
  const ref = React.useRef<HTMLDivElement>(null)
  const inView = useInView(ref, { once: true, margin: "0px 0px -40px 0px" })

  const baseClass = cn(ailaCardVariants({ variant, padding }), className)

  if (!animate) {
    return (
      <div ref={ref} className={baseClass} {...props}>
        {children}
      </div>
    )
  }

  return (
    <motion.div
      ref={ref}
      className={baseClass}
      initial={{ opacity: 0, y: prefersReducedMotion ? 0 : 16 }}
      animate={
        inView
          ? { opacity: 1, y: 0 }
          : { opacity: 0, y: prefersReducedMotion ? 0 : 16 }
      }
      transition={{
        duration: prefersReducedMotion ? 0 : 0.3,
        ease: "easeOut",
        delay: prefersReducedMotion ? 0 : delay,
      }}
      {...(props as React.ComponentPropsWithoutRef<typeof motion.div>)}
    >
      {children}
    </motion.div>
  )
}

export { AilaCard, ailaCardVariants }
