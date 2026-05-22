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
  /**
   * Glassmorphic surface — 10px backdrop blur + theme-colored gradient
   * fill. Reads through to whatever's behind the card (sidebar, page
   * background, particle background on login). Opt-in; pages with
   * dense data tables behind cards should leave this off.
   */
  glass?: boolean
  /**
   * L-shaped accent brackets in the four corners of the card. Uses
   * --color-accent at 50% opacity. Pure decoration — purely opt-in;
   * great on hero/landing cards, distracting on grids.
   */
  cornerAccents?: boolean
  /**
   * Animated gradient hairline along the top edge of the card
   * (transparent → accent → transparent). 1px tall. Sits below the
   * border so it doesn't fight the card's existing border colour.
   */
  techBorder?: boolean
  /**
   * On hover, projects a soft accent-coloured glow (no extra radius
   * change). Stacks with `variant="interactive"`'s border-hover.
   */
  glow?: boolean
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
  glass = false,
  cornerAccents = false,
  techBorder = false,
  glow = false,
  children,
  ...props
}: AilaCardProps) {
  const prefersReducedMotion = useReducedMotion()
  const ref = React.useRef<HTMLDivElement>(null)
  const inView = useInView(ref, { once: true, margin: "0px 0px -40px 0px" })

  // Decoration layer adds `relative` positioning when any accent is on,
  // so the absolute-positioned brackets / tech-border anchor correctly.
  const hasDecoration = cornerAccents || techBorder
  const baseClass = cn(
    ailaCardVariants({ variant, padding }),
    hasDecoration && "relative",
    glass && [
      "backdrop-blur-[10px]",
      // Theme-tinted glass: surface base with subtle gradient lift.
      // Uses --color-surface for the tint so the card auto-adapts to
      // synthwave / vaporwave / aero / ps2 / cyberpunk palettes.
      "bg-[linear-gradient(180deg,color-mix(in_srgb,var(--color-surface)_95%,transparent)_0%,color-mix(in_srgb,var(--color-surface)_98%,transparent)_100%)]",
    ],
    glow && "transition-shadow hover:shadow-[0_0_15px_color-mix(in_srgb,var(--color-accent)_30%,transparent)]",
    className,
  )

  // L-shaped 16x16 corner brackets at 50% accent opacity. Matches the
  // card's 4px radius (D-05) on the inner corner. Each corner gets only
  // the 2 borders forming the L.
  const cornerColor = "color-mix(in srgb, var(--color-accent) 50%, transparent)"
  const corners = cornerAccents ? (
    <>
      <span
        aria-hidden
        className="pointer-events-none absolute top-0 left-0 h-4 w-4 rounded-tl-[4px] border-t-2 border-l-2"
        style={{ borderColor: cornerColor }}
      />
      <span
        aria-hidden
        className="pointer-events-none absolute top-0 right-0 h-4 w-4 rounded-tr-[4px] border-t-2 border-r-2"
        style={{ borderColor: cornerColor }}
      />
      <span
        aria-hidden
        className="pointer-events-none absolute bottom-0 left-0 h-4 w-4 rounded-bl-[4px] border-b-2 border-l-2"
        style={{ borderColor: cornerColor }}
      />
      <span
        aria-hidden
        className="pointer-events-none absolute bottom-0 right-0 h-4 w-4 rounded-br-[4px] border-b-2 border-r-2"
        style={{ borderColor: cornerColor }}
      />
    </>
  ) : null

  // 1px tech-border hairline along the top edge:
  // transparent → accent@50% → transparent.
  const techHairline = techBorder ? (
    <span
      aria-hidden
      className="pointer-events-none absolute inset-x-0 top-0 h-px"
      style={{
        background: `linear-gradient(90deg, transparent, color-mix(in srgb, var(--color-accent) 50%, transparent), transparent)`,
      }}
    />
  ) : null

  const decorations = (cornerAccents || techBorder) ? (
    <>
      {techHairline}
      {corners}
    </>
  ) : null

  if (!animate) {
    return (
      <div ref={ref} className={baseClass} {...props}>
        {decorations}
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
      {decorations}
      {children}
    </motion.div>
  )
}

export { AilaCard, ailaCardVariants }
