import * as React from "react"
import { AnimatePresence, motion, useReducedMotion } from "motion/react"

import { cn } from "@/lib/utils"

export interface PageTransitionProps {
  /**
   * Unique key for the animated content — typically the current route pathname.
   * Must change when route changes to trigger exit/enter animation.
   */
  motionKey: string
  /**
   * Children to render inside the animated container.
   */
  children: React.ReactNode
  /**
   * Additional class name for the motion.div wrapper.
   */
  className?: string
}

/**
 * PageTransition — route-level fade + slide animation wrapper (D-21).
 *
 * Uses `motion/react` (NOT framer-motion — renamed package per Pitfall 6).
 * Respects prefers-reduced-motion via `useReducedMotion()` hook:
 * - When reduced motion is preferred: duration=0, no y offsets
 * - Otherwise: 200ms fade + 8px slide, easeOut easing
 *
 * Wrap route outlet content with this component, passing `motionKey`
 * as the current pathname so AnimatePresence triggers on navigation.
 *
 * @example
 * ```tsx
 * const location = useLocation()
 * return (
 *   <PageTransition motionKey={location.pathname}>
 *     <Outlet />
 *   </PageTransition>
 * )
 * ```
 */
function PageTransition({ motionKey, children, className }: PageTransitionProps) {
  const prefersReducedMotion = useReducedMotion()

  const variants = {
    initial: {
      opacity: 0,
      y: prefersReducedMotion ? 0 : 8,
    },
    animate: {
      opacity: 1,
      y: 0,
    },
    exit: {
      opacity: 0,
      y: prefersReducedMotion ? 0 : -8,
    },
  }

  const transition = {
    duration: prefersReducedMotion ? 0 : 0.2,
    ease: "easeOut" as const,
  }

  return (
    <AnimatePresence mode="wait" initial={false}>
      <motion.div
        key={motionKey}
        variants={variants}
        initial="initial"
        animate="animate"
        exit="exit"
        transition={transition}
        className={cn("min-h-0 flex-1", className)}
      >
        {children}
      </motion.div>
    </AnimatePresence>
  )
}

export { PageTransition }
