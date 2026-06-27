import { useReducedMotion as useMotionReducedMotion } from "motion/react"

/**
 * Returns true when the user prefers reduced motion.
 *
 * Wraps motion/react's useReducedMotion for consistent app-wide usage (D-21).
 * motion/react returns `boolean | null` -- this wrapper normalises to a plain
 * boolean so callers don't need to null-check.
 *
 * When true, all animations should be disabled or made instant.
 */
export function useReducedMotion(): boolean {
  return useMotionReducedMotion() ?? false
}
