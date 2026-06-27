import * as React from "react"
import { motion, type Transition, type Variants } from "motion/react"

import { useReducedMotion } from "@/hooks/useReducedMotion"

/**
 * Orchestrated list entrance -- single staggered cascade on mount.
 *
 * Pattern:
 * ```tsx
 * <StaggeredList as="ul" className="flex flex-col gap-2">
 *   {items.map((item) => (
 *     <StaggeredItem as="li" key={item.id}>
 *       <Card />
 *     </StaggeredItem>
 *   ))}
 * </StaggeredList>
 * ```
 *
 * The container holds the `staggerChildren` variant; each item inherits
 * the cascade through Motion's variant tree. New keys mount with the
 * cascade applied; existing keys (after a filter or refetch) stay in
 * the `show` state and do not replay.
 *
 * Respects `prefers-reduced-motion` via `useReducedMotion()` (A5 / B10):
 * when set, items render at final opacity with no y-offset and zero
 * stagger or duration.
 *
 * `ref` forwarding is intentionally not exposed because Motion's bundled
 * React types collide with the project's React types on `Ref<T>`. Call
 * sites that need a DOM ref (e.g. dnd-kit `setNodeRef`) should wrap an
 * inner `<div ref={…}>` inside `<StaggeredItem>`.
 */

const STAGGER_INTERVAL_S = 0.04
const STAGGER_LEAD_S = 0.02
const ITEM_DURATION_S = 0.22
const ITEM_Y_OFFSET_PX = 8

interface StaggerSpec {
  container: Variants
  item: Variants
  transition: Transition
}

function useStaggerSpec(): StaggerSpec {
  const reducedMotion = useReducedMotion()
  return React.useMemo<StaggerSpec>(() => {
    if (reducedMotion) {
      return {
        container: { hidden: {}, show: {} },
        item: { hidden: { opacity: 1 }, show: { opacity: 1 } },
        transition: { duration: 0 },
      }
    }
    return {
      container: {
        hidden: {},
        show: {
          transition: {
            staggerChildren: STAGGER_INTERVAL_S,
            delayChildren: STAGGER_LEAD_S,
          },
        },
      },
      item: {
        hidden: { opacity: 0, y: ITEM_Y_OFFSET_PX },
        show: { opacity: 1, y: 0 },
      },
      transition: { duration: ITEM_DURATION_S, ease: "easeOut" },
    }
  }, [reducedMotion])
}

// HTMLAttributes' onAnimation*/onDrag* handlers collide with the
// motion-library signatures of the same names. Strip them from the
// public surface -- call sites can reach for the underlying motion
// component if they truly need the framer hooks.
type SafeHtmlAttrs<E extends HTMLElement> = Omit<
  React.HTMLAttributes<E>,
  | "onAnimationStart"
  | "onAnimationEnd"
  | "onAnimationIteration"
  | "onDrag"
  | "onDragStart"
  | "onDragEnd"
>

// ─────────────────────────────────────────────────────────
// StaggeredList -- orchestrating parent.
// ─────────────────────────────────────────────────────────

type ContainerTag = "ul" | "ol" | "div" | "section"

export interface StaggeredListProps extends SafeHtmlAttrs<HTMLElement> {
  /** Semantic tag for the container. Defaults to `ul`. */
  as?: ContainerTag
  children?: React.ReactNode
}

export function StaggeredList({
  as = "ul",
  children,
  ...rest
}: StaggeredListProps) {
  const { container } = useStaggerSpec()
  const animationProps = {
    variants: container,
    initial: "hidden" as const,
    animate: "show" as const,
  }
  switch (as) {
    case "ul":
      return (
        <motion.ul
          {...animationProps}
          {...(rest as React.ComponentPropsWithoutRef<typeof motion.ul>)}
        >
          {children}
        </motion.ul>
      )
    case "ol":
      return (
        <motion.ol
          {...animationProps}
          {...(rest as React.ComponentPropsWithoutRef<typeof motion.ol>)}
        >
          {children}
        </motion.ol>
      )
    case "section":
      return (
        <motion.section
          {...animationProps}
          {...(rest as React.ComponentPropsWithoutRef<typeof motion.section>)}
        >
          {children}
        </motion.section>
      )
    case "div":
    default:
      return (
        <motion.div
          {...animationProps}
          {...(rest as React.ComponentPropsWithoutRef<typeof motion.div>)}
        >
          {children}
        </motion.div>
      )
  }
}

// ─────────────────────────────────────────────────────────
// StaggeredItem -- child of StaggeredList.
//   Inherits the parent's variant cascade; no `initial` / `animate`
//   props needed at this layer.
// ─────────────────────────────────────────────────────────

type ItemTag = "li" | "div" | "tr" | "section"

export interface StaggeredItemProps extends SafeHtmlAttrs<HTMLElement> {
  /** Semantic tag for the item. Defaults to `div`. */
  as?: ItemTag
  children?: React.ReactNode
}

export function StaggeredItem({
  as = "div",
  children,
  ...rest
}: StaggeredItemProps) {
  const { item, transition } = useStaggerSpec()
  const animationProps = { variants: item, transition }
  switch (as) {
    case "li":
      return (
        <motion.li
          {...animationProps}
          {...(rest as React.ComponentPropsWithoutRef<typeof motion.li>)}
        >
          {children}
        </motion.li>
      )
    case "tr":
      return (
        <motion.tr
          {...animationProps}
          {...(rest as React.ComponentPropsWithoutRef<typeof motion.tr>)}
        >
          {children}
        </motion.tr>
      )
    case "section":
      return (
        <motion.section
          {...animationProps}
          {...(rest as React.ComponentPropsWithoutRef<typeof motion.section>)}
        >
          {children}
        </motion.section>
      )
    case "div":
    default:
      return (
        <motion.div
          {...animationProps}
          {...(rest as React.ComponentPropsWithoutRef<typeof motion.div>)}
        >
          {children}
        </motion.div>
      )
  }
}
