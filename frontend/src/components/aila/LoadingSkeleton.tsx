import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

/**
 * CVA variant definition for LoadingSkeleton.
 * Uses the `skeleton-aila` class from globals.css which provides
 * the amber scan line animation (D-22) -- a thin amber line sweeping
 * horizontally across a dark surface. Cyberpunk terminal aesthetic.
 */
const loadingSkeletonVariants = cva("skeleton-aila", {
  variants: {
    /**
     * Height of the skeleton placeholder element.
     */
    size: {
      sm: "h-4",
      md: "h-8",
      lg: "h-12",
      xl: "h-20",
      full: "h-full",
    },
    /**
     * Width of the skeleton placeholder element.
     */
    width: {
      full: "w-full",
      half: "w-1/2",
      third: "w-1/3",
      quarter: "w-1/4",
      auto: "w-auto",
    },
  },
  defaultVariants: {
    size: "md",
    width: "full",
  },
})

export type LoadingSkeletonVariants = VariantProps<typeof loadingSkeletonVariants>

export interface LoadingSkeletonProps
  extends React.HTMLAttributes<HTMLDivElement>,
    LoadingSkeletonVariants {}

/**
 * LoadingSkeleton -- amber scan line skeleton placeholder (D-22).
 *
 * Renders a dark surface element with an amber scan line sweeping across it,
 * giving a cyberpunk terminal loading aesthetic. The animation is pure CSS
 * (defined in globals.css as `.skeleton-aila`), no JS required.
 * Respects prefers-reduced-motion -- animation stops, static amber tint shown.
 *
 * @example
 * ```tsx
 * <LoadingSkeleton size="md" width="full" />
 * <LoadingSkeleton size="sm" width="half" />
 * ```
 */
function LoadingSkeleton({
  className,
  size,
  width,
  ...props
}: LoadingSkeletonProps) {
  return (
    <div
      className={cn(loadingSkeletonVariants({ size, width }), className)}
      aria-hidden="true"
      {...props}
    />
  )
}

export interface LoadingSkeletonGroupProps extends React.HTMLAttributes<HTMLDivElement> {
  /**
   * Number of skeleton lines to render. Defaults to 3.
   */
  lines?: number
  /**
   * Gap between skeleton lines. Defaults to "gap-2".
   */
  gap?: string
}

/**
 * LoadingSkeletonGroup -- paragraph-like skeleton placeholder.
 *
 * Renders multiple skeleton lines with naturally varying widths
 * to simulate a paragraph of text loading.
 *
 * @example
 * ```tsx
 * <LoadingSkeletonGroup lines={4} />
 * ```
 */
function LoadingSkeletonGroup({
  lines = 3,
  gap = "gap-2",
  className,
  ...props
}: LoadingSkeletonGroupProps) {
  // Predefined width pattern for natural paragraph appearance
  const widthPattern: Array<LoadingSkeletonVariants["width"]> = [
    "full",
    "half",
    "third",
    "full",
    "quarter",
    "half",
  ]

  return (
    <div className={cn("flex flex-col", gap, className)} {...props} aria-hidden="true">
      {Array.from({ length: lines }).map((_, i) => (
        <LoadingSkeleton
          key={i}
          size="sm"
          width={widthPattern[i % widthPattern.length]}
        />
      ))}
    </div>
  )
}

export { LoadingSkeleton, LoadingSkeletonGroup, loadingSkeletonVariants }
