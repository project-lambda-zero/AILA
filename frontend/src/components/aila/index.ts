/**
 * AILA Component Library -- barrel export (D-15).
 *
 * All 7 AILA cyberpunk components exported from a single entry point.
 * Import from "@/components/aila" in feature pages.
 *
 * @example
 * ```tsx
 * import { AilaCard, AilaBadge, AilaTable, AilaChart } from "@/components/aila"
 * ```
 */

export { AilaCard, ailaCardVariants } from "./AilaCard"
export type { AilaCardProps, AilaCardVariants, AilaCardDecoration } from "./AilaCard"

export { AilaBadge, ailaBadgeVariants } from "./AilaBadge"
export type { AilaBadgeProps, AilaBadgeVariants } from "./AilaBadge"

export { AilaTable } from "./AilaTable"
export type {
  AilaTableProps,
  AilaTableHeaderProps,
  AilaTableBodyProps,
  AilaTablePaginationProps,
} from "./AilaTable"

export { AilaChart, ailaChartVariants, DEFAULT_COLORS } from "./AilaChart"
export type { AilaChartProps, AilaChartVariants } from "./AilaChart"

export { SeverityPulse } from "./SeverityPulse"
export type { SeverityPulseProps } from "./SeverityPulse"

export { LoadingSkeleton, LoadingSkeletonGroup, loadingSkeletonVariants } from "./LoadingSkeleton"
export type {
  LoadingSkeletonProps,
  LoadingSkeletonVariants,
  LoadingSkeletonGroupProps,
} from "./LoadingSkeleton"

export { PageTransition } from "./PageTransition"
export type { PageTransitionProps } from "./PageTransition"

export { EmptyState } from "./EmptyState"
export type { EmptyStateProps } from "./EmptyState"

export { HelpTip } from "./HelpTip"
export type { HelpTipProps } from "./HelpTip"
