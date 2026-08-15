/**
 * AILA component library -- barrel export (mock design-system era).
 *
 * The legacy cyberpunk primitives (AilaCard, AilaBadge, AilaTable,
 * SeverityPulse, PageTransition, KpiTile, StaggeredList, PageShell,
 * ConnectedEntities) were removed in the total rebuild to the design mock.
 * Pages compose the mock kit (`@/components/aila/mock`) plus WindowPanel and
 * PixelIcon directly. Only tokenized, still-current primitives are re-exported
 * here.
 */

export { AilaChart, ailaChartVariants, DEFAULT_COLORS } from "./AilaChart"
export type { AilaChartProps, AilaChartVariants } from "./AilaChart"

export { LoadingSkeleton, LoadingSkeletonGroup, loadingSkeletonVariants } from "./LoadingSkeleton"
export type {
  LoadingSkeletonProps,
  LoadingSkeletonVariants,
  LoadingSkeletonGroupProps,
} from "./LoadingSkeleton"

export { EmptyState } from "./EmptyState"
export type { EmptyStateProps } from "./EmptyState"

export { HelpTip } from "./HelpTip"
export type { HelpTipProps } from "./HelpTip"
