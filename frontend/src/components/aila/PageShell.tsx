import * as React from "react"
import type { ReactNode } from "react"

import { PageHeaderProvider, usePageHeaderOverrides } from "@/components/aila/PageHeaderContext"
import { cn } from "@/lib/utils"

/**
 * PageShell — every top-level page wraps in this. Carries the
 * cyber-tech aesthetic in one place so individual pages stay
 * focused on their actual content:
 *
 *   - Sticky header with title + optional subtitle + actions
 *   - Optional icon slot to the left of the title
 *   - Optional live "system online" pulse dot
 *   - Page-level top hairline (accent gradient, theme-tinted)
 *   - Page-level L-shaped corner brackets in all four corners
 *   - Consistent 8-unit padding wrapper around the body
 *
 * Theme-tinted via --color-accent so every theme automatically
 * picks up its own colour: synthwave pink, vaporwave teal, ps2
 * cyan, vendetta red, midnight-cloud-8 hot pink, etc.
 *
 * Usage:
 *
 *   <PageShell
 *     title="Investigations"
 *     subtitle="Hypothesis-driven research across targets"
 *     icon={<MagnifyingGlass />}
 *     status="live"
 *     actions={<Button>New investigation</Button>}
 *   >
 *     ...page body...
 *   </PageShell>
 *
 * Existing AilaCard usages with techBorder/glow remain unchanged —
 * the shell wraps everything, doesn't replace per-card decoration.
 */
export interface PageShellProps {
  /** Page title — rendered as h1 in the sticky header. */
  title: ReactNode
  /** Optional subtitle line under the title. */
  subtitle?: ReactNode
  /** Optional icon rendered in a 40x40 accent-tinted square left of the title. */
  icon?: ReactNode
  /** Optional live status indicator (a pulsing accent dot + label). */
  status?: "live" | "ready" | "paused" | "error" | null
  /** Optional right-aligned action row (buttons, kebab menus, etc.). */
  actions?: ReactNode
  /** Page body. */
  children: ReactNode
  /** Suppress the L-shaped corner brackets — useful for full-bleed maps/canvases. */
  hideCornerAccents?: boolean
  /** Suppress the top hairline. */
  hideTechBorder?: boolean
  /** Override the wrapper className (rare — for non-standard layouts). */
  className?: string
  /** Override the inner content className. */
  contentClassName?: string
}

const STATUS_LABEL: Record<NonNullable<PageShellProps["status"]>, string> = {
  live: "Live",
  ready: "Ready",
  paused: "Paused",
  error: "Error",
}

const STATUS_COLOR: Record<NonNullable<PageShellProps["status"]>, string> = {
  live: "bg-status-running",
  ready: "bg-status-completed",
  paused: "bg-status-paused",
  error: "bg-status-failed",
}

function PageShellInner({
  title,
  subtitle,
  icon,
  status,
  actions,
  children,
  hideCornerAccents = false,
  hideTechBorder = false,
  className,
  contentClassName,
}: PageShellProps) {
  // Pull overrides set by the currently-mounted page via useUpdatePageHeader.
  // Explicit `null` clears the corresponding field; `undefined` falls through
  // to the static prop value supplied by PageFrame / router.tsx.
  const ov = usePageHeaderOverrides()
  const resolve = <T,>(override: T | null | undefined, fallback: T | undefined): T | undefined => {
    if (override === null) return undefined
    if (override !== undefined) return override
    return fallback
  }
  title = resolve(ov.title, title) ?? title
  subtitle = resolve(ov.subtitle, subtitle)
  icon = resolve(ov.icon, icon)
  status = resolve(ov.status, status)
  actions = resolve(ov.actions, actions)
  // L-shaped 16x16 corner brackets in accent colour at 50% opacity.
  // Same shape as AilaCard.cornerAccents but rendered at page scope.
  const cornerColor = "color-mix(in srgb, var(--color-accent) 50%, transparent)"
  const corners = !hideCornerAccents ? (
    <>
      <span
        aria-hidden
        className="pointer-events-none fixed top-2 left-2 z-50 h-4 w-4 border-t-2 border-l-2"
        style={{ borderColor: cornerColor }}
      />
      <span
        aria-hidden
        className="pointer-events-none fixed top-2 right-2 z-50 h-4 w-4 border-t-2 border-r-2"
        style={{ borderColor: cornerColor }}
      />
      <span
        aria-hidden
        className="pointer-events-none fixed bottom-2 left-2 z-50 h-4 w-4 border-b-2 border-l-2"
        style={{ borderColor: cornerColor }}
      />
      <span
        aria-hidden
        className="pointer-events-none fixed bottom-2 right-2 z-50 h-4 w-4 border-b-2 border-r-2"
        style={{ borderColor: cornerColor }}
      />
    </>
  ) : null

  // Top hairline — same treatment as AilaCard.techBorder, page scope.
  const hairline = !hideTechBorder ? (
    <span
      aria-hidden
      className="pointer-events-none absolute inset-x-0 top-0 h-px"
      style={{
        background:
          "linear-gradient(90deg, transparent, color-mix(in srgb, var(--color-accent) 60%, transparent), transparent)",
      }}
    />
  ) : null

  return (
    <div className={cn("relative min-h-screen", className)}>
      {hairline}
      {corners}
      <header className="sticky top-0 z-20 backdrop-blur-sm bg-base/80 border-b border-border">
        <div className="flex items-center gap-4 px-6 py-4">
          {icon && (
            <div
              className={cn(
                "flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-[4px]",
                "border border-border",
                "bg-[linear-gradient(180deg,var(--color-elevated),var(--color-surface))]",
                "text-accent",
              )}
              style={{
                boxShadow:
                  "0 0 12px color-mix(in srgb, var(--color-accent) 22%, transparent)",
              }}
            >
              <span className="[&_svg]:h-5 [&_svg]:w-5">{icon}</span>
            </div>
          )}
          <div className="min-w-0 flex-1">
            <h1
              className="font-display text-xl font-bold text-foreground tracking-tight truncate"
              style={{
                textShadow:
                  "0 0 1px color-mix(in srgb, var(--color-accent) 40%, transparent)",
              }}
            >
              {title}
            </h1>
            {(subtitle || status) && (
              <div className="mt-0.5 flex items-center gap-2 text-xs text-text-muted font-mono">
                {status && (
                  <span className="inline-flex items-center gap-1.5">
                    <span
                      aria-hidden
                      className={cn(
                        "inline-block size-1.5 rounded-full animate-pulse",
                        STATUS_COLOR[status],
                      )}
                    />
                    <span className="uppercase tracking-wider">{STATUS_LABEL[status]}</span>
                    {subtitle && <span className="text-text-muted/50">·</span>}
                  </span>
                )}
                {subtitle && <span className="truncate">{subtitle}</span>}
              </div>
            )}
          </div>
          {actions && (
            <div className="flex flex-shrink-0 items-center gap-2">{actions}</div>
          )}
        </div>
      </header>
      <main className={cn("p-6", contentClassName)}>{children}</main>
    </div>
  )
}

export function PageShell(props: PageShellProps) {
  return (
    <PageHeaderProvider>
      <PageShellInner {...props} />
    </PageHeaderProvider>
  )
}
