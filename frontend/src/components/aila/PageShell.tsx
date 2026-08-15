import * as React from "react"
import type { ReactNode } from "react"

import { PageHeaderProvider, usePageHeaderOverrides } from "@/components/aila/PageHeaderContext"
import { cn } from "@/lib/utils"

/**
 * PageShell -- every top-level page wraps in this. Carries the
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
 * Existing AilaCard usages with techBorder/glow remain unchanged --
 * the shell wraps everything, doesn't replace per-card decoration.
 */
export interface PageShellProps {
  /** Page title -- rendered as h1 in the sticky header. */
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
  /** Suppress the L-shaped corner brackets -- useful for full-bleed maps/canvases. */
  hideCornerAccents?: boolean
  /** Suppress the top hairline. */
  hideTechBorder?: boolean
  /** Override the wrapper className (rare -- for non-standard layouts). */
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
  live: "var(--status-running)",
  ready: "var(--status-completed)",
  paused: "var(--status-paused)",
  error: "var(--status-failed)",
}

function PageShellInner({
  title,
  subtitle,
  icon,
  status,
  actions,
  children,
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
  return (
    <div className={cn("relative min-h-screen", className)}>
      <header className="sticky top-0 z-20 border-b border-border bg-base/80 backdrop-blur-sm">
        <div className="flex items-center gap-4 px-6 py-4">
          {icon && (
            <div
              className={cn(
                "flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-[4px]",
                "border border-[var(--color-border-bright)] bg-elevated text-accent",
              )}
              style={{ boxShadow: "var(--bevel-raised)" }}
            >
              <span className="[&_svg]:h-5 [&_svg]:w-5">{icon}</span>
            </div>
          )}
          <div className="min-w-0 flex-1">
            <h1 className="truncate font-display text-xl font-bold tracking-tight text-foreground">
              {title}
            </h1>
            {(subtitle || status) && (
              <div className="mt-0.5 flex items-center gap-2 font-mono text-xs text-muted-foreground">
                {status && (
                  <span className="inline-flex items-center gap-1.5">
                    <span
                      aria-hidden
                      className="inline-block size-1.5 rounded-full animate-pulse"
                      style={{ background: STATUS_COLOR[status] }}
                    />
                    <span className="uppercase tracking-wider">{STATUS_LABEL[status]}</span>
                    {subtitle && <span className="text-muted-foreground/50">·</span>}
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
