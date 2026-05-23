/**
 * PageHeaderContext — lets detail pages override the static route title
 * supplied to PageFrame at render time. Without this, /vr/projects/:id
 * pages can only ever show "VR Project Detail" (the route title) instead
 * of the live project name.
 *
 * Usage:
 *
 *   function ProjectDetailPage() {
 *     const project = useProject(...)
 *     useUpdatePageHeader({
 *       title: project?.name,
 *       subtitle: project?.cve_id ?? undefined,
 *       status: project?.status === "running" ? "live" : "ready",
 *       actions: <Button>Stop</Button>,
 *     })
 *     ...
 *   }
 *
 * The overrides are scoped to the currently-mounted page. When the page
 * unmounts (route change), the overrides clear automatically.
 */
import * as React from "react"

type PageStatus = "live" | "ready" | "paused" | "error"

export interface PageHeaderOverrides {
  title?: string | null
  subtitle?: React.ReactNode | null
  icon?: React.ReactNode | null
  status?: PageStatus | null
  actions?: React.ReactNode | null
}

interface PageHeaderContextValue {
  overrides: PageHeaderOverrides
  setOverrides: (next: PageHeaderOverrides) => void
}

const PageHeaderContext = React.createContext<PageHeaderContextValue | null>(null)

export function PageHeaderProvider({ children }: { children: React.ReactNode }) {
  const [overrides, setOverrides] = React.useState<PageHeaderOverrides>({})
  const value = React.useMemo(() => ({ overrides, setOverrides }), [overrides])
  return <PageHeaderContext.Provider value={value}>{children}</PageHeaderContext.Provider>
}

/**
 * Read the active page-header overrides from inside PageShell. Returns
 * an empty object if no provider is mounted (which means PageShell is
 * being rendered outside the normal routed-page tree — fine, defaults
 * to PageFrame-passed props).
 */
export function usePageHeaderOverrides(): PageHeaderOverrides {
  return React.useContext(PageHeaderContext)?.overrides ?? {}
}

/**
 * Page-level hook to override PageShell header fields dynamically.
 *
 * Only pass keys you want to override. Omitted keys (or explicitly
 * `undefined`) fall through to the static props from PageFrame /
 * router.tsx. Explicitly passing `null` clears that field.
 *
 * Pass primitives where possible — objects allocated inline in render
 * trigger re-syncs every render, which is harmless but wasteful.
 */
export function useUpdatePageHeader(overrides: PageHeaderOverrides) {
  const ctx = React.useContext(PageHeaderContext)
  // Capture each individual field so a parent re-render with the same
  // values doesn't re-fire the effect.
  const { title, subtitle, icon, status, actions } = overrides

  React.useEffect(() => {
    if (!ctx) return
    ctx.setOverrides({ title, subtitle, icon, status, actions })
    return () => ctx.setOverrides({})
    // ctx.setOverrides is stable via useState; we intentionally omit it
    // from deps to avoid extra renders.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [title, subtitle, icon, status, actions])
}
