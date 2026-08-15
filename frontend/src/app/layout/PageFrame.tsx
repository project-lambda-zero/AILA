import { useEffect, type ReactNode } from "react";

import { PageHeaderProvider, usePageHeaderOverrides } from "@/components/aila/PageHeaderContext";

interface PageFrameProps {
  title: string;
  children: ReactNode;
  /** Accepted for router.tsx compatibility; the frame no longer paints the title bar. */
  icon?: ReactNode;
  subtitle?: ReactNode;
  status?: "live" | "ready" | "paused" | "error" | null;
  actions?: ReactNode;
  hideCornerAccents?: boolean;
  hideTechBorder?: boolean;
}

/**
 * PageFrame wraps every routed feature page (mounted from router.tsx).
 *
 * Post-rebuild responsibilities:
 *   - Sync `document.title` to the browser tab so tabs and bookmarks read
 *     the route name (or the dynamic override pushed by a detail page via
 *     `useUpdatePageHeader`).
 *   - Mount `PageHeaderProvider` so `useUpdatePageHeader` calls (e.g. from
 *     `TeamDetailPage`, `SystemDetailPage`) have a live context to write
 *     into. The provider is otherwise a no-op display-wise since the mock
 *     rebuild moved page titles into per-page `SectionHeader` bodies.
 *   - Render children on the mock's `--surface-page` canvas. NO title bar,
 *     NO corner brackets, NO hairline -- each page owns its `SectionHeader`
 *     via `@/components/aila/mock` (see CLAUDE.md #16: rendering a title
 *     here on top of the page's SectionHeader produces two stacked
 *     headers).
 *
 * The `icon`, `subtitle`, `status`, `actions`, `hideCornerAccents`, and
 * `hideTechBorder` props stay in the type signature because router.tsx and
 * a handful of detail pages still forward them; they are intentionally
 * unused so upstream code compiles unchanged.
 */
export function PageFrame({ title, children }: PageFrameProps) {
  return (
    <PageHeaderProvider>
      <PageFrameInner title={title}>{children}</PageFrameInner>
    </PageHeaderProvider>
  );
}

function PageFrameInner({ title, children }: { title: string; children: ReactNode }) {
  const overrides = usePageHeaderOverrides();
  const overrideTitle = typeof overrides.title === "string" ? overrides.title : null;
  const effectiveTitle = overrideTitle && overrideTitle.length > 0 ? overrideTitle : title;

  useEffect(() => {
    const previous = document.title;
    document.title = effectiveTitle ? `${effectiveTitle} \u00b7 AILA` : "AILA";
    return () => {
      document.title = previous;
    };
  }, [effectiveTitle]);

  return (
    <div style={{ minHeight: "100%", background: "var(--surface-page)", color: "var(--text-primary)" }}>
      {children}
    </div>
  );
}
