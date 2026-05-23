import { useEffect, type ReactNode } from "react";

import { PageShell } from "@/components/aila/PageShell";

interface PageFrameProps {
  title: string;
  children: ReactNode;
  /** Optional sidebar icon — same Phosphor icons modules use in their nav.ts. */
  icon?: ReactNode;
  /** Optional subtitle line under the title. */
  subtitle?: ReactNode;
  /** Optional live-status pulse dot. */
  status?: "live" | "ready" | "paused" | "error" | null;
  /** Optional right-aligned action row (buttons, links, menus). */
  actions?: ReactNode;
  /** Suppress the corner brackets — full-bleed canvases (maps, graphs). */
  hideCornerAccents?: boolean;
  /** Suppress the top hairline. */
  hideTechBorder?: boolean;
}

/**
 * PageFrame wraps every routed feature page (mounted from router.tsx).
 * Syncs the document title to the browser tab, then renders the
 * children inside a PageShell carrying the cyber-tech aesthetic
 * (sticky header + corner brackets + accent hairline).
 *
 * Pages can forward icon / subtitle / actions / status via the props
 * here so they don't have to import PageShell themselves. When a page
 * still renders its own inline <h1>, BOTH the PageShell title and the
 * inline heading will appear — the codemod sweep strips redundant
 * inline headers as part of the overhaul rollout.
 */
export function PageFrame({
  title,
  children,
  icon,
  subtitle,
  status,
  actions,
  hideCornerAccents,
  hideTechBorder,
}: PageFrameProps) {
  useEffect(() => {
    const previous = document.title;
    document.title = title ? `${title} · AILA` : "AILA";
    return () => {
      document.title = previous;
    };
  }, [title]);

  return (
    <PageShell
      title={title}
      subtitle={subtitle}
      icon={icon}
      status={status ?? null}
      actions={actions}
      hideCornerAccents={hideCornerAccents}
      hideTechBorder={hideTechBorder}
    >
      {children}
    </PageShell>
  );
}
