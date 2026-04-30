import { useEffect, type ReactNode } from "react";

interface PageFrameProps {
  title: string;
  children: ReactNode;
}

/**
 * PageFrame wraps a routed feature page. It syncs the document title
 * to the browser tab but no longer renders a visible <h1>, because
 * every feature page already supplies its own heading and rendering
 * both here produced duplicated headers on every screen.
 */
export function PageFrame({ title, children }: PageFrameProps) {
  useEffect(() => {
    const previous = document.title;
    document.title = title ? `${title} · AILA` : "AILA";
    return () => {
      document.title = previous;
    };
  }, [title]);

  return (
    <section className="page-frame">
      <div className="page-frame__body">{children}</div>
    </section>
  );
}
