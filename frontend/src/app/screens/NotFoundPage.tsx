import { Link } from "react-router";

import { WifiSlash } from "@phosphor-icons/react/dist/csr/WifiSlash";

import { WindowPanel } from "@/components/aila/WindowPanel";

/**
 * 404 SIGNAL LOST -- a centred `WindowPanel` carrying the not-found notice.
 *
 * The panel gives the error state the same OS-window chrome as every other
 * surface. The large muted `404` glyph sits behind the panel as a page-scale
 * marker; the panel itself is the readable affordance.
 */
export function NotFoundPage() {
  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-base p-6">
      <span
        aria-hidden="true"
        className="pointer-events-none absolute select-none font-mono font-black"
        style={{
          fontSize: "clamp(8rem, 25vw, 20rem)",
          color: "color-mix(in srgb, var(--color-text) 3%, transparent)",
          lineHeight: 1,
        }}
      >
        404
      </span>

      <WindowPanel
        title="signal lost"
        tone="accent"
        status="404 · route not registered"
        className="relative z-10 w-full max-w-md"
      >
        <div className="flex flex-col items-center gap-4 py-6 text-center">
          <WifiSlash
            size={40}
            weight="duotone"
            className="text-accent"
            aria-hidden="true"
          />
          <h2 className="font-mono text-2xl font-bold uppercase tracking-widest text-accent">
            Signal lost
          </h2>
          <p className="max-w-xs font-mono text-xs text-text-muted">
            The page you requested does not exist on this workbench.
          </p>
          <Link
            className="mt-1 font-mono text-xs text-accent underline underline-offset-2 hover:opacity-80"
            to="/"
          >
            Return to dashboard
          </Link>
        </div>
      </WindowPanel>
    </div>
  );
}
