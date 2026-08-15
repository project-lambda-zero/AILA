import { Link } from "react-router";

import { WarningOctagon } from "@phosphor-icons/react/dist/csr/WarningOctagon";

import { WindowPanel } from "@/components/aila/WindowPanel";
import { Button } from "@/components/ui/button";

interface ServerErrorPageProps {
  error?: Error;
  resetError?: () => void;
}

/**
 * 500 SYSTEM ERROR -- centred `WindowPanel` used by AppErrorBoundary and by
 * the direct `/500` route.
 *
 * Security (T-140-09): the underlying error object is intentionally not
 * shown; the panel prints a generic operator-safe message.
 */
export function ServerErrorPage({ error: _error, resetError }: ServerErrorPageProps) {
  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-base p-6">
      <span
        aria-hidden="true"
        className="pointer-events-none absolute select-none font-mono font-black"
        style={{
          fontSize: "clamp(8rem, 25vw, 20rem)",
          color: "color-mix(in srgb, var(--color-critical) 4%, transparent)",
          lineHeight: 1,
        }}
      >
        500
      </span>

      <WindowPanel
        title="system error"
        tone="warn"
        status="500 · handler raised"
        className="relative z-10 w-full max-w-md"
      >
        <div className="flex flex-col items-center gap-4 py-6 text-center">
          <WarningOctagon
            size={48}
            weight="duotone"
            className="text-critical"
            aria-hidden="true"
          />
          <h1 className="font-mono text-2xl font-bold uppercase tracking-widest text-critical">
            System error
          </h1>
          <p className="max-w-xs font-mono text-xs text-text-muted">
            Something went wrong on this workbench. Please try again.
          </p>
          <div className="flex flex-col items-center gap-2 pt-1">
            {resetError ? (
              <Button size="sm" onClick={resetError}>
                Try again
              </Button>
            ) : null}
            <Link
              className="font-mono text-xs text-critical underline underline-offset-2 hover:opacity-80"
              to="/"
            >
              Return to dashboard
            </Link>
          </div>
        </div>
      </WindowPanel>
    </div>
  );
}
