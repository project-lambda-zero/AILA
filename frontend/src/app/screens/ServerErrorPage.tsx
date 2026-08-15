import { Link } from "react-router";

import { WarningOctagon } from "@phosphor-icons/react/dist/csr/WarningOctagon";

import { SectionHeader } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";

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
    <div
      className="relative flex min-h-screen items-center justify-center overflow-hidden p-6"
      style={{ background: "var(--surface-page)" }}
    >
      <span
        aria-hidden="true"
        className="pointer-events-none absolute select-none font-mono font-black"
        style={{
          fontSize: "clamp(8rem, 25vw, 20rem)",
          color: "color-mix(in srgb, var(--accent) 4%, transparent)",
          lineHeight: 1,
        }}
      >
        500
      </span>

      <WindowPanel
        title="server error"
        tone="warn"
        status="500 · handler raised"
        className="relative z-10 w-full max-w-md"
      >
        <div className="flex flex-col" style={{ gap: 14, padding: "6px 2px 4px" }}>
          <SectionHeader
            icon={
              <WarningOctagon
                size={18}
                weight="duotone"
                style={{ color: "var(--text-on-accent)" }}
                aria-hidden="true"
              />
            }
            title="server error"
            size={20}
          />
          <p
            className="font-mono"
            style={{
              color: "var(--text-muted)",
              fontSize: 11,
              lineHeight: 1.55,
              letterSpacing: "0.02em",
            }}
          >
            Something went wrong on this workbench. Please try again.
          </p>
          <div className="flex items-center flex-wrap" style={{ gap: 8, paddingTop: 4 }}>
            {resetError ? (
              <button
                type="button"
                onClick={resetError}
                className="font-mono uppercase inline-flex items-center"
                style={{
                  height: 26,
                  padding: "0 12px",
                  fontSize: 9.5,
                  letterSpacing: "0.1em",
                  border: "1px solid var(--accent)",
                  background: "var(--accent)",
                  color: "var(--text-on-accent)",
                  borderRadius: 3,
                  cursor: "pointer",
                }}
              >
                Try again
              </button>
            ) : null}
            <Link
              to="/"
              className="font-mono uppercase inline-flex items-center"
              style={{
                height: 26,
                padding: "0 12px",
                fontSize: 9.5,
                letterSpacing: "0.1em",
                border: "1px solid var(--border-soft)",
                background: "var(--surface-sunk)",
                color: "var(--text-primary)",
                borderRadius: 3,
                textDecoration: "none",
              }}
            >
              Return to dashboard
            </Link>
          </div>
        </div>
      </WindowPanel>
    </div>
  );
}
