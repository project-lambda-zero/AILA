import { Link } from "react-router";

import { WifiSlash } from "@phosphor-icons/react/dist/csr/WifiSlash";

import { SectionHeader } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";

/**
 * 404 SIGNAL LOST -- centred `WindowPanel` carrying the not-found notice.
 *
 * The large muted `404` glyph sits behind the panel as a page-scale marker;
 * the panel itself is the readable affordance. Title is rendered by the mock
 * `SectionHeader` (accent icon square + Apoc display font).
 */
export function NotFoundPage() {
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
          color: "color-mix(in srgb, var(--text-primary) 3%, transparent)",
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
        <div className="flex flex-col" style={{ gap: 14, padding: "6px 2px 4px" }}>
          <SectionHeader
            icon={
              <WifiSlash
                size={18}
                weight="duotone"
                style={{ color: "var(--text-on-accent)" }}
                aria-hidden="true"
              />
            }
            title="signal lost"
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
            The page you requested does not exist on this workbench.
          </p>
          <div className="flex items-center" style={{ gap: 8, paddingTop: 4 }}>
            <Link
              to="/"
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
