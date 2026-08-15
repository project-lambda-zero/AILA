import { Link } from "react-router";

import { ShieldSlash } from "@phosphor-icons/react/dist/csr/ShieldSlash";

import { SectionHeader } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";

/**
 * 403 ACCESS DENIED -- centred `WindowPanel` rendered by ProtectedRoute when
 * the operator's role is insufficient. Amber warn tone reads as a permission
 * gate rather than a system fault. Title via mock `SectionHeader`.
 */
export function ForbiddenPage() {
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
          color: "color-mix(in srgb, var(--status-warn) 3%, transparent)",
          lineHeight: 1,
        }}
      >
        403
      </span>

      <WindowPanel
        title="access denied"
        tone="warn"
        status="403 · role insufficient"
        className="relative z-10 w-full max-w-md"
      >
        <div className="flex flex-col" style={{ gap: 14, padding: "6px 2px 4px" }}>
          <SectionHeader
            icon={
              <ShieldSlash
                size={18}
                weight="duotone"
                style={{ color: "var(--text-on-accent)" }}
                aria-hidden="true"
              />
            }
            title="access denied"
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
            You do not have permission to access this resource.
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
                border: "1px solid var(--status-warn)",
                background: "color-mix(in srgb, var(--status-warn) 14%, transparent)",
                color: "var(--status-warn)",
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
