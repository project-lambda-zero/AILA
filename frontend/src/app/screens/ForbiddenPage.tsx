import { Link } from "react-router";

import { ShieldSlash } from "@phosphor-icons/react/dist/csr/ShieldSlash";

import { WindowPanel } from "@/components/aila/WindowPanel";

/**
 * 403 ACCESS DENIED -- centred `WindowPanel` rendered by ProtectedRoute when
 * the operator's role is insufficient. Uses the amber warn tone so it reads
 * as a permission gate rather than a system fault.
 */
export function ForbiddenPage() {
  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-base p-6">
      <span
        aria-hidden="true"
        className="pointer-events-none absolute select-none font-mono font-black"
        style={{
          fontSize: "clamp(8rem, 25vw, 20rem)",
          color: "color-mix(in srgb, var(--color-amber) 3%, transparent)",
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
        <div className="flex flex-col items-center gap-4 py-6 text-center">
          <ShieldSlash
            size={48}
            weight="duotone"
            style={{ color: "var(--color-amber)" }}
            aria-hidden="true"
          />
          <span
            aria-hidden="true"
            style={{
              width: 4,
              height: 40,
              background: "var(--color-amber)",
              borderRadius: 2,
            }}
          />
          <h1
            className="font-mono text-2xl font-bold uppercase tracking-widest"
            style={{ color: "var(--color-amber)" }}
          >
            Access denied
          </h1>
          <p className="max-w-xs font-mono text-xs text-text-muted">
            You do not have permission to access this resource.
          </p>
          <Link
            className="mt-1 font-mono text-xs underline underline-offset-2 hover:opacity-80"
            style={{ color: "var(--color-amber)" }}
            to="/"
          >
            Return to dashboard
          </Link>
        </div>
      </WindowPanel>
    </div>
  );
}
