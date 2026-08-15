import { useEffect, useState } from "react";
import { Link, useLocation, useMatches } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { MagnifyingGlass } from "@phosphor-icons/react/dist/csr/MagnifyingGlass";
import { List } from "@phosphor-icons/react/dist/csr/List";

import { NotificationBell } from "@/components/shell/NotificationBell";
import { UserAvatarMenu } from "@/components/shell/UserAvatarMenu";
import { requestJson } from "@platform/api/http";

/**
 * AppHeader -- the AILA workbench MenuBar, rebuilt from the design mock.
 *
 * A 32px OS-frame bar: pink AILA brand square + wordmark on the left, then
 * a rail toggle, then a row of lowercase mono tabs that jump to the top-level
 * platform surfaces. Right side is a search entrypoint, notifications, the
 * user avatar menu, a live engine dot + label from GET /health, and a HH:MM:SS
 * live clock. Tokens are the mock's semantic names (--surface-chrome,
 * --border, --border-soft, --text-*), NEVER raw palette utilities.
 */
interface AppHeaderProps {
  onToggleRail?: () => void;
}

interface HealthResponse {
  status: "healthy" | "degraded" | "unhealthy";
}

// The mock's three tabs. Kept minimal on purpose -- the rail carries the
// long tail of navigation; the MenuBar is the top-level bucket switcher.
const TABS: ReadonlyArray<{ label: string; to: string; match: (p: string) => boolean }> = [
  { label: "console", to: "/", match: (p) => p === "/" },
  { label: "dashboard", to: "/dashboard", match: (p) => p.startsWith("/dashboard") },
  { label: "docs", to: "/docs", match: (p) => p.startsWith("/docs") },
];

interface RouteMatch {
  id: string;
  pathname: string;
  handle?: { breadcrumb?: string };
}

function openCommandPalette() {
  window.dispatchEvent(new CustomEvent("open-command-palette"));
}

function useClock(): string {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const id = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(id);
  }, []);
  const hh = String(now.getHours()).padStart(2, "0");
  const mm = String(now.getMinutes()).padStart(2, "0");
  const ss = String(now.getSeconds()).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}

function useEngineHealth(): { color: string; label: string; glow: boolean } {
  // Shares the ["system-status","health"] query key with StatusBar so both
  // consumers dedupe onto a single network request via TanStack Query.
  const q = useQuery({
    queryKey: ["system-status", "health"],
    queryFn: () => requestJson<HealthResponse>("/health"),
    refetchInterval: 10_000,
    staleTime: 5_000,
    retry: 1,
  });
  if (q.isError) return { color: "var(--status-warn)", label: "offline", glow: false };
  const s = q.data?.status;
  if (s === "unhealthy") return { color: "var(--accent)", label: "offline", glow: false };
  if (s === "degraded") return { color: "var(--status-warn)", label: "degraded", glow: false };
  // "healthy" or (loading -> optimistic ok, glow on).
  return { color: "var(--status-ok)", label: "engine ok", glow: true };
}

const RIGHT_CELL: React.CSSProperties = {
  borderLeft: "1px solid var(--border-soft)",
};

export function AppHeader({ onToggleRail }: AppHeaderProps) {
  const location = useLocation();
  const matches = useMatches() as RouteMatch[];
  const clock = useClock();
  const engine = useEngineHealth();

  // Deepest handle-carried breadcrumb, used as a compact "bound" hint on the
  // right of the menubar so operators know which surface they are in even when
  // the URL is deep. Falls back to `console` when nothing is registered.
  const bound = matches
    .filter((m) => m.handle?.breadcrumb)
    .map((m) => m.handle!.breadcrumb as string)
    .pop() ?? "console";

  return (
    <header
      className="flex flex-none items-stretch"
      style={{
        height: "var(--menubar-h, 32px)",
        background: "var(--surface-chrome)",
        borderBottom: "2px solid var(--border)",
        fontFamily: "var(--font-mono)",
        fontSize: "10.5px",
        letterSpacing: "0.12em",
        textTransform: "uppercase",
        position: "relative",
        zIndex: 20,
      }}
    >
      {/* Brand block -- pink dot + AILA wordmark, hard-set left of the bar. */}
      <div
        className="flex items-center"
        style={{ gap: 8, padding: "0 12px", borderRight: "1px solid var(--border-soft)" }}
      >
        <span
          aria-hidden="true"
          style={{
            width: 9,
            height: 9,
            background: "var(--accent)",
            boxShadow: "0 0 8px var(--accent)",
          }}
        />
        <span
          className="select-none font-bold"
          style={{ letterSpacing: "0.2em", fontSize: 12, color: "var(--text-primary)" }}
        >
          AILA
        </span>
      </div>

      {/* Rail toggle */}
      <button
        type="button"
        onClick={onToggleRail}
        aria-label="Toggle rail"
        className="flex items-center"
        style={{
          padding: "0 12px",
          borderRight: "1px solid var(--border-soft)",
          color: "var(--text-muted)",
          background: "transparent",
          border: 0,
          borderRightWidth: 1,
          borderRightStyle: "solid",
          borderRightColor: "var(--border-soft)",
          cursor: "pointer",
        }}
      >
        <List size={16} />
      </button>

      {/* Lowercase mono tabs. Active tab paints on the accent surface. */}
      <nav aria-label="Primary" className="flex items-stretch">
        {TABS.map((t) => {
          const active = t.match(location.pathname);
          return (
            <Link
              key={t.to}
              to={t.to}
              className="flex items-center"
              style={{
                padding: "0 14px",
                letterSpacing: "0.08em",
                textTransform: active ? "uppercase" : "none",
                color: active ? "var(--text-on-accent)" : "var(--text-muted)",
                background: active ? "var(--accent)" : "transparent",
                borderRight: "1px solid var(--border-soft)",
                fontWeight: active ? 700 : 400,
                textDecoration: "none",
              }}
            >
              {t.label}
            </Link>
          );
        })}
      </nav>

      <div className="flex-1" />

      {/* Search / cmd-k. `text-transform:none` overrides the header uppercase
          so the hint kbd hint stays readable. */}
      <button
        type="button"
        onClick={openCommandPalette}
        aria-label="Open command palette"
        className="hidden items-center sm:flex"
        style={{
          gap: 8,
          padding: "0 12px",
          ...RIGHT_CELL,
          color: "var(--text-muted)",
          background: "transparent",
          border: 0,
          borderLeft: "1px solid var(--border-soft)",
          cursor: "pointer",
          textTransform: "none",
          letterSpacing: "0.06em",
        }}
      >
        <MagnifyingGlass size={13} />
        <span>search</span>
        <span style={{ color: "var(--text-faint)" }}>ctrl k</span>
      </button>

      {/* Notifications + user avatar keep their own dropdown chrome. */}
      <div className="flex items-center" style={{ ...RIGHT_CELL, padding: "0 4px", gap: 2 }}>
        <NotificationBell />
        <UserAvatarMenu />
      </div>

      {/* Engine health -- pink dot when healthy + label. Never uppercased so
          it reads as a live-status readout, not a menubar tab. */}
      <div
        className="hidden items-center sm:flex"
        style={{
          gap: 9,
          padding: "0 12px",
          ...RIGHT_CELL,
          color: "var(--text-muted)",
          textTransform: "none",
          letterSpacing: "0.05em",
        }}
        title={`Platform health: ${engine.label}`}
      >
        <span
          aria-hidden="true"
          style={{
            width: 8,
            height: 8,
            background: engine.color,
            boxShadow: engine.glow ? `0 0 7px ${engine.color}` : "none",
          }}
        />
        <span>{engine.label}</span>
      </div>

      {/* Bound-context hint -- deepest breadcrumb (Route.handle.breadcrumb). */}
      {bound !== "console" && (
        <div
          className="hidden items-center md:flex"
          style={{
            padding: "0 12px",
            ...RIGHT_CELL,
            color: "var(--text-faint)",
            textTransform: "none",
            letterSpacing: "0.06em",
          }}
        >
          {bound.toLowerCase()}
        </div>
      )}

      {/* Live clock */}
      <div
        className="flex items-center"
        style={{
          padding: "0 12px",
          ...RIGHT_CELL,
          color: "var(--text-faint)",
          textTransform: "none",
          letterSpacing: "0.06em",
          fontVariantNumeric: "tabular-nums",
        }}
      >
        {clock}
      </div>
    </header>
  );
}
