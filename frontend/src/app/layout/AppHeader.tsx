import { useEffect, useState } from "react";
import { useMatches } from "react-router";
import { MagnifyingGlass } from "@phosphor-icons/react/dist/csr/MagnifyingGlass";
import { List } from "@phosphor-icons/react/dist/csr/List";

import { NotificationBell } from "@/components/shell/NotificationBell";
import { UserAvatarMenu } from "@/components/shell/UserAvatarMenu";

/**
 * AppHeader -- the AILA workbench MenuBar.
 *
 * The 32px OS-frame menubar from the design system: a glowing pink brand
 * square + AILA wordmark, a rail toggle, a mono uppercase breadcrumb, and a
 * right cluster of search / notifications / account / clock. This is the
 * mockup menubar, not a restyled dashboard header.
 */
interface AppHeaderProps {
  onToggleRail?: () => void;
}

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
  return now.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

const CELL_BORDER = "1px solid var(--color-border)";

export function AppHeader({ onToggleRail }: AppHeaderProps) {
  const matches = useMatches() as RouteMatch[];
  const crumbs = matches
    .filter((m) => m.handle?.breadcrumb)
    .map((m) => m.handle!.breadcrumb as string);
  const clock = useClock();

  return (
    <header
      className="flex flex-none items-stretch font-mono"
      style={{
        height: "var(--menubar-h)",
        background: "var(--color-chrome)",
        borderBottom: "2px solid var(--color-border-bright)",
      }}
    >
      <div className="flex items-center gap-2 px-3" style={{ borderRight: CELL_BORDER }}>
        <span
          aria-hidden="true"
          style={{ width: 9, height: 9, background: "var(--color-accent)", boxShadow: "0 0 8px var(--color-accent)" }}
        />
        <span
          className="font-bold select-none"
          style={{ letterSpacing: "0.2em", fontSize: "12px", color: "var(--color-text)" }}
        >
          AILA
        </span>
      </div>

      <button
        type="button"
        onClick={onToggleRail}
        aria-label="Toggle rail"
        className="flex items-center px-3 transition-colors hover:bg-elevated"
        style={{ borderRight: CELL_BORDER, color: "var(--color-text-muted)" }}
      >
        <List size={16} />
      </button>

      <nav
        aria-label="Breadcrumb"
        className="flex items-center gap-2 overflow-hidden px-3 uppercase"
        style={{ fontSize: "10.5px", letterSpacing: "0.12em", color: "var(--color-text-muted)" }}
      >
        {crumbs.length > 0 ? (
          crumbs.map((c, i) => (
            <span key={`${c}-${i}`} className="flex items-center gap-2 whitespace-nowrap">
              {i > 0 && <span style={{ color: "var(--color-text-faint)" }}>/</span>}
              <span style={{ color: i === crumbs.length - 1 ? "var(--color-text)" : "var(--color-text-muted)" }}>
                {c}
              </span>
            </span>
          ))
        ) : (
          <span>console</span>
        )}
      </nav>

      <div className="flex-1" />

      <button
        type="button"
        onClick={openCommandPalette}
        aria-label="Open command palette"
        className="flex items-center gap-2 px-3 uppercase transition-colors hover:bg-elevated"
        style={{ borderLeft: CELL_BORDER, fontSize: "10.5px", letterSpacing: "0.1em", color: "var(--color-text-muted)" }}
      >
        <MagnifyingGlass size={14} />
        <span className="hidden sm:inline">search</span>
        <span style={{ color: "var(--color-text-faint)" }}>ctrl k</span>
      </button>

      <div className="flex items-center gap-1 px-2" style={{ borderLeft: CELL_BORDER }}>
        <NotificationBell />
        <UserAvatarMenu />
      </div>

      <div
        className="hidden items-center px-3 sm:flex"
        style={{ borderLeft: CELL_BORDER, fontSize: "10.5px", letterSpacing: "0.06em", color: "var(--color-text-faint)" }}
      >
        {clock}
      </div>
    </header>
  );
}
