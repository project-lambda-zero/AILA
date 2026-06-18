import { useEffect } from "react";
import { Link, matchRoutes, useLocation, useMatches } from "react-router";
import { MagnifyingGlass } from "@phosphor-icons/react/dist/csr/MagnifyingGlass";

import { routeObjects } from "@/app/router";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { NotificationBell } from "@/components/shell/NotificationBell";
import { UserAvatarMenu } from "@/components/shell/UserAvatarMenu";

interface RouteMatch {
  id: string;
  pathname: string;
  handle?: { breadcrumb?: string };
}

function titleCaseSegment(segment: string): string {
  if (/^\d+$/.test(segment)) return "Detail";
  return segment
    .split(/[-_]/g)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

/**
 * Return true when ``candidate`` resolves to a registered route. The
 * pathname-fallback used to synthesise crumbs for every `/a/b/c` prefix,
 * which produced dead links whenever a module registered only
 * ``/forensics`` and ``/forensics/projects/:id`` (no ``/forensics/projects``
 * list page exists). We filter fallbacks through the actual router so
 * crumbs only appear for paths that navigate somewhere real.
 */
function pathHasRoute(candidate: string): boolean {
  const hits = matchRoutes(routeObjects, candidate);
  if (!hits) return false;
  // ``matchRoutes`` returns the catch-all ``*`` route for any unknown
  // path; reject matches whose path is ``*``.
  return hits.some((h) => h.route.path && h.route.path !== "*");
}

/**
 * Look up the breadcrumb label declared on whichever route matches
 * ``candidate`` (via ``matchRoutes``), or ``null`` when no match
 * declares one. Used to synthesise intermediate crumbs when module
 * routes are registered as flat siblings rather than nested children.
 */
function breadcrumbForPath(candidate: string): string | null {
  const hits = matchRoutes(routeObjects, candidate);
  if (!hits) return null;
  for (let i = hits.length - 1; i >= 0; i -= 1) {
    const handle = (hits[i].route as { handle?: { breadcrumb?: string } }).handle;
    if (handle?.breadcrumb) return handle.breadcrumb;
  }
  return null;
}

function buildCrumbs(
  pathname: string,
  matches: RouteMatch[],
): Array<{ label: string; path: string; isLast: boolean }> {
  // Preferred path: use every route in the active match chain that
  // declared ``handle.breadcrumb``. Top-level module routes now
  // declare this so the trail stays correct.
  const handleCrumbs = matches
    .filter((m) => m.handle?.breadcrumb)
    .map((m) => ({ label: m.handle!.breadcrumb!, path: m.pathname }));

  if (handleCrumbs.length > 0) {
    // Module routes are registered as flat siblings, so ``useMatches``
    // only returns the single matched module route (not its logical
    // ancestors). Walk pathname prefixes and synthesise crumbs for any
    // prefix that resolves to a registered route with a declared
    // breadcrumb, merging them with the active match chain and keeping
    // ``currentPath`` as the terminal crumb.
    const segments = pathname.replace(/^\/+/, "").split("/").filter(Boolean);
    const currentPath = handleCrumbs[handleCrumbs.length - 1].path;
    const seen = new Set<string>(handleCrumbs.map((c) => c.path));
    const synthesized: Array<{ label: string; path: string }> = [];
    for (let i = 0; i < segments.length; i += 1) {
      const prefix = "/" + segments.slice(0, i + 1).join("/");
      if (prefix === currentPath || seen.has(prefix)) continue;
      const label = breadcrumbForPath(prefix);
      if (label) {
        synthesized.push({ label, path: prefix });
        seen.add(prefix);
      }
    }
    const merged = [...synthesized, ...handleCrumbs].sort(
      (a, b) => a.path.length - b.path.length,
    );
    const crumbs = [
      { label: "Home", path: "/" },
      ...merged.filter((c) => c.path !== "/"),
    ];
    return crumbs.map((c, i) => ({ ...c, isLast: i === crumbs.length - 1 }));
  }

  // Fallback: derive from pathname segments, but ONLY emit a crumb for
  // a prefix that resolves to a registered route. This keeps
  // intermediate crumbs clickable without ever linking to a 404.
  if (pathname === "/") {
    return [{ label: "Dashboard", path: "/", isLast: true }];
  }

  const segments = pathname.replace(/^\/+/, "").split("/").filter(Boolean);
  const crumbs: Array<{ label: string; path: string }> = [
    { label: "Home", path: "/" },
  ];
  segments.forEach((seg, index) => {
    const path = "/" + segments.slice(0, index + 1).join("/");
    const isCurrent = index === segments.length - 1;
    // Always keep the current location so the user sees where they are;
    // intermediate crumbs only survive when they navigate somewhere.
    if (isCurrent || pathHasRoute(path)) {
      crumbs.push({ label: titleCaseSegment(seg), path });
    }
  });

  return crumbs.map((c, i) => ({ ...c, isLast: i === crumbs.length - 1 }));
}

function openCommandPalette() {
  window.dispatchEvent(new CustomEvent("open-command-palette"));
}

export function AppHeader() {
  const location = useLocation();
  const matches = useMatches() as RouteMatch[];
  const crumbs = buildCrumbs(location.pathname, matches);

  // Keyboard shortcut: Ctrl+K / Cmd+K opens command palette (Plan 03 listens for event)
  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "k" && (event.ctrlKey || event.metaKey)) {
        event.preventDefault();
        openCommandPalette();
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  return (
    <header className="flex h-14 min-w-0 w-full shrink-0 items-center justify-between gap-3 border-b border-border bg-background px-4 overflow-hidden">
      {/* Left side: hamburger toggle + separator + breadcrumbs */}
      <div className="flex items-center gap-2 min-w-0 flex-1 overflow-hidden">
        <SidebarTrigger className="-ml-1" />
        <Separator orientation="vertical" className="mx-1 h-4" />
        <Breadcrumb className="min-w-0 flex-1 overflow-hidden">
          <BreadcrumbList className="flex-nowrap overflow-hidden">
            {crumbs.map((crumb, index) => (
              <BreadcrumbItem key={crumb.path} className="min-w-0 shrink truncate">
                {index > 0 && <BreadcrumbSeparator className="shrink-0" />}
                {crumb.isLast ? (
                  <BreadcrumbPage className="truncate">{crumb.label}</BreadcrumbPage>
                ) : (
                  <BreadcrumbLink className="truncate" render={<Link to={crumb.path} />}>
                    {crumb.label}
                  </BreadcrumbLink>
                )}
              </BreadcrumbItem>
            ))}
          </BreadcrumbList>
        </Breadcrumb>
      </div>

      {/* Right side: cmd+k trigger, notification bell, user avatar */}
      <div className="flex items-center gap-2 shrink-0">
        <Button
          variant="outline"
          size="sm"
          className="touch-target hidden sm:flex items-center gap-2 text-muted-foreground h-9 min-h-[44px] sm:min-h-0 sm:h-8 px-3"
          onClick={openCommandPalette}
          aria-label="Open command palette"
        >
          <MagnifyingGlass size={14} />
          <span className="text-sm">Search...</span>
          <kbd className="pointer-events-none ml-1 hidden select-none rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-xs opacity-70 sm:inline-flex">
            Ctrl K
          </kbd>
        </Button>
        <NotificationBell />
        <UserAvatarMenu />
      </div>
    </header>
  );
}
