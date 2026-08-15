import { Link } from "react-router";

import { useRecentlyViewed } from "@/hooks/useRecentlyViewed";

function formatRelativeTime(timestamp: number): string {
  const diffMs = Date.now() - timestamp;
  const diffSec = Math.floor(diffMs / 1000);
  const diffMin = Math.floor(diffSec / 60);
  const diffHr = Math.floor(diffMin / 60);

  if (diffMin < 1) return "just now";
  if (diffMin < 60) return `${diffMin}m ago`;
  if (diffHr < 24) return `${diffHr}h ago`;
  return `${Math.floor(diffHr / 24)}d ago`;
}

/**
 * RecentlyViewed -- the workbench rail's recent-entities list. Rendered only
 * when the rail is visible (AppShell mounts the rail conditionally), so it no
 * longer needs the shadcn sidebar collapse context.
 */
export function RecentlyViewed() {
  const { items } = useRecentlyViewed();

  if (items.length === 0) return null;

  return (
    <div className="pb-2">
      <p
        className="font-mono uppercase"
        style={{
          fontSize: "9px",
          letterSpacing: "0.16em",
          color: "var(--color-text-muted)",
          padding: "10px 12px 5px",
        }}
      >
        Recent
      </p>
      <ul>
        {items.map((item) => (
          <li key={item.path}>
            <Link
              to={item.path}
              className="flex items-center justify-between px-3 py-1.5 font-mono transition-colors hover:bg-elevated"
              style={{ fontSize: "11px", color: "var(--color-text-muted)" }}
            >
              <span className="min-w-0 truncate">{item.label}</span>
              <span className="ml-2 shrink-0" style={{ fontSize: "9px", color: "var(--color-text-faint)" }}>
                {formatRelativeTime(item.visitedAt)}
              </span>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
