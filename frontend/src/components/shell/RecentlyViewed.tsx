import { Link } from "react-router-dom";

import { useRecentlyViewed } from "@/hooks/useRecentlyViewed";
import { useSidebar } from "@/components/ui/sidebar";

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

export function RecentlyViewed() {
  const { state } = useSidebar();
  const { items } = useRecentlyViewed();

  // Hide entirely in collapsed (icon-only rail) mode
  if (state === "collapsed") return null;

  if (items.length === 0) return null;

  return (
    <div className="px-2 pb-2">
      <p className="px-2 py-1 text-xs font-medium text-sidebar-foreground/50 uppercase tracking-wider">
        Recent
      </p>
      <ul className="space-y-0.5">
        {items.map((item) => (
          <li key={item.path}>
            <Link
              to={item.path}
              className="flex items-center justify-between px-2 py-1.5 rounded-md text-xs text-sidebar-foreground/70 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground transition-colors"
            >
              <span className="truncate min-w-0">{item.label}</span>
              <span className="ml-2 shrink-0 text-sidebar-foreground/40">
                {formatRelativeTime(item.visitedAt)}
              </span>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
