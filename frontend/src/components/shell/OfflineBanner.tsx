import { WifiSlash } from "@phosphor-icons/react/dist/csr/WifiSlash";
import { useOnlineStatus } from "@/hooks/useOnlineStatus";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatLastSync(isoString: string | null): string {
  if (!isoString) return "unknown";
  try {
    const date = new Date(isoString);
    const now = Date.now();
    const diffMs = now - date.getTime();
    const diffMin = Math.floor(diffMs / 60_000);

    if (diffMin < 1) return "just now";
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHr = Math.floor(diffMin / 60);
    if (diffHr < 24) return `${diffHr}h ago`;
    return date.toLocaleDateString();
  } catch {
    return "unknown";
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/**
 * OfflineBanner — shows when the browser has no network connectivity (UX-07).
 *
 * Renders a top banner strip indicating offline mode and last sync time.
 * Disappears automatically when connectivity is restored.
 * Read-only mode: mutation actions in the app should check useOnlineStatus()
 * and disable themselves when isOnline is false.
 */
export function OfflineBanner() {
  const { isOnline, lastSyncTime } = useOnlineStatus();

  if (isOnline) return null;

  return (
    <div
      role="status"
      aria-live="polite"
      className="flex items-center justify-center gap-2 bg-medium/20 border-b border-medium/40 px-4 py-2 font-mono text-xs text-medium"
      data-testid="offline-banner"
    >
      <WifiSlash size={14} weight="bold" aria-hidden="true" />
      <span>
        Offline — last synced {formatLastSync(lastSyncTime)}
      </span>
      <span className="text-text-muted ml-1">
        (read-only mode — data may be stale)
      </span>
    </div>
  );
}
