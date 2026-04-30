import { useState, useEffect } from "react";

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

interface UseOnlineStatusReturn {
  isOnline: boolean;
  lastSyncTime: string | null;
}

/**
 * useOnlineStatus — tracks browser online/offline state.
 *
 * Uses navigator.onLine for initial value, then listens to the
 * browser's online/offline events for real-time updates.
 *
 * lastSyncTime: read from localStorage "aila-last-sync" key.
 * The Service Worker writes this key when caching a response.
 *
 * @example
 * ```tsx
 * const { isOnline } = useOnlineStatus();
 * if (!isOnline) return <OfflineBanner />;
 * ```
 */
export function useOnlineStatus(): UseOnlineStatusReturn {
  const [isOnline, setIsOnline] = useState(() =>
    typeof navigator !== "undefined" ? navigator.onLine : true,
  );
  const [lastSyncTime, setLastSyncTime] = useState<string | null>(() => {
    try {
      return localStorage.getItem("aila-last-sync");
    } catch {
      return null;
    }
  });

  useEffect(() => {
    function handleOnline() {
      setIsOnline(true);
      // Refresh last sync time when coming back online
      try {
        setLastSyncTime(localStorage.getItem("aila-last-sync"));
      } catch {
        // ignore
      }
    }

    function handleOffline() {
      setIsOnline(false);
    }

    window.addEventListener("online", handleOnline);
    window.addEventListener("offline", handleOffline);

    return () => {
      window.removeEventListener("online", handleOnline);
      window.removeEventListener("offline", handleOffline);
    };
  }, []);

  return { isOnline, lastSyncTime };
}
