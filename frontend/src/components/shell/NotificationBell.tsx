/**
 * NotificationBell -- header bell icon with unread count badge and dropdown.
 *
 * SSE-driven: the SSEProvider invalidates ["notifications"] on inbound events,
 * so this component reflects live unread state without polling (RT-02).
 *
 * Features:
 * - Unread count badge from GET /notifications/unread (server-authoritative)
 * - Dropdown lists latest 5 notifications with relative timestamps
 * - Mark individual notification as read on click
 * - "Mark all as read" in dropdown footer
 * - Navigate to /notifications for full inbox
 *
 * Per T-138-18: all queries are user-scoped on the backend.
 * Per D-12 (146-CONTEXT): polling removed, SSE invalidation drives updates.
 */
import { useNavigate } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bell } from "@phosphor-icons/react/dist/csr/Bell";
import { Check } from "@phosphor-icons/react/dist/csr/Check";

import { authorizedRequestJson } from "@platform/api/http";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface NotificationItem {
  id: string;
  title: string;
  body?: string;
  category?: string;
  is_read?: boolean;
  created_at?: string;
}

interface NotificationsEnvelope {
  data?: NotificationItem[];
  meta?: { total?: number };
}

interface UnreadEnvelope {
  data?: {
    unread_count: number;
    items?: NotificationItem[];
  };
  meta?: { unread_count?: number };
}

// ---------------------------------------------------------------------------
// Relative time helper
// ---------------------------------------------------------------------------

function relativeTime(isoString: string | undefined): string {
  if (!isoString) return "";
  const now = Date.now();
  const then = new Date(isoString).getTime();
  const diffMs = now - then;
  const diffMin = Math.floor(diffMs / 60_000);
  if (diffMin < 1) return "Just now";
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHour = Math.floor(diffMin / 60);
  if (diffHour < 24) return `${diffHour}h ago`;
  return `${Math.floor(diffHour / 24)}d ago`;
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

/** Latest 5 notifications for the dropdown list. */
function useRecentNotifications() {
  return useQuery<NotificationsEnvelope>({
    queryKey: ["notifications", "recent"],
    queryFn: () =>
      authorizedRequestJson<NotificationsEnvelope>("/notifications?limit=5"),
    // No refetchInterval -- SSEProvider invalidates this key on notification events
    staleTime: 60_000,
    retry: false,
    throwOnError: false,
  });
}

/** Server-authoritative unread count from /notifications/unread. */
function useUnreadCount() {
  return useQuery<UnreadEnvelope>({
    queryKey: ["notifications", "unread-count"],
    queryFn: () => authorizedRequestJson<UnreadEnvelope>("/notifications/unread"),
    staleTime: 60_000,
    retry: false,
    throwOnError: false,
  });
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function NotificationBell() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const { data: recentData } = useRecentNotifications();
  const { data: unreadData } = useUnreadCount();

  const notifications: NotificationItem[] = recentData?.data ?? [];
  const badgeCount: number = unreadData?.data?.unread_count ?? 0;

  // Mark individual notification as read
  const markRead = useMutation({
    mutationFn: (id: string) =>
      authorizedRequestJson(`/notifications/${id}/read`, { method: "POST" }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["notifications"] });
    },
  });

  // Mark all as read
  const markAllRead = useMutation({
    mutationFn: () =>
      authorizedRequestJson("/notifications/read-all", { method: "POST" }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["notifications"] });
    },
  });

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <Button
            variant="ghost"
            size="sm"
            className="relative h-8 w-8 p-0"
            aria-label={
              badgeCount > 0
                ? `${badgeCount} unread notifications`
                : "Notifications"
            }
          />
        }
      >
        <Bell size={18} />
        {badgeCount > 0 && (
          <Badge
            variant="destructive"
            className="absolute -top-0.5 -right-0.5 flex h-4 min-w-4 items-center justify-center rounded-full p-0 text-[10px] font-bold leading-none"
          >
            {badgeCount > 99 ? "99+" : badgeCount}
          </Badge>
        )}
      </DropdownMenuTrigger>

      <DropdownMenuContent align="end" side="bottom" sideOffset={8} className="w-80">
        <DropdownMenuLabel className="flex items-center justify-between">
          <span>Notifications</span>
          {badgeCount > 0 && (
            <span className="text-xs text-text-muted font-normal">
              {badgeCount} unread
            </span>
          )}
        </DropdownMenuLabel>
        <DropdownMenuSeparator />

        {notifications.length === 0 ? (
          <div className="p-4 text-center text-sm text-text-muted">
            No new notifications
          </div>
        ) : (
          notifications.slice(0, 5).map((notification) => (
            <DropdownMenuItem
              key={notification.id}
              className="flex flex-col items-start gap-1 py-2 cursor-pointer"
              onClick={() => {
                if (!notification.is_read) {
                  markRead.mutate(notification.id);
                }
              }}
            >
              <div className="flex w-full items-start justify-between gap-2">
                <div className="flex items-center gap-1.5 min-w-0">
                  {!notification.is_read && (
                    <span
                      className="h-2 w-2 rounded-full bg-accent shrink-0 mt-0.5"
                      aria-label="Unread"
                    />
                  )}
                  <span className="text-sm font-medium text-foreground leading-snug truncate">
                    {notification.title}
                  </span>
                </div>
                {notification.created_at && (
                  <span className="text-xs text-text-muted shrink-0 mt-0.5">
                    {relativeTime(notification.created_at)}
                  </span>
                )}
              </div>
              {notification.body && (
                <span className="text-xs text-text-muted leading-snug line-clamp-2 pl-3.5">
                  {notification.body}
                </span>
              )}
            </DropdownMenuItem>
          ))
        )}

        <DropdownMenuSeparator />

        <div className="flex items-center justify-between px-2 py-1">
          {badgeCount > 0 && (
            <button
              className="flex items-center gap-1 text-xs text-text-muted hover:text-foreground transition-colors"
              onClick={(e) => {
                e.stopPropagation();
                markAllRead.mutate();
              }}
              disabled={markAllRead.isPending}
              aria-label="Mark all notifications as read"
            >
              <Check size={12} />
              Mark all read
            </button>
          )}
          <DropdownMenuItem
            className="ml-auto text-sm text-accent hover:text-accent/80 cursor-pointer px-0"
            onClick={() => navigate("/notifications")}
          >
            View all
          </DropdownMenuItem>
        </div>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
