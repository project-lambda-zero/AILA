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
 *
 * UI: rebuilt on the mock kit -- raw <button> trigger with a MonoBadge count
 * dot, absolute-positioned <WindowPanel> dropdown, no shadcn primitives.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bell } from "@phosphor-icons/react/dist/csr/Bell";
import { Check } from "@phosphor-icons/react/dist/csr/Check";

import { authorizedRequestJson } from "@platform/api/http";
import { MonoBadge } from "@/components/aila/mock";
import { WindowPanel } from "@/components/aila/WindowPanel";

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
// Presentation helpers
// ---------------------------------------------------------------------------

const ROW_STYLE: React.CSSProperties = {
  display: "flex",
  flexDirection: "column",
  gap: 4,
  padding: "8px 10px",
  fontFamily: "var(--font-mono)",
  cursor: "pointer",
  borderBottom: "1px solid var(--border-faint)",
  background: "transparent",
  border: 0,
  borderRadius: 0,
  textAlign: "left",
  width: "100%",
};

const FOOTER_LINK_STYLE: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  gap: 4,
  height: 22,
  padding: "0 8px",
  fontFamily: "var(--font-mono)",
  fontSize: 10,
  letterSpacing: "0.08em",
  color: "var(--text-muted)",
  background: "transparent",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  cursor: "pointer",
  textTransform: "uppercase",
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function NotificationBell() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement | null>(null);

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

  const closeMenu = useCallback(() => setOpen(false), []);

  useEffect(() => {
    if (!open) return;
    function onDown(event: MouseEvent) {
      if (!rootRef.current) return;
      if (!rootRef.current.contains(event.target as Node)) setOpen(false);
    }
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") setOpen(false);
    }
    window.addEventListener("mousedown", onDown);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onDown);
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const ariaLabel =
    badgeCount > 0 ? `${badgeCount} unread notifications` : "Notifications";
  const displayCount = badgeCount > 99 ? "99+" : String(badgeCount);

  return (
    <div ref={rootRef} style={{ position: "relative", display: "inline-flex" }}>
      <button
        type="button"
        aria-label={ariaLabel}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((prev) => !prev)}
        className="touch-target flex items-center justify-center"
        style={{
          position: "relative",
          width: 30,
          height: 28,
          padding: 0,
          background: "transparent",
          color: "var(--text-primary)",
          border: "1px solid var(--border-soft)",
          borderRadius: 3,
          cursor: "pointer",
        }}
      >
        <Bell size={16} />
        {badgeCount > 0 && (
          <span
            aria-hidden="true"
            style={{
              position: "absolute",
              top: -6,
              right: -6,
              pointerEvents: "none",
            }}
          >
            <MonoBadge tone="critical">{displayCount}</MonoBadge>
          </span>
        )}
      </button>

      {open && (
        <div
          role="menu"
          style={{
            position: "absolute",
            top: "calc(100% + 6px)",
            right: 0,
            zIndex: 60,
            width: 340,
          }}
        >
          <WindowPanel
            title="notifications"
            tone={badgeCount > 0 ? "warn" : "muted"}
            actions={
              badgeCount > 0 ? (
                <span
                  className="font-mono uppercase"
                  style={{
                    fontSize: 9.5,
                    letterSpacing: "0.1em",
                    color: "var(--text-muted)",
                  }}
                >
                  {badgeCount} unread
                </span>
              ) : null
            }
            flush
          >
            {notifications.length === 0 ? (
              <div
                className="font-mono"
                style={{
                  padding: 20,
                  textAlign: "center",
                  fontSize: 10.5,
                  color: "var(--text-muted)",
                  letterSpacing: "0.04em",
                }}
              >
                No new notifications
              </div>
            ) : (
              <div style={{ maxHeight: 360, overflowY: "auto" }}>
                {notifications.slice(0, 5).map((notification) => (
                  <button
                    type="button"
                    role="menuitem"
                    key={notification.id}
                    style={ROW_STYLE}
                    onMouseEnter={(e) => {
                      (e.currentTarget as HTMLElement).style.background =
                        "var(--surface-hover)";
                    }}
                    onMouseLeave={(e) => {
                      (e.currentTarget as HTMLElement).style.background = "transparent";
                    }}
                    onClick={() => {
                      if (!notification.is_read) {
                        markRead.mutate(notification.id);
                      }
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        alignItems: "flex-start",
                        justifyContent: "space-between",
                        gap: 8,
                        width: "100%",
                      }}
                    >
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 6,
                          minWidth: 0,
                        }}
                      >
                        {!notification.is_read && (
                          <span
                            aria-label="Unread"
                            style={{
                              width: 6,
                              height: 6,
                              flex: "0 0 auto",
                              background: "var(--accent)",
                              boxShadow: "0 0 6px var(--accent)",
                            }}
                          />
                        )}
                        <span
                          style={{
                            fontSize: 11,
                            color: "var(--text-primary)",
                            letterSpacing: "0.02em",
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                          }}
                        >
                          {notification.title}
                        </span>
                      </div>
                      {notification.created_at && (
                        <span
                          style={{
                            fontSize: 9.5,
                            color: "var(--text-faint)",
                            flex: "0 0 auto",
                            letterSpacing: "0.06em",
                          }}
                        >
                          {relativeTime(notification.created_at)}
                        </span>
                      )}
                    </div>
                    {notification.body && (
                      <span
                        style={{
                          fontSize: 10,
                          color: "var(--text-muted)",
                          lineHeight: 1.4,
                          paddingLeft: notification.is_read ? 0 : 12,
                          display: "-webkit-box",
                          WebkitLineClamp: 2,
                          WebkitBoxOrient: "vertical",
                          overflow: "hidden",
                        }}
                      >
                        {notification.body}
                      </span>
                    )}
                  </button>
                ))}
              </div>
            )}

            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 8,
                padding: "8px 10px",
                borderTop: "1px solid var(--border-faint)",
                background: "var(--surface-sunk)",
              }}
            >
              {badgeCount > 0 ? (
                <button
                  type="button"
                  style={FOOTER_LINK_STYLE}
                  onClick={(e) => {
                    e.stopPropagation();
                    markAllRead.mutate();
                  }}
                  disabled={markAllRead.isPending}
                  aria-label="Mark all notifications as read"
                >
                  <Check size={11} />
                  <span>Mark all read</span>
                </button>
              ) : (
                <span />
              )}
              <button
                type="button"
                role="menuitem"
                style={{
                  ...FOOTER_LINK_STYLE,
                  color: "var(--accent)",
                  border: "1px solid var(--accent)",
                  background: "color-mix(in srgb, var(--accent) 8%, transparent)",
                }}
                onClick={() => {
                  closeMenu();
                  navigate("/notifications");
                }}
              >
                View all
              </button>
            </div>
          </WindowPanel>
        </div>
      )}
    </div>
  );
}
