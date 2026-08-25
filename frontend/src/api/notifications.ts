import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "./client";

/** One `NotificationRecord` as returned by the `/notifications` router
 * (`api/schemas/endpoints.py:NotificationResponse`). The center is a pure
 * consumer of this shape; the platform owns the writers (cost.py missing
 * pricing, budget_alert.py 80%/100%). */
export interface Notification {
  id: string;
  user_id: string;
  title: string;
  body: string;
  category: string;
  source_module: string | null;
  source_entity_id: string | null;
  is_read: boolean;
  created_at: string;
  read_at: string | null;
}

export interface UnreadNotifications {
  unread_count: number;
  items: Notification[];
}

/** Badge feed: unread count + the latest 10 unread rows. Polls on the shell's
 * cadence (no new SSE channel) so a freshly written budget/pricing alert shows
 * up within one cycle. Always live so the topbar badge stays current even when
 * the center is closed. */
export function useUnreadNotifications() {
  return useQuery({
    queryKey: ["notifications", "unread"],
    queryFn: () => apiFetch<UnreadNotifications>("/notifications/unread"),
    refetchInterval: 15_000,
    staleTime: 10_000,
  });
}

/** Full list for the center, optionally scoped to unread. `enabled` keeps the
 * list idle (and un-polled) until the panel opens. */
export function useNotifications(isRead: boolean | null, enabled: boolean) {
  const scope = isRead === null ? "" : `&is_read=${isRead}`;
  return useQuery({
    queryKey: ["notifications", "list", isRead],
    queryFn: () => apiFetch<Notification[]>(`/notifications?limit=100${scope}`),
    enabled,
    refetchInterval: enabled ? 15_000 : false,
  });
}

/** Mark one row read (`POST /notifications/{id}/read`). Invalidates every
 * notifications query so both the list and the unread badge re-derive. */
export function useMarkNotificationRead() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => apiFetch<Notification>(`/notifications/${id}/read`, { method: "POST" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["notifications"] }),
  });
}

/** Mark every unread row read (`POST /notifications/read-all`). */
export function useMarkAllNotificationsRead() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => apiFetch<{ marked_read: number }>("/notifications/read-all", { method: "POST" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["notifications"] }),
  });
}

/** Delete one row (`DELETE /notifications/{id}`, 204). */
export function useDeleteNotification() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => apiFetch<unknown>(`/notifications/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["notifications"] }),
  });
}
