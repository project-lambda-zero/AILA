import { useEffect, useState } from "react";
import type { CSSProperties } from "react";

import {
  useDeleteNotification,
  useMarkAllNotificationsRead,
  useMarkNotificationRead,
  useNotifications,
  useUnreadNotifications,
  type Notification,
} from "../api/notifications";

// First-class alerts center for the console shell. A bell affordance in the
// menu bar carries an unread badge; clicking it opens a panel that reads,
// acks, and deletes the rows the platform already writes (cost.py missing
// pricing, budget_alert.py 80%/100%). Pure consumer of the /notifications
// router -- no backend change, no new delivery channel.

type Tab = "unread" | "all";

interface Kind {
  label: string;
  tone: string;
}

// A row's display kind so a spend alert reads differently from a config
// warning. Budget alerts arrive from budget_alert.py with category "warning";
// missing-pricing rows arrive from cost.py carrying a "pricing_missing:<slug>"
// source_entity_id. Tone drives the left rule + kind chip color.
function classify(n: Notification): Kind {
  if (n.source_entity_id && n.source_entity_id.startsWith("pricing_missing:")) {
    return { label: "config", tone: "var(--status-info)" };
  }
  const c = n.category.toLowerCase();
  if (c === "warning") return { label: "budget", tone: "var(--status-warn)" };
  if (c === "error" || c === "critical") return { label: c, tone: "var(--accent)" };
  if (c === "success") return { label: c, tone: "var(--status-ok)" };
  return { label: c || "info", tone: "var(--status-signal)" };
}

// Compact relative age ("3m" / "2h" / "5d"), with an absolute date past a
// month and a raw-string fallback on an unparseable timestamp (never "NaN").
function relAge(iso: string): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  const secs = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (secs < 60) return `${secs}s`;
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h`;
  const days = Math.round(hrs / 24);
  if (days < 30) return `${days}d`;
  return new Date(t).toLocaleDateString();
}

const rowActBtn: CSSProperties = {
  background: "transparent",
  border: "1px solid var(--border-soft)",
  borderRadius: 2,
  color: "var(--text-primary)",
  fontFamily: "var(--font-mono)",
  fontSize: 9,
  letterSpacing: "0.06em",
  textTransform: "uppercase",
  padding: "2px 6px",
  cursor: "pointer",
  flex: "0 0 auto",
};

const rowDelBtn: CSSProperties = {
  background: "transparent",
  border: 0,
  color: "var(--text-muted)",
  fontFamily: "var(--font-mono)",
  fontSize: 11,
  cursor: "pointer",
  padding: "0 4px",
  flex: "0 0 auto",
};

function CenterMessage({ text, tone }: { text: string; tone?: string }) {
  return (
    <div style={{ padding: "26px 14px", textAlign: "center", fontSize: 10.5, color: tone ?? "var(--text-faint)" }}>{text}</div>
  );
}

function NotificationRow({ n, onRead, onDelete }: { n: Notification; onRead: (id: string) => void; onDelete: (id: string) => void }) {
  const k = classify(n);
  return (
    <div
      style={{
        display: "flex",
        borderBottom: "1px solid var(--border-faint)",
        opacity: n.is_read ? 0.62 : 1,
        background: n.is_read ? "transparent" : "color-mix(in srgb, var(--accent) 4%, transparent)",
      }}
    >
      <span aria-hidden="true" style={{ flex: "0 0 3px", background: k.tone }} />
      <div style={{ flex: 1, minWidth: 0, padding: "8px 10px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ fontSize: 8.5, fontWeight: 700, letterSpacing: "0.1em", textTransform: "uppercase", color: k.tone }}>{k.label}</span>
          <div style={{ flex: 1 }} />
          <span style={{ fontSize: 9, color: "var(--text-faint)" }} title={n.created_at}>{relAge(n.created_at)}</span>
        </div>
        <div style={{ fontSize: 11.5, fontWeight: 600, marginTop: 3, wordBreak: "break-word" }}>{n.title}</div>
        {n.body ? (
          <div style={{ fontSize: 10.5, color: "var(--text-muted)", marginTop: 2, wordBreak: "break-word", whiteSpace: "pre-wrap" }}>{n.body}</div>
        ) : null}
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 5 }}>
          {n.source_module ? <span style={{ fontSize: 9, color: "var(--text-faint)" }}>{n.source_module}</span> : null}
          {n.source_entity_id ? (
            <span style={{ fontSize: 9, color: "var(--text-faint)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 180 }} title={n.source_entity_id}>
              {n.source_entity_id}
            </span>
          ) : null}
          <div style={{ flex: 1 }} />
          {!n.is_read ? (
            <button type="button" onClick={() => onRead(n.id)} style={rowActBtn}>
              mark read
            </button>
          ) : null}
          <button type="button" aria-label="delete notification" title="delete" onClick={() => onDelete(n.id)} style={rowDelBtn}>
            {"\u2715"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function NotificationsCenter() {
  const [open, setOpen] = useState(false);
  const [tab, setTab] = useState<Tab>("unread");

  const unread = useUnreadNotifications();
  const unreadCount = unread.data?.unread_count ?? 0;

  const list = useNotifications(tab === "unread" ? false : null, open);
  const markRead = useMarkNotificationRead();
  const markAll = useMarkAllNotificationsRead();
  const del = useDeleteNotification();

  // Esc closes the panel while it is open.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  const rows = list.data ?? [];

  return (
    <div style={{ position: "relative", display: "flex", alignItems: "stretch" }}>
      <button
        type="button"
        aria-label={unreadCount > 0 ? `notifications, ${unreadCount} unread` : "notifications"}
        aria-expanded={open}
        aria-haspopup="dialog"
        title="notifications"
        onClick={() => setOpen((v) => !v)}
        style={{
          position: "relative",
          display: "flex",
          alignItems: "center",
          padding: "0 12px",
          background: open ? "var(--accent)" : "transparent",
          color: open ? "var(--text-on-accent)" : unreadCount > 0 ? "var(--text-primary)" : "var(--text-muted)",
          border: 0,
          borderLeft: "1px solid var(--border-soft)",
          cursor: "pointer",
        }}
      >
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M8 1.8a1 1 0 0 1 1 1v.5c1.8.45 3 2.03 3 4.02v2.4l1 1.5H3l1-1.5V7.32C4 5.33 5.2 3.75 7 3.3v-.5a1 1 0 0 1 1-1z" />
          <path d="M6.3 12.8a1.7 1.7 0 0 0 3.4 0" />
        </svg>
        {unreadCount > 0 ? (
          <span
            style={{
              position: "absolute",
              top: 3,
              right: 4,
              minWidth: 14,
              height: 14,
              padding: "0 3px",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              background: "var(--accent)",
              color: "var(--text-on-accent)",
              fontSize: 8.5,
              fontWeight: 700,
              borderRadius: 8,
              lineHeight: 1,
            }}
          >
            {unreadCount > 99 ? "99+" : unreadCount}
          </span>
        ) : null}
      </button>

      {open ? (
        <>
          <div aria-hidden="true" onClick={() => setOpen(false)} style={{ position: "fixed", inset: 0, zIndex: 55, background: "transparent" }} />
          <div
            role="dialog"
            aria-label="notifications center"
            style={{
              position: "fixed",
              top: "var(--menubar-h,32px)",
              right: 0,
              width: 400,
              maxWidth: "96vw",
              maxHeight: "calc(100vh - var(--menubar-h,32px) - var(--statusbar-h,24px) - 16px)",
              display: "flex",
              flexDirection: "column",
              zIndex: 60,
              background: "var(--surface-card)",
              border: "1px solid var(--border)",
              borderTop: "2px solid var(--accent)",
              boxShadow: "0 18px 50px rgba(0,0,0,0.55)",
              fontFamily: "var(--font-mono)",
              color: "var(--text-primary)",
              textTransform: "none",
              letterSpacing: "normal",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "9px 11px", borderBottom: "1px solid var(--border-soft)" }}>
              <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.12em", textTransform: "uppercase" }}>notifications</span>
              <div style={{ flex: 1 }} />
              <button
                type="button"
                disabled={unreadCount === 0 || markAll.isPending}
                onClick={() => markAll.mutate()}
                style={{
                  background: "transparent",
                  border: "1px solid var(--border-soft)",
                  borderRadius: 2,
                  color: unreadCount === 0 ? "var(--text-faint)" : "var(--text-primary)",
                  fontFamily: "var(--font-mono)",
                  fontSize: 9,
                  letterSpacing: "0.06em",
                  textTransform: "uppercase",
                  padding: "3px 7px",
                  cursor: unreadCount === 0 ? "default" : "pointer",
                }}
              >
                mark all read
              </button>
              <button
                type="button"
                aria-label="close notifications"
                onClick={() => setOpen(false)}
                style={{ background: "transparent", border: 0, color: "var(--text-muted)", fontFamily: "var(--font-mono)", fontSize: 12, cursor: "pointer", padding: "0 3px" }}
              >
                {"\u2715"}
              </button>
            </div>

            <div style={{ display: "flex", borderBottom: "1px solid var(--border-soft)" }}>
              {(["unread", "all"] as Tab[]).map((t) => (
                <button
                  key={t}
                  type="button"
                  onClick={() => setTab(t)}
                  aria-pressed={tab === t}
                  style={{
                    flex: 1,
                    padding: "6px 0",
                    background: tab === t ? "color-mix(in srgb, var(--accent) 14%, transparent)" : "transparent",
                    color: tab === t ? "var(--text-primary)" : "var(--text-muted)",
                    border: 0,
                    borderBottom: tab === t ? "2px solid var(--accent)" : "2px solid transparent",
                    fontFamily: "var(--font-mono)",
                    fontSize: 10,
                    letterSpacing: "0.1em",
                    textTransform: "uppercase",
                    cursor: "pointer",
                  }}
                >
                  {t === "unread" && unreadCount > 0 ? `unread (${unreadCount})` : t}
                </button>
              ))}
            </div>

            <div style={{ overflowY: "auto", flex: 1 }}>
              {list.isLoading ? (
                <CenterMessage text="loading notifications..." />
              ) : list.isError ? (
                <CenterMessage text="could not load notifications." tone="var(--accent)" />
              ) : rows.length === 0 ? (
                <CenterMessage text={tab === "unread" ? "no unread notifications." : "no notifications yet."} />
              ) : (
                rows.map((n) => <NotificationRow key={n.id} n={n} onRead={(id) => markRead.mutate(id)} onDelete={(id) => del.mutate(id)} />)
              )}
            </div>
          </div>
        </>
      ) : null}
    </div>
  );
}
