import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Monitor } from "@phosphor-icons/react/dist/csr/Monitor";

import { fetchSessions, revokeSession, type SessionRecord } from "./api";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";
import {
  SectionHeader,
  DataGrid,
  MonoBadge,
} from "@/components/aila/mock";

// ---------------------------------------------------------------------------
// User-agent parsing
// ---------------------------------------------------------------------------

function parseBrowser(userAgent: string | null): string {
  if (!userAgent) return "unknown browser";
  if (/Firefox\//i.test(userAgent)) return "firefox";
  if (/Edg\//i.test(userAgent)) return "edge";
  if (/Chrome\//i.test(userAgent)) return "chrome";
  if (/Safari\//i.test(userAgent)) return "safari";
  if (/Opera|OPR\//i.test(userAgent)) return "opera";
  return "unknown browser";
}

function parseOS(userAgent: string | null): string {
  if (!userAgent) return "unknown os";
  if (/Windows NT/i.test(userAgent)) return "windows";
  if (/Mac OS X/i.test(userAgent)) return "macos";
  if (/Linux/i.test(userAgent)) return "linux";
  if (/Android/i.test(userAgent)) return "android";
  if (/iPhone|iPad/i.test(userAgent)) return "ios";
  return "unknown os";
}

// ---------------------------------------------------------------------------
// Relative time
// ---------------------------------------------------------------------------

function relativeTime(isoString: string | null): string {
  if (!isoString) return "unknown";
  const now = Date.now();
  const then = new Date(isoString).getTime();
  const diffSec = Math.floor((now - then) / 1000);
  if (diffSec < 60) return "just now";
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHour = Math.floor(diffMin / 60);
  if (diffHour < 24) return `${diffHour}h ago`;
  const diffDay = Math.floor(diffHour / 24);
  return `${diffDay}d ago`;
}

// ---------------------------------------------------------------------------
// Shared inline styles
// ---------------------------------------------------------------------------

const ACTION_BUTTON_STYLE: React.CSSProperties = {
  height: 22,
  fontSize: 9.5,
  padding: "0 10px",
  textTransform: "uppercase",
  letterSpacing: "0.1em",
  background: "var(--surface-sunk)",
  color: "var(--status-warn)",
  border:
    "1px solid color-mix(in srgb, var(--status-warn) 45%, transparent)",
  borderRadius: 3,
  cursor: "pointer",
};

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function SessionsPage() {
  const queryClient = useQueryClient();

  const sessionsQuery = useQuery({
    queryKey: ["sessions"],
    queryFn: fetchSessions,
    staleTime: 30_000,
  });

  const revokeMutation = useMutation({
    mutationFn: revokeSession,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["sessions"] });
    },
  });

  const sessions = sessionsQuery.data ?? [];

  // Heuristic (T-140-20): the session with the latest created_at is the current one.
  // This is a UI-only indicator -- server-side revocation is always correct regardless.
  const currentSessionId =
    sessions.length > 0
      ? sessions.reduce((latest, s) => {
          if (!latest.created_at) return s;
          if (!s.created_at) return latest;
          return new Date(s.created_at) > new Date(latest.created_at)
            ? s
            : latest;
        }).id
      : null;

  function handleRevoke(sessionId: string) {
    if (!window.confirm("Revoke this session? The device will be signed out.")) {
      return;
    }
    revokeMutation.mutate(sessionId);
  }

  return (
    <div className="flex flex-col" style={{ gap: 16, padding: 20 }}>
      <SectionHeader
        icon={"\u25c7"}
        title="sessions"
        actions={
          <span
            className="font-mono"
            style={{
              fontSize: 10,
              color: "var(--text-muted)",
              textTransform: "uppercase",
              letterSpacing: "0.12em",
            }}
          >
            {sessions.length} active
          </span>
        }
      />

      {sessionsQuery.isError && (
        <div
          className="font-mono"
          style={{
            border:
              "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
            background:
              "color-mix(in srgb, var(--status-warn) 10%, transparent)",
            color: "var(--status-warn)",
            padding: "10px 14px",
            fontSize: 12,
            borderRadius: 3,
          }}
        >
          failed to load sessions. please refresh the page.
        </div>
      )}

      {revokeMutation.isError && (
        <div
          className="font-mono"
          style={{
            border:
              "1px solid color-mix(in srgb, var(--status-warn) 40%, transparent)",
            background:
              "color-mix(in srgb, var(--status-warn) 10%, transparent)",
            color: "var(--status-warn)",
            padding: "10px 14px",
            fontSize: 12,
            borderRadius: 3,
          }}
        >
          failed to revoke session. please try again.
        </div>
      )}

      {sessionsQuery.isLoading ? (
        <WindowPanel
          title="session list"
          status="LOADING"
          tone="muted"
          aria-label="Loading sessions"
          aria-busy="true"
        >
          <LoadingSkeletonGroup lines={4} />
        </WindowPanel>
      ) : sessions.length === 0 ? (
        <WindowPanel title="session list" tone="muted">
          <div
            className="flex flex-col items-center justify-center"
            style={{ gap: 8, padding: 32, textAlign: "center", minHeight: 120 }}
          >
            <span aria-hidden style={{ color: "var(--text-faint)", marginBottom: 4 }}>
              <Monitor className="h-10 w-10" />
            </span>
            <div
              className="font-mono uppercase"
              style={{ fontSize: 11, letterSpacing: "0.14em", color: "var(--text-primary)" }}
            >
              No active sessions
            </div>
            <div
              className="font-mono"
              style={{ fontSize: 10.5, color: "var(--text-muted)", maxWidth: 440 }}
            >
              Your account has no active browser sessions. Sign in from another device to see it listed here.
            </div>
          </div>
        </WindowPanel>
      ) : (
        <WindowPanel
          title="session list"
          status={`${sessions.length} ACTIVE`}
          tone="muted"
          flush
        >
          <DataGrid<SessionRecord>
            columns={[
              { label: "SESSION ID", width: "160px" },
              { label: "DEVICE", width: "minmax(160px, 1fr)" },
              { label: "IP", width: "140px" },
              { label: "STARTED", width: "120px" },
              { label: "STATUS", width: "130px" },
              { label: "", width: "90px", align: "right" },
            ]}
            rows={sessions}
            getKey={(s) => s.id}
            renderCells={(s) => {
              const isCurrent = s.id === currentSessionId;
              const browser = parseBrowser(s.user_agent);
              const os = parseOS(s.user_agent);
              return [
                <span
                  className="truncate font-mono"
                  style={{ color: "var(--accent)", fontSize: 11 }}
                  title={s.id}
                >
                  {s.id.slice(0, 12)}
                  {"\u2026"}
                </span>,
                <div className="flex flex-col" style={{ gap: 2, minWidth: 0 }}>
                  <span
                    className="font-mono"
                    style={{
                      color: "var(--text-primary)",
                      fontSize: 11,
                    }}
                  >
                    {browser} / {os}
                  </span>
                  {s.user_agent && (
                    <span
                      className="font-mono truncate"
                      style={{
                        color: "var(--text-faint)",
                        fontSize: 9.5,
                      }}
                      title={s.user_agent}
                    >
                      {s.user_agent.slice(0, 72)}
                      {s.user_agent.length > 72 ? "\u2026" : ""}
                    </span>
                  )}
                </div>,
                <span
                  className="font-mono"
                  style={{ color: "var(--text-muted)", fontSize: 11 }}
                >
                  {s.ip_address ?? "\u2014"}
                </span>,
                <span
                  className="font-mono tabular-nums"
                  style={{ color: "var(--text-muted)", fontSize: 10 }}
                >
                  {relativeTime(s.created_at)}
                </span>,
                isCurrent ? (
                  <MonoBadge tone="accent">current</MonoBadge>
                ) : (
                  <MonoBadge tone="ok">active</MonoBadge>
                ),
                <button
                  type="button"
                  onClick={() => handleRevoke(s.id)}
                  disabled={isCurrent || revokeMutation.isPending}
                  className="font-mono no-row-click"
                  style={{
                    ...ACTION_BUTTON_STYLE,
                    opacity: isCurrent || revokeMutation.isPending ? 0.35 : 1,
                    cursor:
                      isCurrent || revokeMutation.isPending
                        ? "not-allowed"
                        : "pointer",
                  }}
                  title={
                    isCurrent
                      ? "Cannot revoke current session"
                      : "Revoke this session"
                  }
                >
                  revoke
                </button>,
              ];
            }}
          />
        </WindowPanel>
      )}
    </div>
  );
}
