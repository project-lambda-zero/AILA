import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Monitor } from "@phosphor-icons/react/dist/csr/Monitor";
import { Globe } from "@phosphor-icons/react/dist/csr/Globe";
import { Clock } from "@phosphor-icons/react/dist/csr/Clock";
import { ShieldWarning } from "@phosphor-icons/react/dist/csr/ShieldWarning";

import { fetchSessions, revokeSession, type SessionRecord } from "./api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/aila/EmptyState";
import { LoadingSkeletonGroup } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";

// ---------------------------------------------------------------------------
// User-agent parsing
// ---------------------------------------------------------------------------

function parseBrowser(userAgent: string | null): string {
  if (!userAgent) return "Unknown Browser";
  if (/Firefox\//i.test(userAgent)) return "Firefox";
  if (/Edg\//i.test(userAgent)) return "Edge";
  if (/Chrome\//i.test(userAgent)) return "Chrome";
  if (/Safari\//i.test(userAgent)) return "Safari";
  if (/Opera|OPR\//i.test(userAgent)) return "Opera";
  return "Unknown Browser";
}

function parseOS(userAgent: string | null): string {
  if (!userAgent) return "Unknown OS";
  if (/Windows NT/i.test(userAgent)) return "Windows";
  if (/Mac OS X/i.test(userAgent)) return "macOS";
  if (/Linux/i.test(userAgent)) return "Linux";
  if (/Android/i.test(userAgent)) return "Android";
  if (/iPhone|iPad/i.test(userAgent)) return "iOS";
  return "Unknown OS";
}

function formatDeviceLabel(userAgent: string | null): string {
  if (!userAgent) return "Unknown device";
  return `${parseBrowser(userAgent)} on ${parseOS(userAgent)}`;
}

// ---------------------------------------------------------------------------
// Relative time
// ---------------------------------------------------------------------------

function relativeTime(isoString: string | null): string {
  if (!isoString) return "Unknown";
  const now = Date.now();
  const then = new Date(isoString).getTime();
  const diffMs = now - then;
  const diffSec = Math.floor(diffMs / 1000);
  if (diffSec < 60) return "Just now";
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin} minute${diffMin !== 1 ? "s" : ""} ago`;
  const diffHour = Math.floor(diffMin / 60);
  if (diffHour < 24) return `${diffHour} hour${diffHour !== 1 ? "s" : ""} ago`;
  const diffDay = Math.floor(diffHour / 24);
  return `${diffDay} day${diffDay !== 1 ? "s" : ""} ago`;
}

// ---------------------------------------------------------------------------
// Session row
// ---------------------------------------------------------------------------

interface SessionRowProps {
  session: SessionRecord;
  isCurrent: boolean;
  onRevoke: (id: string) => void;
  isRevoking: boolean;
}

function SessionRow({ session, isCurrent, onRevoke, isRevoking }: SessionRowProps) {
  const deviceLabel = formatDeviceLabel(session.user_agent);
  const ipLabel = session.ip_address ?? "Unknown";

  return (
    <tr className="border-b border-border last:border-0">
      {/* Device / Browser */}
      <td className="px-4 py-3">
        <div className="flex items-center gap-2">
          <Monitor size={16} className="text-text-muted shrink-0" />
          <div>
            <p className="text-sm font-medium text-foreground">{deviceLabel}</p>
            {session.user_agent && (
              <p
                className="text-xs text-text-muted truncate max-w-xs"
                title={session.user_agent}
              >
                {session.user_agent.slice(0, 60)}
                {session.user_agent.length > 60 ? "…" : ""}
              </p>
            )}
          </div>
        </div>
      </td>

      {/* IP Address */}
      <td className="px-4 py-3">
        <div className="flex items-center gap-2 text-sm text-foreground">
          <Globe size={14} className="text-text-muted shrink-0" />
          {ipLabel}
        </div>
      </td>

      {/* Last Active */}
      <td className="px-4 py-3">
        <div className="flex items-center gap-2 text-sm text-text-muted">
          <Clock size={14} className="shrink-0" />
          {relativeTime(session.created_at)}
        </div>
      </td>

      {/* Status */}
      <td className="px-4 py-3">
        {isCurrent ? (
          <Badge className="bg-accent/15 text-accent border border-accent/40 font-mono text-xs">
            Current Session
          </Badge>
        ) : (
          <Badge variant="outline" className="text-xs font-mono">
            Active
          </Badge>
        )}
      </td>

      {/* Actions */}
      <td className="px-4 py-3 text-right">
        <Button
          variant="outline"
          size="sm"
          onClick={() => onRevoke(session.id)}
          disabled={isCurrent || isRevoking}
          className="text-destructive hover:text-destructive border-destructive/30 hover:bg-destructive/10 disabled:opacity-40"
          title={isCurrent ? "Cannot revoke current session" : "Revoke this session"}
        >
          Revoke
        </Button>
      </td>
    </tr>
  );
}

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
          return new Date(s.created_at) > new Date(latest.created_at) ? s : latest;
        }).id
      : null;

  function handleRevoke(sessionId: string) {
    if (!window.confirm("Revoke this session? The device will be signed out.")) {
      return;
    }
    revokeMutation.mutate(sessionId);
  }

  return (
    <div className="space-y-6">
      {/* Page header */}

      {/* Error state */}
      {sessionsQuery.isError && (
        <div className="flex items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
          <ShieldWarning size={16} className="shrink-0" />
          Failed to load sessions. Please refresh the page.
        </div>
      )}

      {/* Loading state -- content-shaped skeleton mirrors the sessions table rows */}
      {sessionsQuery.isLoading && (
        <WindowPanel
          title="Active Sessions"
          status="LOADING"
          tone="muted"
          aria-label="Loading sessions"
          aria-busy="true"
        >
          <LoadingSkeletonGroup lines={4} />
        </WindowPanel>
      )}

      {/* Revoke error */}
      {revokeMutation.isError && (
        <div className="flex items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
          <ShieldWarning size={16} className="shrink-0" />
          Failed to revoke session. Please try again.
        </div>
      )}

      {/* Sessions table */}
      {!sessionsQuery.isLoading && (
        <WindowPanel
          title="Active Sessions"
          status={sessions.length > 0 ? `${sessions.length} ACTIVE` : undefined}
          tone="muted"
          flush
        >
          {sessions.length === 0 ? (
            <EmptyState
              icon={<Monitor className="h-10 w-10" />}
              title="No active sessions"
              description="Your account has no active browser sessions. Sign in from another device to see it listed here."
            />
          ) : (
            <table aria-label="Active sessions" className="w-full text-left border-collapse [&_th]:border [&_th]:border-border [&_td]:border [&_td]:border-border">
              <thead>
                <tr className="border-b border-border bg-elevated">
                  <th className="px-4 py-3 font-mono text-xs font-medium text-text-muted uppercase tracking-wider">
                    Device / Browser
                  </th>
                  <th className="px-4 py-3 font-mono text-xs font-medium text-text-muted uppercase tracking-wider">
                    IP Address
                  </th>
                  <th className="px-4 py-3 font-mono text-xs font-medium text-text-muted uppercase tracking-wider">
                    Last Active
                  </th>
                  <th className="px-4 py-3 font-mono text-xs font-medium text-text-muted uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-4 py-3 font-mono text-xs font-medium text-text-muted uppercase tracking-wider text-right">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody>
                {sessions.map((session) => (
                  <SessionRow
                    key={session.id}
                    session={session}
                    isCurrent={session.id === currentSessionId}
                    onRevoke={handleRevoke}
                    isRevoking={revokeMutation.isPending}
                  />
                ))}
              </tbody>
            </table>
          )}
        </WindowPanel>
      )}
    </div>
  );
}
