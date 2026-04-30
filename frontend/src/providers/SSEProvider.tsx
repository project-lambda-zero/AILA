/**
 * SSEProvider — global SSE connection for authenticated users.
 *
 * Mounts one ``useSSE`` connection to ``/events/stream`` for the lifetime of
 * the authenticated session. All surfaces share this single connection rather
 * than opening per-component streams.
 *
 * On each inbound event the provider:
 *   1. Calls ``queryClient.invalidateQueries`` for the affected query keys.
 *   2. Shows a sonner toast appropriate to the event type and severity.
 *
 * Exposes ``useSSEStatus()`` so UI components can render a connection indicator.
 *
 * Per D-02, D-09, D-10, D-11, D-14 (146-CONTEXT).
 */
import * as React from "react";
import { useCallback } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { useAuthStore } from "@platform/auth/useAuthStore";
import { useSSE, type SSEConnectionStatus, type SSEEvent } from "@/hooks/useSSE";

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

interface SSEContextValue {
  status: SSEConnectionStatus;
}

const SSEContext = React.createContext<SSEContextValue>({ status: "disconnected" });

/** Returns the current SSE connection status for the global platform stream. */
export function useSSEStatus(): SSEConnectionStatus {
  return React.useContext(SSEContext).status;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function asRecord(data: unknown): Record<string, unknown> | null {
  if (data !== null && typeof data === "object" && !Array.isArray(data)) {
    return data as Record<string, unknown>;
  }
  return null;
}

function isCriticalFinding(data: unknown): boolean {
  const d = asRecord(data);
  return d !== null && (d.criticality === "CRITICAL" || Number(d.score ?? 0) >= 9.0);
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export function SSEProvider({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const queryClient = useQueryClient();
  const [status, setStatus] = React.useState<SSEConnectionStatus>("disconnected");

  const handleEvent = useCallback(
    (event: SSEEvent) => {
      switch (event.type) {
        // ------------------------------------------------------------------ //
        // notification — a new NotificationRecord was persisted for the user   //
        // ------------------------------------------------------------------ //
        case "notification": {
          void queryClient.invalidateQueries({ queryKey: ["notifications"] });
          const d = asRecord(event.data);
          if (d) {
            const category = String(d.category ?? "info");
            const title = String(d.title ?? "New notification");
            const body = typeof d.body === "string" ? d.body : undefined;
            if (category === "critical") {
              toast.error(title, { description: body, duration: 10_000 });
            } else if (category === "warning") {
              toast.warning(title, { description: body, duration: 8_000 });
            } else {
              toast.info(title, { description: body, duration: 5_000 });
            }
          }
          break;
        }

        // ------------------------------------------------------------------ //
        // scan_complete — a task finished (done / failed / cancelled)          //
        // ------------------------------------------------------------------ //
        case "scan_complete": {
          void queryClient.invalidateQueries({ queryKey: ["dashboard", "stats"] });
          // Matches ["platform", "tasks", ...] via prefix invalidation
          void queryClient.invalidateQueries({ queryKey: ["platform", "tasks"] });
          void queryClient.invalidateQueries({ queryKey: ["notifications"] });
          const d = asRecord(event.data);
          const scanStatus = d ? String(d.status ?? "done") : "done";
          if (scanStatus === "done") {
            toast.success("Scan complete", {
              description: "Vulnerability scan finished successfully.",
              duration: 5_000,
            });
          } else if (scanStatus === "failed") {
            toast.error("Scan failed", {
              description: "Vulnerability scan encountered an error.",
              duration: 8_000,
            });
          } else if (scanStatus === "cancelled") {
            toast.info("Scan cancelled", {
              description: "Vulnerability scan was cancelled.",
              duration: 4_000,
            });
          }
          break;
        }

        // ------------------------------------------------------------------ //
        // finding_arrived — new finding upserted (critical only triggers toast) //
        // ------------------------------------------------------------------ //
        case "finding_arrived": {
          // Matches ["platform", "findings-facets"] and ["platform", "system-findings", ...]
          void queryClient.invalidateQueries({ queryKey: ["platform", "findings-facets"] });
          void queryClient.invalidateQueries({ queryKey: ["platform", "system-findings"] });
          void queryClient.invalidateQueries({ queryKey: ["platform", "dashboard-trend"] });
          void queryClient.invalidateQueries({ queryKey: ["dashboard", "stats"] });
          if (isCriticalFinding(event.data)) {
            const d = asRecord(event.data);
            toast.error("Critical finding detected", {
              description: `CVE: ${String(d?.cve_id ?? "unknown")} on ${String(d?.host ?? "unknown host")}`,
              duration: 10_000,
            });
          }
          break;
        }

        // ------------------------------------------------------------------ //
        // sbd_complete — Security by Design LLM analysis finished              //
        // ------------------------------------------------------------------ //
        case "sbd_complete": {
          void queryClient.invalidateQueries({ queryKey: ["sbd-nfr"] });
          void queryClient.invalidateQueries({ queryKey: ["notifications"] });
          toast.success("SbD resolution complete", {
            description: "Security by Design analysis finished.",
            duration: 5_000,
          });
          break;
        }

        // ------------------------------------------------------------------ //
        // system_unreachable — managed host went offline                       //
        // ------------------------------------------------------------------ //
        case "system_unreachable": {
          // Matches ["platform", "systems", ...] and ["platform", "topology"]
          void queryClient.invalidateQueries({ queryKey: ["platform", "systems"] });
          void queryClient.invalidateQueries({ queryKey: ["platform", "topology"] });
          const d = asRecord(event.data);
          const hostname = d ? String(d.hostname ?? "unknown") : "unknown";
          toast.warning("System unreachable", {
            description: `${hostname} is no longer responding.`,
            duration: 8_000,
          });
          break;
        }

        // ------------------------------------------------------------------ //
        // ping / unknown — ignore keepalives and unrecognised types            //
        // ------------------------------------------------------------------ //
        case "ping":
        default:
          break;
      }
    },
    [queryClient],
  );

  useSSE({
    url: "/events/stream",
    enabled: isAuthenticated,
    onEvent: handleEvent,
    onStatusChange: setStatus,
  });

  return (
    <SSEContext.Provider value={{ status }}>
      {children}
    </SSEContext.Provider>
  );
}
