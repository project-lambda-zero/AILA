import { AilaBadge } from "@/components/aila/AilaBadge";
import type { ConnectivityStatus } from "./api";

/**
 * ConnectivityBadge — SSH reachability status indicator (D-04).
 *
 * Pure component. No hooks, no queries. Takes the status string already
 * present in the enriched system row data.
 *
 * Renders a 6px colored dot preceding an AilaBadge label:
 * - reachable: mint green dot + info badge "ONLINE"
 * - unreachable: red dot + critical badge "OFFLINE" (no pulse — pulse reserved for security findings)
 * - unknown/null: gray dot + neutral badge "UNKNOWN"
 */
export function ConnectivityBadge({ status }: { status: ConnectivityStatus | null }) {
  if (status === "reachable") {
    return (
      <span className="inline-flex items-center gap-1.5">
        <span
          className="inline-block h-1.5 w-1.5 rounded-full flex-shrink-0"
          style={{ backgroundColor: "var(--color-connectivity-online, #97dbbe)" }}
          aria-hidden="true"
        />
        <AilaBadge severity="info" size="sm">ONLINE</AilaBadge>
      </span>
    );
  }

  if (status === "unreachable") {
    return (
      <span className="inline-flex items-center gap-1.5">
        <span
          className="inline-block h-1.5 w-1.5 rounded-full flex-shrink-0 bg-critical"
          aria-hidden="true"
        />
        <AilaBadge severity="critical" size="sm">OFFLINE</AilaBadge>
      </span>
    );
  }

  return (
    <span className="inline-flex items-center gap-1.5">
      <span
        className="inline-block h-1.5 w-1.5 rounded-full flex-shrink-0 bg-text-muted"
        aria-hidden="true"
      />
      <AilaBadge severity="neutral" size="sm">UNKNOWN</AilaBadge>
    </span>
  );
}
