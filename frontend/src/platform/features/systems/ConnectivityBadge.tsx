import { MonoBadge } from "@/components/aila/mock";
import type { ConnectivityStatus } from "./api";

/**
 * ConnectivityBadge -- SSH reachability status indicator (D-04).
 *
 * Pure component. No hooks, no queries. Consumes the status string already
 * present in the enriched system row data. Rebuilt to the mock language:
 * a MonoBadge chip whose tone maps to the connectivity state. No pulse --
 * pulse is reserved for security findings.
 */
export function ConnectivityBadge({ status }: { status: ConnectivityStatus | null }) {
  if (status === "reachable") {
    return <MonoBadge tone="ok">ONLINE</MonoBadge>;
  }
  if (status === "unreachable") {
    return <MonoBadge tone="critical">OFFLINE</MonoBadge>;
  }
  return <MonoBadge tone="muted">UNKNOWN</MonoBadge>;
}
