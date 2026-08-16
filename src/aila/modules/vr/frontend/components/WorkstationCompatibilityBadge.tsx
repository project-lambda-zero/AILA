import type { RegisteredSystem, TargetClass } from "../types";
import { MonoBadge } from "@/components/aila/mock";

/**
 * Heuristic compatibility hint between a chosen workstation and a
 * target class (08_FRONTEND_UX.md §1.2). Renders a small MonoBadge:
 *
 *  - ok      -- workstation looks compatible
 *  - warn    -- likely but unconfirmed (e.g. wrong OS family)
 *  - error   -- definitely incompatible (e.g. kernel target on
 *              non-Linux host)
 *
 * The badge is advisory only. The backend has the final say once the
 * analysis pipeline runs.
 */
type Verdict = "ok" | "warn" | "error";

function judge(system: RegisteredSystem, kind: TargetClass): {
  verdict: Verdict;
  reason: string;
} {
  const host = (system.host ?? "").toLowerCase();
  const looksLinux =
    host.endsWith(".local")
    || host.includes("ubuntu")
    || host.includes("linux")
    || host.includes("wsl");
  if (kind === "kernel" || kind === "hypervisor") {
    if (!looksLinux) {
      return {
        verdict: "warn",
        reason: `${kind} targets typically need a Linux host`,
      };
    }
    return { verdict: "ok", reason: `Linux host, ${kind}-class compatible` };
  }
  if (kind === "android") {
    return {
      verdict: "warn",
      reason: "android needs an SDK + emulator on the host",
    };
  }
  if (kind === "ios") {
    return {
      verdict: "warn",
      reason: "iOS analysis typically needs macOS + Xcode",
    };
  }
  return { verdict: "ok", reason: "no known constraints for this class" };
}

// Verdict -> MonoBadge tone (see wave-2 brief severity mapping):
//   ok    -> ok       (status-ok, "compatible")
//   warn  -> medium   (status-info, "check")
//   error -> high     (status-warn, "incompatible")
const VERDICT_TONE: Record<Verdict, string> = {
  ok: "ok",
  warn: "medium",
  error: "high",
};

const VERDICT_LABEL: Record<Verdict, string> = {
  ok: "compatible",
  warn: "check",
  error: "incompatible",
};

export function WorkstationCompatibilityBadge({
  system,
  kind,
}: {
  system: RegisteredSystem;
  kind: TargetClass;
}) {
  const { verdict, reason } = judge(system, kind);
  return (
    <MonoBadge tone={VERDICT_TONE[verdict]} title={reason}>
      {VERDICT_LABEL[verdict]}
    </MonoBadge>
  );
}
