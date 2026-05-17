import type { RegisteredSystem, TargetClass } from "../types";
import { AilaBadge } from "@/components/aila/AilaBadge";

/**
 * Heuristic compatibility hint between a chosen workstation and a
 * target class (08_FRONTEND_UX.md §1.2). Renders a small badge:
 *
 *  - ok      — workstation looks compatible
 *  - warn    — likely but unconfirmed (e.g. wrong OS family)
 *  - error   — definitely incompatible (e.g. kernel target on
 *              non-Linux host)
 *
 * The badge is advisory only. The backend has the final say once the
 * analysis pipeline runs.
 */
type Verdict = "ok" | "warn" | "error";
type BadgeSeverity = "low" | "medium" | "high";

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

export function WorkstationCompatibilityBadge({
  system,
  kind,
}: {
  system: RegisteredSystem;
  kind: TargetClass;
}) {
  const { verdict, reason } = judge(system, kind);
  // Map verdict to AilaBadge severity tokens (the design system has
  // no "warning" — we use "medium" for caution, "high" for error,
  // "low" for ok).
  const severity: BadgeSeverity =
    verdict === "ok" ? "low" : verdict === "warn" ? "medium" : "high";
  return (
    <span
      className="inline-flex items-center gap-1"
      title={reason}
    >
      <AilaBadge severity={severity} size="sm">
        {verdict === "ok"
          ? "compatible"
          : verdict === "warn"
            ? "check"
            : "incompatible"}
      </AilaBadge>
    </span>
  );
}
