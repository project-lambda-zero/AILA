/**
 * useVRListInvalidation -- additive live-refresh for VR list screens.
 *
 * Subscribes the caller to the shell's shared platform SSE stream
 * (``/events/stream`` via {@link useSSESubscribe}) and invalidates the
 * React Query keys that back the calling list screen whenever a
 * VR-origin lifecycle event lands. Non-matching events are a no-op --
 * the callback never invalidates on unrelated types.
 *
 * Design notes:
 *   * One subscription per mount. {@link useSSESubscribe} adds the
 *     listener on mount and removes it on unmount, so a screen never
 *     opens a second stream and never leaks a listener when the
 *     operator navigates away.
 *   * Additive. Existing ``refetchInterval`` / ``refetch()`` behaviour
 *     on each list's ``useQuery`` is untouched; SSE-driven invalidation
 *     just closes the gap between polls.
 *   * The shared stream carries generic types (``notification``,
 *     ``finding_arrived``, ``scan_complete``, ``system_unreachable``,
 *     ``ping``). We filter to VR-origin events via
 *     ``event.data.source_module === "vr"`` where available and by
 *     event-type shape where it isn't. If VR emits no matching event on
 *     a given code path, the list keeps polling on its existing
 *     interval -- the SSE handler simply doesn't fire.
 */

import { useCallback } from "react";

import { useQueryClient } from "@tanstack/react-query";

import type { SSEEvent } from "@/hooks/useSSE";
import { useSSESubscribe } from "@/providers/SSEProvider";

/** The list screens that opt into live invalidation. Add a new value
 *  here + a matching entry in {@link INVALIDATE_KEYS} to wire another
 *  screen. */
export type VRListKind =
  | "investigations"
  | "targets"
  | "findings"
  | "workspaces"
  | "fuzz-campaigns"
  | "disclosures"
  | "patterns";

/** React Query key prefixes invalidated for each kind. Every entry is
 *  passed to ``invalidateQueries({ queryKey })`` which does prefix
 *  matching -- so e.g. ``["vr", "investigations"]`` invalidates every
 *  paginated / filtered variant regardless of trailing offset/limit
 *  args. Ordering does not matter; duplicates are cheap. */
const INVALIDATE_KEYS: Record<VRListKind, readonly (readonly unknown[])[]> = {
  investigations: [
    ["vr", "investigations"],
    ["vr", "investigations-for-target"],
    ["vr", "investigation"],
  ],
  targets: [
    ["vr", "targets"],
    ["vr", "target"],
  ],
  findings: [
    ["vr", "all-findings"],
    ["vr", "findings"],
    ["vr", "finding-by-id"],
    ["vr", "finding"],
  ],
  workspaces: [["vr", "workspaces"]],
  "fuzz-campaigns": [
    ["vr", "fuzz-campaigns"],
    ["vr", "fuzz-campaign"],
  ],
  disclosures: [
    ["vr", "disclosures"],
    ["vr", "disclosure"],
  ],
  patterns: [
    ["vr", "patterns"],
    ["vr", "pattern"],
  ],
};

/** True when an inbound platform SSE frame is a VR-origin lifecycle
 *  signal that should invalidate the given list.
 *
 *  * ``finding_arrived`` -- fan-out to any finding-shaped list. The
 *    global findings screen is team-wide and cannot cheaply filter to
 *    VR-owned rows; over-invalidating a paginated list is a
 *    background-fetch cost, not a correctness issue.
 *  * ``scan_complete`` -- fires when a background task completes. We
 *    invalidate the entity lists whose row status could have changed
 *    (investigations, targets, fuzz campaigns) when the payload names
 *    ``source_module === "vr"`` -- or has no source tag, so an older
 *    emit site without the tag still refreshes.
 *  * ``notification`` -- generic operator notification. Only fires
 *    for the caller's list when the emitter set
 *    ``source_module === "vr"`` and the ``source_entity_type`` tag
 *    matches the list; a bare VR notification with no entity tag
 *    fans out to every list so nothing goes stale.
 *
 *  Every other event type (``ping``, ``system_unreachable``, unknown
 *  types) is a hard no-op. */
function eventMatchesKind(event: SSEEvent, kind: VRListKind): boolean {
  const data =
    event.data !== null && typeof event.data === "object" && !Array.isArray(event.data)
      ? (event.data as Record<string, unknown>)
      : null;
  const source = data ? String(data.source_module ?? "") : "";
  const type = event.type;

  if (type === "finding_arrived") {
    return kind === "findings";
  }

  if (type === "scan_complete") {
    if (source && source !== "vr") return false;
    return (
      kind === "investigations" ||
      kind === "targets" ||
      kind === "fuzz-campaigns"
    );
  }

  if (type === "notification") {
    if (source !== "vr") return false;
    const entityType = data ? String(data.source_entity_type ?? "") : "";
    if (!entityType) return true;
    const et = entityType.toLowerCase();
    switch (kind) {
      case "investigations":
        return et.includes("investigation");
      case "targets":
        return et.includes("target");
      case "findings":
        return et.includes("finding");
      case "workspaces":
        return et.includes("workspace");
      case "fuzz-campaigns":
        return et.includes("campaign") || et.includes("crash");
      case "disclosures":
        return et.includes("disclosure");
      case "patterns":
        return et.includes("pattern");
    }
  }

  return false;
}

/** Subscribe the current screen to the platform SSE fan-out and
 *  invalidate its list's query keys whenever a VR-origin event affects
 *  it. Safe to call at the top of any list screen; a single subscription
 *  is installed per mount and cleaned up on unmount. */
export function useVRListInvalidation(kind: VRListKind): void {
  const qc = useQueryClient();
  const listener = useCallback(
    (event: SSEEvent) => {
      if (!eventMatchesKind(event, kind)) return;
      for (const queryKey of INVALIDATE_KEYS[kind]) {
        void qc.invalidateQueries({ queryKey: queryKey as unknown[] });
      }
    },
    [qc, kind],
  );
  useSSESubscribe(listener);
}
