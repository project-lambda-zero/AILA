import type { RailRow } from "../api/forensicsRail";

/** Rail row cap; the rail is a worklist, not a catalogue. */
export const RAIL_ROW_LIMIT = 40;

/** Whether a row's status counts as live work for the module's rail.
 * `analyzing` is a forensics project status (a pipeline is working on it),
 * while `created` is the initial malware investigation state. Neither status
 * is shared across modules. `ready` is idle in every module and stays hidden
 * unless pinned. */
function isActiveStatus(moduleId: string, status: string | undefined): boolean {
  const s = (status ?? "").toLowerCase();
  if (s === "running" || s === "active") return true;
  if (moduleId === "forensics" && s === "analyzing") return true;
  return moduleId === "malware" && s === "created";
}

/** Select the rail's rows: live work plus pinned/favorited rows, pinned first,
 * then by activity weight (branches, then messages), capped at RAIL_ROW_LIMIT.
 * Does not mutate `raw`. */
export function selectRailRows(
  raw: readonly RailRow[],
  pinnedIds: readonly string[],
  moduleId: string,
): RailRow[] {
  const score = (v: RailRow): number =>
    (v.branch_count ?? 0) * 1000 + (v.message_count ?? 0);
  const isPinned = (v: RailRow): boolean =>
    pinnedIds.includes(v.id) || Boolean(v.is_favorite);
  return raw
    .filter((v) => isActiveStatus(moduleId, v.status) || isPinned(v))
    .sort((a, b) => {
      const ap = isPinned(a) ? 1 : 0;
      const bp = isPinned(b) ? 1 : 0;
      if (ap !== bp) return bp - ap;
      return score(b) - score(a);
    })
    .slice(0, RAIL_ROW_LIMIT);
}
