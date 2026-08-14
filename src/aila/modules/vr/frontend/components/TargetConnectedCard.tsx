/**
 * TargetConnectedCard -- links every entity the target references,
 * plus the derived reverse relationships that are already fetched
 * elsewhere on the target page (investigations + projects rooted on
 * this target).
 *
 * Wire-native lineage on VRTargetSummary:
 *   - workspace_id
 * The task brief lists `patched_target_id` and `parent_target_id`;
 * neither is present on the current VRTargetSummary contract (they
 * live on VRProjectSummary, project -> patched_target_id). We surface
 * the projects side instead so the operator still gets a target ->
 * paired-target navigation via the projects list, and note the absence
 * inline for future backend work.
 *
 * Cross-links resolved client-side from cached list queries:
 *   - investigations where investigation.target_id === this
 *   - projects where project.target_id === this OR
 *     project.patched_target_id === this (patched-vs-vulnerable pairs)
 */
import { useMemo } from "react";

import { AilaCard } from "@/components/aila/AilaCard";
import {
  ConnectedEntities,
  type ConnectedEntity,
} from "@/components/aila/ConnectedEntities";

import {
  useInvestigationsForTarget,
  useVRProjects,
  useWorkspaceMap,
} from "../queries";
import type { VRTargetSummary } from "../types";

function shortId(id: string): string {
  return id.length > 12 ? `${id.slice(0, 8)}\u2026` : id;
}

const MAX_ROWS_PER_CATEGORY = 8;

export function TargetConnectedCard({ target }: { target: VRTargetSummary }) {
  const workspaceMap = useWorkspaceMap();
  const investigationsQuery = useInvestigationsForTarget(target.id);
  // useVRProjects is already used elsewhere in the module; results are
  // small (<= 20 default), safe to iterate for the reverse target_id +
  // patched_target_id lookup.
  const projectsQuery = useVRProjects(0, 100);

  const entities = useMemo<ConnectedEntity[]>(() => {
    const rows: ConnectedEntity[] = [];

    if (target.workspace_id) {
      const w = workspaceMap.get(target.workspace_id);
      rows.push({
        id: target.workspace_id,
        type: "Workspace",
        title: w?.name ?? shortId(target.workspace_id),
        href: "/vr/workspaces",
        severity: "neutral",
      });
    }

    const projects = projectsQuery.data?.data ?? [];
    let projectShown = 0;
    for (const p of projects) {
      if (projectShown >= MAX_ROWS_PER_CATEGORY) break;
      const linkType =
        p.target_id === target.id
          ? "Project (vulnerable)"
          : p.patched_target_id === target.id
            ? "Project (patched pair)"
            : null;
      if (!linkType) continue;
      rows.push({
        id: p.id,
        type: linkType,
        title: p.name || shortId(p.id),
        href: `/vr/projects/${p.id}`,
        severity: linkType.includes("patched") ? "low" : "info",
        meta:
          typeof p.finding_count === "number"
            ? `${p.finding_count} finding${p.finding_count === 1 ? "" : "s"}`
            : undefined,
      });
      projectShown += 1;
    }

    // Reverse target lookup: any project whose patched_target_id points
    // at THIS target implies the operator is looking at the patched
    // side; add the reverse "vulnerable target" pointer so the pair is
    // navigable both directions.
    const patchedFrom = projects
      .filter((p) => p.patched_target_id === target.id && p.target_id)
      .map((p) => p.target_id)
      .filter((id, i, arr) => id && arr.indexOf(id) === i)
      .slice(0, MAX_ROWS_PER_CATEGORY);
    for (const pairedTargetId of patchedFrom) {
      if (!pairedTargetId) continue;
      rows.push({
        id: pairedTargetId,
        type: "Vulnerable Target",
        title: shortId(pairedTargetId),
        href: `/vr/targets/${pairedTargetId}`,
        severity: "high",
        meta: "paired via project.patched_target_id",
      });
    }

    const investigations = investigationsQuery.data?.data ?? [];
    let invShown = 0;
    for (const inv of investigations) {
      if (invShown >= MAX_ROWS_PER_CATEGORY) break;
      rows.push({
        id: inv.id,
        type: "Investigation",
        title: inv.title || shortId(inv.id),
        href: `/vr/investigations/${inv.id}`,
        severity: inv.status === "failed" ? "critical" : "info",
        meta: `${inv.kind} · ${inv.status}`,
      });
      invShown += 1;
    }
    if (investigations.length > MAX_ROWS_PER_CATEGORY) {
      rows.push({
        id: `${target.id}-more-investigations`,
        type: "More",
        title: `+${investigations.length - MAX_ROWS_PER_CATEGORY} more investigations`,
        href: `/vr/investigations?target=${target.id}`,
        severity: "neutral",
      });
    }

    return rows;
  }, [target, workspaceMap, projectsQuery.data, investigationsQuery.data]);

  if (entities.length === 0) return null;

  return (
    <AilaCard techBorder glow>
      <ConnectedEntities entities={entities} heading="Connected" />
    </AilaCard>
  );
}
