/**
 * InvestigationConnectedCard -- links every entity the investigation
 * summary references so operators can pivot without hunting through
 * cards.
 *
 * Purely derived from the wire payload:
 *   - target_id            -> Target detail
 *   - workspace_id         -> Workspaces list (no per-workspace route)
 *   - parent_investigation_id -> Investigation detail
 *   - primary_outcome_id   -> anchor into the outcomes card on this page
 *   - linked_finding_ids[] -> Finding detail (global)
 *   - linked_campaign_ids[] -> Fuzz Campaign detail
 *
 * Titles come from cheap already-cached queries (target map, workspace
 * map, parent single-fetch); when they haven't resolved yet the row
 * falls back to a short id + type badge so the pivot is always
 * clickable.
 */
import { useMemo } from "react";

import { AilaCard } from "@/components/aila/AilaCard";
import {
  ConnectedEntities,
  type ConnectedEntity,
} from "@/components/aila/ConnectedEntities";

import {
  useInvestigation,
  useTargetMap,
  useWorkspaceMap,
} from "../queries";
import type { VRInvestigationSummary } from "../types";

function shortId(id: string): string {
  return id.length > 12 ? `${id.slice(0, 8)}\u2026` : id;
}

export function InvestigationConnectedCard({
  investigation,
}: {
  investigation: VRInvestigationSummary;
}) {
  const targetMap = useTargetMap();
  const workspaceMap = useWorkspaceMap();
  // Parent lookup piggybacks on the same cache as the lineage panel
  // (queryKey ["vr","investigation",id]) so mounting both simultaneously
  // costs one HTTP request, not two.
  const parentQuery = useInvestigation(
    investigation.parent_investigation_id ?? "",
  );

  const entities = useMemo<ConnectedEntity[]>(() => {
    const rows: ConnectedEntity[] = [];

    if (investigation.target_id) {
      const t = targetMap.get(investigation.target_id);
      rows.push({
        id: investigation.target_id,
        type: "Target",
        title: t?.display_name ?? shortId(investigation.target_id),
        href: `/vr/targets/${investigation.target_id}`,
        severity: "info",
        meta: t?.kind ? t.kind.replace(/_/g, " ") : undefined,
      });
    }

    if (investigation.workspace_id) {
      const w = workspaceMap.get(investigation.workspace_id);
      rows.push({
        id: investigation.workspace_id,
        type: "Workspace",
        title: w?.name ?? shortId(investigation.workspace_id),
        // No per-workspace detail route in the VR module (routes.tsx
        // only registers the list); operator lands on the list scoped
        // by the workspace picker.
        href: "/vr/workspaces",
        severity: "neutral",
      });
    }

    if (investigation.parent_investigation_id) {
      const parent = parentQuery.data;
      rows.push({
        id: investigation.parent_investigation_id,
        type: "Parent Investigation",
        title:
          parent?.title ?? shortId(investigation.parent_investigation_id),
        href: `/vr/investigations/${investigation.parent_investigation_id}`,
        severity: "info",
        meta: parent?.kind,
      });
    }

    // Note: primary_outcome_id is intentionally not surfaced here --
    // the outcome hero card renders it directly on this same page, and
    // the ConnectedEntities component would treat a hash-only href as
    // external (opens in new tab). Deferring an in-page anchor pivot
    // to a future outcome-card id anchor if it lands.

    for (const findingId of investigation.linked_finding_ids ?? []) {
      rows.push({
        id: findingId,
        type: "Finding",
        title: shortId(findingId),
        href: `/vr/findings/${findingId}`,
        severity: "high",
      });
    }

    for (const campaignId of investigation.linked_campaign_ids ?? []) {
      rows.push({
        id: campaignId,
        type: "Fuzz Campaign",
        title: shortId(campaignId),
        href: `/vr/fuzz/campaigns/${campaignId}`,
        severity: "medium",
      });
    }

    return rows;
  }, [investigation, parentQuery.data, targetMap, workspaceMap]);

  if (entities.length === 0) return null;

  return (
    <AilaCard techBorder glow>
      <ConnectedEntities entities={entities} heading="Connected" />
    </AilaCard>
  );
}
