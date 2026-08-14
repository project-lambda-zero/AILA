/**
 * FindingConnectedCard -- links every entity referenced by a VRFinding.
 *
 * The finding wire shape is deliberately narrow (types.ts::VRFinding);
 * the only relational IDs currently on the contract are `project_id`
 * and `advisory_id`. The task brief lists `source_outcome_id`,
 * `source_investigation_id`, and `promoted_to_finding_id` -- none of
 * those live on the finding today. `promoted_to_finding_id` is the
 * REVERSE pointer from a fuzz crash to a finding (see
 * VRFuzzCrashSummary); resolving the crashes-linking-to-me set would
 * cost a target-wide crashes fetch on every finding page, so this card
 * leaves that pivot to the disclosure lookup and shows only relations
 * the finding itself carries.
 *
 * Additionally offers disclosure submissions filed for this finding
 * (via useDisclosures({ findingId })) since they're a cheap same-call
 * lookup and give operators the finding -> disclosure chain the brief
 * asks about.
 */
import { useMemo } from "react";

import { AilaCard } from "@/components/aila/AilaCard";
import {
  ConnectedEntities,
  type ConnectedEntity,
} from "@/components/aila/ConnectedEntities";

import { useDisclosures } from "../queries";
import type { VRFinding } from "../types";

function shortId(id: string | null | undefined): string {
  if (!id) return "";
  return id.length > 12 ? `${id.slice(0, 8)}\u2026` : id;
}

export function FindingConnectedCard({ finding }: { finding: VRFinding }) {
  const findingId = finding.id ?? "";
  // Cheap: backend indexes finding_id and returns only that finding's
  // submissions. Skipped entirely when the finding has no id (e.g. a
  // stub that hasn't been persisted yet).
  const disclosuresQuery = useDisclosures(
    findingId ? { findingId } : undefined,
  );

  const entities = useMemo<ConnectedEntity[]>(() => {
    const rows: ConnectedEntity[] = [];

    if (finding.project_id) {
      rows.push({
        id: finding.project_id,
        type: "Project",
        title: shortId(finding.project_id),
        href: `/vr/projects/${finding.project_id}`,
        severity: "info",
      });
    }

    if (finding.advisory_id) {
      rows.push({
        id: finding.advisory_id,
        type: "Advisory",
        title: shortId(finding.advisory_id),
        href: `/vr/disclosures/${finding.advisory_id}`,
        severity: "medium",
      });
    }

    if (finding.assigned_cve_id) {
      rows.push({
        id: finding.assigned_cve_id,
        type: "CVE",
        title: finding.assigned_cve_id,
        href: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(finding.assigned_cve_id)}`,
        severity: "high",
        meta: "NVD",
      });
    }

    const submissions = disclosuresQuery.data?.data ?? [];
    for (const s of submissions) {
      // Skip if it's the same row as advisory_id already surfaced.
      if (s.id === finding.advisory_id) continue;
      rows.push({
        id: s.id,
        type: "Disclosure",
        title: shortId(s.id),
        href: `/vr/disclosures/${s.id}`,
        severity: "medium",
        meta: s.status,
      });
    }

    return rows;
  }, [finding, disclosuresQuery.data]);

  if (entities.length === 0) return null;

  return (
    <AilaCard techBorder glow>
      <ConnectedEntities entities={entities} heading="Connected" />
    </AilaCard>
  );
}
