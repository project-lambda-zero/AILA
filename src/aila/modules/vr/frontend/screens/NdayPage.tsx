import { Link, useParams } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { NdayStageView, type StageData } from "../components/NdayStageView";
import {
  useTargetName,
  useVRFindings,
  useVRProject,
} from "../queries";
import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";

/** N-day Task View (08_FRONTEND_UX.md §1.11).
 *
 *  Dedicated 4-stage progression view for the n-day reproduction workflow.
 *  The stages are visible at all times so the operator sees the state
 *  machine, not a hidden one.
 *
 *  Backend: derived from project + findings data. Each stage's status is
 *  inferred from what exists on the finding:
 *
 *    Patch acquired   → project.cve_id present + project.patched_target_id present
 *    Root cause       → finding.root_cause present
 *    Trigger          → finding.poc?.code present
 *    Exploit          → finding.poc.crashes_vulnerable >= 4 */
export function NdayPage() {
  const { projectId = "" } = useParams<{
    projectId: string;
    cveId: string;
  }>();
  const { data: project, isLoading } = useVRProject(projectId);
  const { data: findingsResult } = useVRFindings(projectId);
  const targetName = useTargetName(project?.target_id);
  const patchedName = useTargetName(project?.patched_target_id);

  useUpdatePageHeader({
    title: 'N-day reproduction',
    subtitle: project ? (project.cve_id ? `${project.name} · ${project.cve_id}` : project.name) : undefined,
    status: null,
  });

  if (isLoading || !project) return <LoadingSkeleton size="lg" width="full" />;

  const findings = findingsResult?.data ?? [];
  const primaryFinding = findings[0] ?? null;

  const stages: StageData[] = [
    {
      id: "patch_acquired",
      title: "Patch acquired",
      description:
        "Vulnerable + patched binaries identified, BinDiff comparison drawn.",
      status:
        project.cve_id && project.patched_target_id
          ? "complete"
          : project.cve_id
            ? "in_progress"
            : "pending",
      evidence: (
        <dl className="text-xs grid grid-cols-2 gap-1 font-mono">
          <dt className="text-text-muted">CVE</dt>
          <dd className="text-foreground">{project.cve_id ?? "—"}</dd>
          <dt className="text-text-muted">Vulnerable target</dt>
          <dd className="text-foreground truncate">{targetName}</dd>
          <dt className="text-text-muted">Patched target</dt>
          <dd className="text-foreground truncate">
            {project.patched_target_id ? patchedName : "—"}
          </dd>
        </dl>
      ),
    },
    {
      id: "root_cause",
      title: "Root cause located",
      description:
        "LLM analysis: where the patch adds a check / what condition the pre-patch code missed.",
      status: primaryFinding?.root_cause
        ? "complete"
        : project.status === "analyzing"
          ? "in_progress"
          : "pending",
      evidence: primaryFinding?.root_cause ? (
        <div>
          <p className="text-xs text-foreground whitespace-pre-wrap line-clamp-6">
            {primaryFinding.root_cause}
          </p>
          {primaryFinding.vulnerable_function && (
            <p className="text-3xs text-text-muted mt-1 font-mono">
              Function: {primaryFinding.vulnerable_function}
            </p>
          )}
        </div>
      ) : null,
    },
    {
      id: "trigger",
      title: "Trigger crafted",
      description:
        "Minimal input that hits the pre-patch path. Reproduces the crash 5/5 on vulnerable, 0/1 on patched.",
      status: primaryFinding?.poc?.code
        ? primaryFinding.poc.crashes_vulnerable >= 4
          ? "complete"
          : "in_progress"
        : "pending",
      evidence: primaryFinding?.poc ? (
        <div className="text-xs space-y-1 font-mono">
          <p>
            <span className="text-text-muted">language:</span>{" "}
            <span className="text-foreground">{primaryFinding.poc.language}</span>
          </p>
          <p>
            <span className="text-text-muted">repro:</span>{" "}
            <span className="text-foreground">
              {primaryFinding.poc.crashes_vulnerable}/5 vulnerable,{" "}
              {primaryFinding.poc.crashes_patched}/1 patched
            </span>
          </p>
          {primaryFinding.id && (
            <Link
              to={`/vr/projects/${projectId}/findings/${primaryFinding.id}`}
              className="text-accent hover:underline"
            >
              View full PoC →
            </Link>
          )}
        </div>
      ) : null,
    },
    {
      id: "exploit",
      title: "Exploit demonstrated",
      description:
        "Reliability passes the threshold across runs. Mitigations defeated documented.",
      status:
        primaryFinding?.poc &&
        primaryFinding.poc.crashes_vulnerable >= 5 &&
        primaryFinding.poc.crashes_patched === 0
          ? "complete"
          : primaryFinding?.poc
            ? "in_progress"
            : "pending",
      evidence: primaryFinding?.advisory_id ? (
        <Link
          to={`/vr/disclosures/${primaryFinding.advisory_id}`}
          className="text-xs text-accent hover:underline"
        >
          View advisory →
        </Link>
      ) : null,
    },
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <Link
          to={`/vr/projects/${projectId}`}
          className="text-xs px-3 py-1.5 rounded bg-surface border border-border-default hover:bg-surface-hover"
        >
          ← project dashboard
        </Link>
      </div>

      <AilaCard className="border-dashed" techBorder glow><AilaBadge severity="info" size="sm">
        synthesised view
      </AilaBadge>
      <p className="text-3xs text-text-muted mt-1">
        Per §1.11: each stage state is inferred from project + finding data.
        Real stage tracking (rewind / per-stage operator notes / BinDiff
        score / commit hash) is backend pending.
      </p></AilaCard>

      <NdayStageView stages={stages} />
    </div>
  );
}
