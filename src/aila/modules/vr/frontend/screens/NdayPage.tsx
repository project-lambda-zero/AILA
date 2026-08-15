import type { CSSProperties } from "react";
import { Link, useParams } from "react-router";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { MonoBadge, SectionHeader } from "@/components/aila/mock";
import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";

import { NdayStageView, type StageData } from "../components/NdayStageView";
import {
  useTargetName,
  useVRFindings,
  useVRProject,
} from "../queries";

/** N-day Task View (08_FRONTEND_UX.md §1.11).
 *
 *  Dedicated 4-stage progression view for the n-day reproduction workflow.
 *  The stages are visible at all times so the operator sees the state
 *  machine, not a hidden one.
 *
 *  Backend: derived from project + findings data. Each stage's status is
 *  inferred from what exists on the finding:
 *
 *    Patch acquired   : project.cve_id present + project.patched_target_id present
 *    Root cause       : finding.root_cause present
 *    Trigger          : finding.poc?.code present
 *    Exploit          : finding.poc.crashes_vulnerable >= 4
 */

const BACK_LINK: CSSProperties = {
  height: 28,
  padding: "0 12px",
  fontSize: 10,
  letterSpacing: "0.08em",
  background: "var(--surface-sunk)",
  border: "1px solid var(--border-soft)",
  color: "var(--text-primary)",
  borderRadius: 3,
  cursor: "pointer",
  fontFamily: "var(--font-mono)",
  textTransform: "uppercase",
  display: "inline-flex",
  alignItems: "center",
  gap: 6,
  textDecoration: "none",
};

const DL: CSSProperties = {
  display: "grid",
  gridTemplateColumns: "auto 1fr",
  columnGap: 12,
  rowGap: 3,
  margin: 0,
  fontFamily: "var(--font-mono)",
  fontSize: 10.5,
};

const DT: CSSProperties = {
  fontSize: 9,
  letterSpacing: "0.14em",
  color: "var(--text-faint)",
  textTransform: "uppercase",
  alignSelf: "center",
};

const DD: CSSProperties = {
  color: "var(--text-primary)",
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
  margin: 0,
};

const EVIDENCE_LINK: CSSProperties = {
  color: "var(--accent)",
  fontFamily: "var(--font-mono)",
  fontSize: 10.5,
  textDecoration: "none",
  letterSpacing: "0.04em",
};

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
    title: "N-day reproduction",
    subtitle: project
      ? project.cve_id
        ? `${project.name} \u00b7 ${project.cve_id}`
        : project.name
      : undefined,
    status: null,
  });

  if (isLoading || !project) {
    return <LoadingSkeleton size="lg" width="full" />;
  }

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
        <dl style={DL}>
          <dt style={DT}>cve</dt>
          <dd style={DD}>{project.cve_id ?? "\u2014"}</dd>
          <dt style={DT}>vulnerable</dt>
          <dd style={DD}>{targetName}</dd>
          <dt style={DT}>patched</dt>
          <dd style={DD}>
            {project.patched_target_id ? patchedName : "\u2014"}
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
          <p
            className="font-mono"
            style={{
              fontSize: 11,
              lineHeight: 1.5,
              color: "var(--text-primary)",
              whiteSpace: "pre-wrap",
              display: "-webkit-box",
              WebkitLineClamp: 6,
              WebkitBoxOrient: "vertical",
              overflow: "hidden",
              margin: 0,
            }}
          >
            {primaryFinding.root_cause}
          </p>
          {primaryFinding.vulnerable_function && (
            <p
              className="font-mono"
              style={{
                marginTop: 6,
                fontSize: 9.5,
                letterSpacing: "0.04em",
                color: "var(--text-muted)",
              }}
            >
              function: {primaryFinding.vulnerable_function}
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
        <div
          className="font-mono"
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 4,
            fontSize: 10.5,
          }}
        >
          <div>
            <span style={{ color: "var(--text-faint)" }}>language: </span>
            <span style={{ color: "var(--text-primary)" }}>
              {primaryFinding.poc.language}
            </span>
          </div>
          <div>
            <span style={{ color: "var(--text-faint)" }}>repro: </span>
            <span style={{ color: "var(--text-primary)" }}>
              {primaryFinding.poc.crashes_vulnerable}/5 vulnerable,{" "}
              {primaryFinding.poc.crashes_patched}/1 patched
            </span>
          </div>
          {primaryFinding.id && (
            <Link
              to={`/vr/projects/${projectId}/findings/${primaryFinding.id}`}
              style={EVIDENCE_LINK}
            >
              {"view full poc \u2192"}
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
          style={EVIDENCE_LINK}
        >
          {"view advisory \u2192"}
        </Link>
      ) : null,
    },
  ];

  const headerActions = (
    <Link to={`/vr/projects/${projectId}`} style={BACK_LINK}>
      {"\u2190 project dashboard"}
    </Link>
  );

  return (
    <div className="flex flex-col" style={{ gap: 14 }}>
      <SectionHeader
        icon="\u25c8"
        title="n-day reproduction"
        actions={headerActions}
      />

      <WindowPanel title="scope" tone="muted">
        <div className="flex items-start" style={{ gap: 10 }}>
          <MonoBadge tone="info">synthesised view</MonoBadge>
          <p
            className="font-mono"
            style={{
              fontSize: 10.5,
              lineHeight: 1.5,
              color: "var(--text-muted)",
              letterSpacing: "0.02em",
              margin: 0,
            }}
          >
            per §1.11: each stage state is inferred from project + finding
            data. real stage tracking (rewind / per-stage operator notes /
            bindiff score / commit hash) is backend pending.
          </p>
        </div>
      </WindowPanel>

      <NdayStageView stages={stages} />
    </div>
  );
}
