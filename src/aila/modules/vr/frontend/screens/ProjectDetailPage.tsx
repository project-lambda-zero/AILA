import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { DeleteButton } from "../components/DeleteButton";
import { WorkflowStepper } from "../components/WorkflowStepper";
import { useDeleteProject } from "../mutations";
import {
  useFuzzCampaigns,
  useInvestigations,
  useTargetName,
  useVRFindings,
  useVRProject,
} from "../queries";
import type {
  DisclosureStatus,
  VRFinding,
  VRProjectStatus,
} from "../types";

type TabId = "overview" | "findings" | "agent" | "advisory";

const TABS: ReadonlyArray<{ id: TabId; label: string }> = [
  { id: "overview", label: "Overview" },
  { id: "findings", label: "Findings" },
  { id: "agent", label: "Agent Log" },
  { id: "advisory", label: "Advisory" },
];

const projectStatusColor: Record<VRProjectStatus, "info" | "low" | "medium" | "high" | "critical"> = {
  created: "info",
  analyzing: "medium",
  completed: "low",
  failed: "critical",
  stalled: "high",
};

const disclosureStatusColor: Record<DisclosureStatus, "info" | "low" | "medium" | "high" | "critical"> = {
  undisclosed: "high",
  reported: "medium",
  acknowledged: "info",
  patch_pending: "info",
  patched: "low",
  public: "low",
};

function formatDateTime(value?: string | null): string {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function nvdHref(cveId: string): string {
  return `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`;
}

function FindingRow({ finding }: { finding: VRFinding }) {
  const [expanded, setExpanded] = useState(false);
  const findingId = finding.id ?? "(unsaved)";

  return (
    <div className="border border-border-default rounded-md">
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-surface transition-colors"
      >
        <div className="flex items-center gap-3">
          <span className="font-mono text-sm text-foreground">
            {finding.vulnerable_function || "(unknown function)"}
          </span>
          {finding.crash_type && (
            <AilaBadge severity="high" size="sm">
              {finding.crash_type}
            </AilaBadge>
          )}
          <AilaBadge
            severity={disclosureStatusColor[finding.disclosure_status] ?? "info"}
            size="sm"
          >
            {finding.disclosure_status}
          </AilaBadge>
        </div>
        <span className="text-xs text-text-muted font-mono">
          {expanded ? "−" : "+"}
        </span>
      </button>

      {expanded && (
        <div className="border-t border-border-default px-4 py-3 space-y-3">
          <div>
            <p className="text-xs uppercase tracking-wide text-text-muted">Finding ID</p>
            <p className="font-mono text-sm text-foreground">{findingId}</p>
          </div>
          <div>
            <p className="text-xs uppercase tracking-wide text-text-muted">Root Cause</p>
            <p className="text-sm text-foreground whitespace-pre-wrap">
              {finding.root_cause || "—"}
            </p>
          </div>
          {finding.assigned_cve_id && (
            <div>
              <p className="text-xs uppercase tracking-wide text-text-muted">Assigned CVE</p>
              <a
                href={nvdHref(finding.assigned_cve_id)}
                target="_blank"
                rel="noopener noreferrer"
                className="font-mono text-sm text-accent hover:underline"
              >
                {finding.assigned_cve_id}
              </a>
            </div>
          )}
          {finding.poc && (
            <div>
              <p className="text-xs uppercase tracking-wide text-text-muted">
                PoC ({finding.poc.language}) — vulnerable crashes:{" "}
                {finding.poc.crashes_vulnerable}/5, patched crashes:{" "}
                {finding.poc.crashes_patched}/1
              </p>
              <pre className="mt-1 p-3 rounded-md bg-surface border border-border-default font-mono text-xs text-foreground overflow-x-auto whitespace-pre">
                {finding.poc.code}
              </pre>
              {finding.poc.asan_report && (
                <pre className="mt-2 p-3 rounded-md bg-surface border border-border-default font-mono text-xs text-text-muted overflow-x-auto whitespace-pre">
                  {finding.poc.asan_report}
                </pre>
              )}
            </div>
          )}
          {finding.vendor_contact && (
            <div>
              <p className="text-xs uppercase tracking-wide text-text-muted">Vendor Contact</p>
              <p className="font-mono text-sm text-foreground">{finding.vendor_contact}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function OverviewTab({
  project,
}: {
  project: NonNullable<ReturnType<typeof useVRProject>["data"]>;
}) {
  const targetName = useTargetName(project.target_id);
  const patchedName = useTargetName(project.patched_target_id);
  // Investigations + campaigns scoped to this project's primary target.
  // Lightweight: filter client-side from the full list to avoid adding
  // a backend param.
  const { data: invsResult } = useInvestigations();
  const { data: fuzzResult } = useFuzzCampaigns({
    targetId: project.target_id ?? undefined,
  });
  const allInvs = invsResult?.data ?? [];
  const projInvs = allInvs.filter((i) => i.target_id === project.target_id);
  const activeInvs = projInvs.filter(
    (i) => i.status === "running" || i.status === "paused",
  );
  const fuzzCampaigns = fuzzResult?.data ?? [];
  const activeFuzz = fuzzCampaigns.filter(
    (c) => c.status === "running" || c.status === "paused",
  );

  return (
    <div className="space-y-4">
      {/* Workflow stepper */}
      <AilaCard>
        <WorkflowStepper
          flow="nday"
          currentState={
            project.status === "completed"
              ? "response_emit"
              : project.status === "failed"
                ? "research"
                : project.status === "analyzing"
                  ? "research"
                  : "setup"
          }
          failedAt={project.status === "failed" ? "research" : null}
        />
      </AilaCard>

      {/* Hub panels — matches 08_FRONTEND_UX.md §1.3 */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Targets panel */}
        <AilaCard className="lg:col-span-1">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-text-muted mb-2">
            Targets
          </h3>
          <ul className="space-y-1.5 text-sm">
            {project.target_id && (
              <li className="flex items-center justify-between gap-2 border border-border-default rounded px-2 py-1.5">
                <Link
                  to={`/vr/targets/${project.target_id}`}
                  className="font-mono text-foreground hover:underline truncate"
                >
                  {targetName}
                </Link>
                <AilaBadge severity="medium" size="sm">
                  primary
                </AilaBadge>
              </li>
            )}
            {project.patched_target_id && (
              <li className="flex items-center justify-between gap-2 border border-border-default rounded px-2 py-1.5">
                <Link
                  to={`/vr/targets/${project.patched_target_id}`}
                  className="font-mono text-foreground hover:underline truncate"
                >
                  {patchedName}
                </Link>
                <AilaBadge severity="low" size="sm">
                  patched
                </AilaBadge>
              </li>
            )}
            {!project.target_id && (
              <li className="text-xs text-text-muted">No targets.</li>
            )}
          </ul>
        </AilaCard>

        {/* Active investigations */}
        <AilaCard className="lg:col-span-1">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-text-muted mb-2">
            Investigations
          </h3>
          {projInvs.length === 0 ? (
            <p className="text-xs text-text-muted">
              No investigations on this target yet.
            </p>
          ) : (
            <ul className="space-y-1.5 text-xs">
              {projInvs.slice(0, 6).map((inv) => (
                <li
                  key={inv.id}
                  className="border border-border-default rounded px-2 py-1.5"
                >
                  <Link
                    to={`/vr/investigations/${inv.id}`}
                    className="font-mono text-foreground hover:underline truncate block"
                  >
                    {inv.title}
                  </Link>
                  <div className="flex items-center gap-1 mt-1 flex-wrap">
                    <AilaBadge
                      severity={
                        inv.status === "running"
                          ? "medium"
                          : inv.status === "completed"
                            ? "low"
                            : "info"
                      }
                      size="sm"
                    >
                      {inv.status}
                    </AilaBadge>
                    <span className="text-text-muted font-mono">
                      {inv.message_count}t · ${inv.cost_actual_usd.toFixed(2)}
                    </span>
                  </div>
                </li>
              ))}
            </ul>
          )}
          {activeInvs.length > 0 && (
            <p className="text-[10px] text-text-muted mt-2">
              {activeInvs.length} active
            </p>
          )}
        </AilaCard>

        {/* Findings summary */}
        <AilaCard className="lg:col-span-1">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-text-muted mb-2">
            Findings
          </h3>
          <p className="text-2xl font-bold font-mono text-foreground">
            {project.finding_count}
          </p>
          <p className="text-xs text-text-muted mt-1">
            See <strong>Findings</strong> tab for per-vuln detail.
          </p>
          {activeFuzz.length > 0 && (
            <div className="mt-3 pt-3 border-t border-border-default">
              <p className="text-xs text-text-muted">
                {activeFuzz.length} active fuzz campaign
                {activeFuzz.length === 1 ? "" : "s"}
              </p>
              {activeFuzz.slice(0, 3).map((c) => (
                <Link
                  key={c.id}
                  to={`/vr/fuzz/campaigns/${c.id}`}
                  className="text-xs font-mono text-foreground hover:underline block truncate mt-1"
                >
                  → {c.name}
                </Link>
              ))}
            </div>
          )}
        </AilaCard>
      </div>

      {/* Project metadata strip */}
      <AilaCard>
        <dl className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
          <div>
            <dt className="text-text-muted text-xs">Workspace</dt>
            <dd className="font-mono text-foreground truncate">
              {project.workspace_id ?? "—"}
            </dd>
          </div>
          <div>
            <dt className="text-text-muted text-xs">Created</dt>
            <dd className="font-mono text-foreground">
              {formatDateTime(project.created_at)}
            </dd>
          </div>
          <div>
            <dt className="text-text-muted text-xs">CVE</dt>
            <dd className="font-mono text-foreground">
              {project.cve_id ?? "—"}
            </dd>
          </div>
          <div>
            <dt className="text-text-muted text-xs">Status</dt>
            <dd>
              <AilaBadge
                severity={projectStatusColor[project.status] ?? "info"}
                size="sm"
              >
                {project.status}
              </AilaBadge>
            </dd>
          </div>
        </dl>
      </AilaCard>
    </div>
  );
}

function FindingsTab({ projectId }: { projectId: string }) {
  const { data: result, isLoading, isError } = useVRFindings(projectId);
  const findings = result?.data ?? [];

  if (isLoading) return <LoadingSkeleton size="lg" width="full" />;
  if (isError) {
    return (
      <AilaCard className="border-border-danger">
        <p className="text-sm text-text-danger">Failed to load findings.</p>
      </AilaCard>
    );
  }
  if (findings.length === 0) {
    return (
      <AilaCard>
        <p className="text-sm text-text-muted text-center py-6">
          No findings yet. They appear here once the engine completes a PoC.
        </p>
      </AilaCard>
    );
  }
  return (
    <div className="space-y-2">
      {findings.map((f) => (
        <FindingRow key={f.id ?? Math.random()} finding={f} />
      ))}
    </div>
  );
}

function AgentLogTab({
  project,
}: {
  project: NonNullable<ReturnType<typeof useVRProject>["data"]>;
}) {
  // The "agent log" for an n-day VR project lives across its
  // investigations. Link out to each — every investigation has its own
  // dedicated TurnCard stream (the Investigation Timeline page).
  const { data: invsResult, isLoading } = useInvestigations();
  if (isLoading) return <LoadingSkeleton size="lg" width="full" />;
  const projInvs = (invsResult?.data ?? []).filter(
    (i) => i.target_id === project.target_id,
  );
  if (projInvs.length === 0) {
    return (
      <AilaCard>
        <p className="text-sm text-text-muted text-center py-6">
          No investigations have been started for this project's target yet.
          Create one from the <Link to="/vr/investigations" className="text-accent hover:underline">Investigations</Link>{" "}
          page to drive the engine.
        </p>
      </AilaCard>
    );
  }
  return (
    <div className="space-y-2">
      <p className="text-xs text-text-muted px-1">
        The engine's reasoning is per-investigation. Open one to see its
        turn-by-turn timeline.
      </p>
      {projInvs.map((inv) => (
        <Link
          key={inv.id}
          to={`/vr/investigations/${inv.id}`}
          className="block border border-border-default rounded-md px-3 py-2 hover:bg-surface-hover transition-colors"
        >
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <span className="text-sm font-mono text-foreground truncate">
              {inv.title}
            </span>
            <div className="flex items-center gap-1.5 text-xs">
              <AilaBadge
                severity={
                  inv.status === "running"
                    ? "medium"
                    : inv.status === "completed"
                      ? "low"
                      : inv.status === "failed"
                        ? "critical"
                        : "info"
                }
                size="sm"
              >
                {inv.status}
              </AilaBadge>
              <span className="text-text-muted font-mono">
                {inv.message_count} turns · ${inv.cost_actual_usd.toFixed(2)}
              </span>
            </div>
          </div>
        </Link>
      ))}
    </div>
  );
}

function AdvisoryTab({
  project,
}: {
  project: NonNullable<ReturnType<typeof useVRProject>["data"]>;
}) {
  const { data: findingsResult, isLoading } = useVRFindings(project.id);
  if (isLoading) return <LoadingSkeleton size="lg" width="full" />;
  const findings = findingsResult?.data ?? [];

  if (findings.length === 0) {
    return (
      <AilaCard>
        <p className="text-sm text-text-muted text-center py-6">
          No findings to advise on yet. The engine produces an advisory as
          part of the PoC workflow once a finding reaches the advisory state.
        </p>
      </AilaCard>
    );
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-text-muted px-1">
        Per-finding disclosure state. Click <strong>Disclosures</strong> in
        the sidebar for full advisory editing surface.
      </p>
      {findings.map((f) => (
        <AilaCard key={f.id ?? Math.random()}>
          <div className="flex items-center justify-between gap-2 mb-1 flex-wrap">
            <h3 className="text-sm font-semibold text-foreground font-mono truncate">
              {f.vulnerable_function ?? "(unknown function)"}
            </h3>
            <AilaBadge
              severity={disclosureStatusColor[f.disclosure_status] ?? "info"}
              size="sm"
            >
              {f.disclosure_status}
            </AilaBadge>
          </div>
          {f.assigned_cve_id && (
            <p className="text-xs font-mono text-text-muted">
              CVE: {f.assigned_cve_id}
            </p>
          )}
          {f.root_cause && (
            <p className="text-xs text-foreground mt-2 whitespace-pre-wrap line-clamp-4">
              {f.root_cause}
            </p>
          )}
          {f.advisory_id && (
            <Link
              to={`/vr/disclosures`}
              className="text-xs text-accent hover:underline mt-2 inline-block"
            >
              Open in Disclosures →
            </Link>
          )}
        </AilaCard>
      ))}
    </div>
  );
}

export function ProjectDetailPage() {
  const { projectId = "" } = useParams<{ projectId: string }>();
  const { data: project, isLoading, isError } = useVRProject(projectId);
  const [activeTab, setActiveTab] = useState<TabId>("overview");
  const headerTargetName = useTargetName(project?.target_id);
  const deleteMut = useDeleteProject();
  const navigate = useNavigate();

  if (isLoading) {
    return <LoadingSkeleton size="lg" width="full" />;
  }
  if (isError || !project) {
    return (
      <AilaCard className="border-border-danger">
        <p className="text-sm text-text-danger">Failed to load VR project.</p>
      </AilaCard>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3 justify-between">
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="text-xl font-bold font-mono text-foreground">
            {project.name}
          </h1>
          {project.cve_id && (
            <a
              href={nvdHref(project.cve_id)}
              target="_blank"
              rel="noopener noreferrer"
              className="font-mono text-sm text-accent hover:underline"
            >
              {project.cve_id}
            </a>
          )}
          <AilaBadge severity={projectStatusColor[project.status] ?? "info"} size="sm">
            {project.status}
          </AilaBadge>
          {project.target_id && (
            <AilaBadge severity="info" size="sm">
              target: {headerTargetName}
            </AilaBadge>
          )}
        </div>
        <DeleteButton
          id={project.id}
          label={`project "${project.name}"`}
          mutation={deleteMut}
          onDeleted={() => navigate("/vr")}
        />
      </div>

      <div className="border-b border-border-default flex gap-1">
        {TABS.map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              className={
                "px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors " +
                (isActive
                  ? "border-accent text-foreground"
                  : "border-transparent text-text-muted hover:text-foreground")
              }
            >
              {tab.label}
            </button>
          );
        })}
      </div>

      {activeTab === "overview" && <OverviewTab project={project} />}
      {activeTab === "findings" && <FindingsTab projectId={projectId} />}
      {activeTab === "agent" && <AgentLogTab project={project} />}
      {activeTab === "advisory" && <AdvisoryTab project={project} />}
    </div>
  );
}
