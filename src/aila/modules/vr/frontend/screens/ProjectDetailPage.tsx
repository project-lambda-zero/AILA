import { useState } from "react";
import { useParams } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { useVRFindings, useVRProject } from "../queries";
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
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      <AilaCard>
        <h3 className="text-sm font-semibold font-mono text-foreground mb-3">
          Project
        </h3>
        <dl className="space-y-2 text-sm">
          <div className="flex justify-between gap-4">
            <dt className="text-text-muted">Status</dt>
            <dd>
              <AilaBadge severity={projectStatusColor[project.status] ?? "info"} size="sm">
                {project.status}
              </AilaBadge>
            </dd>
          </div>
          <div className="flex justify-between gap-4">
            <dt className="text-text-muted">Input source</dt>
            <dd className="font-mono text-foreground">{project.input_source ?? "—"}</dd>
          </div>
          <div className="flex justify-between gap-4">
            <dt className="text-text-muted">Target format</dt>
            <dd className="font-mono text-foreground">{project.target_format ?? "—"}</dd>
          </div>
          <div className="flex justify-between gap-4">
            <dt className="text-text-muted">Target class</dt>
            <dd className="font-mono text-foreground">{project.target_class}</dd>
          </div>
          <div className="flex justify-between gap-4">
            <dt className="text-text-muted">Findings</dt>
            <dd className="font-mono text-foreground">{project.finding_count}</dd>
          </div>
          <div className="flex justify-between gap-4">
            <dt className="text-text-muted">Created</dt>
            <dd className="font-mono text-foreground">
              {formatDateTime(project.created_at)}
            </dd>
          </div>
        </dl>
      </AilaCard>

      <AilaCard>
        <h3 className="text-sm font-semibold font-mono text-foreground mb-3">
          Disclosure Obligations
        </h3>
        <p className="text-sm text-text-muted">
          Coordinated-disclosure checklist will appear here once the analysis
          produces findings (v0.2).
        </p>
      </AilaCard>

      <AilaCard className="md:col-span-2">
        <h3 className="text-sm font-semibold font-mono text-foreground mb-3">
          Budget
        </h3>
        <p className="text-sm text-text-muted">
          Token / runtime budget gauge will appear here while the agent runs (v0.2).
        </p>
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
          No findings yet. They will appear here as the agent surfaces them.
        </p>
      </AilaCard>
    );
  }
  return (
    <div className="space-y-2">
      {findings.map((f, i) => (
        <FindingRow key={f.id ?? `${i}`} finding={f} />
      ))}
    </div>
  );
}

function AgentLogTab() {
  return (
    <AilaCard>
      <p className="text-sm text-text-muted text-center py-6">
        Agent log will appear here during analysis.
      </p>
    </AilaCard>
  );
}

function AdvisoryTab() {
  return (
    <AilaCard>
      <p className="text-sm text-text-muted text-center py-6">
        Advisory will be generated after analysis completes.
      </p>
    </AilaCard>
  );
}

export function ProjectDetailPage() {
  const { projectId = "" } = useParams<{ projectId: string }>();
  const { data: project, isLoading, isError } = useVRProject(projectId);
  const [activeTab, setActiveTab] = useState<TabId>("overview");

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
        <AilaBadge severity="info" size="sm">
          {project.target_class}
        </AilaBadge>
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
      {activeTab === "agent" && <AgentLogTab />}
      {activeTab === "advisory" && <AdvisoryTab />}
    </div>
  );
}
