import { useState } from "react";
import { useNavigate, useParams } from "react-router";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";

import { CarvedFilesPanel } from "../components/CarvedFilesPanel";
import { NetworkAnalysisPanel } from "../components/NetworkAnalysisPanel";
import { QuestionsTable } from "../components/QuestionsTable";
import { RegistryViewer } from "../components/RegistryViewer";
import { TimelineViewer } from "../components/TimelineViewer";
import { VIATable } from "../components/VIATable";
import { WriteUpViewer } from "../components/WriteUpViewer";
import { useForensicsProject } from "../queries";
import { useUpdatePageHeader } from "@/components/aila/PageHeaderContext";

type TabId = "network" | "registry" | "timeline" | "via" | "questions" | "writeups";

const tabs: { id: TabId; label: string }[] = [
  { id: "network", label: "Network Analysis" },
  { id: "registry", label: "Registry" },
  { id: "timeline", label: "Timeline" },
  { id: "via", label: "V.I.A." },
  { id: "questions", label: "Questions & Answers" },
  { id: "writeups", label: "Write-Ups" },
];

export function ProjectDetailsPage() {
  const { projectId } = useParams<{ projectId: string }>();
  const navigate = useNavigate();
  const { data: project, isLoading, isError } = useForensicsProject(projectId ?? "");

  useUpdatePageHeader({
    title: project ? `${project.name} -- Details` : undefined,
    subtitle: undefined,
    status: null,
  });
  const [activeTab, setActiveTab] = useState<TabId>("network");

  if (!projectId) {
    return (
      <WindowPanel title="project details" tone="warn" status="forensics ; invalid project id">
        <p className="text-sm text-critical">Invalid project ID.</p>
      </WindowPanel>
    );
  }

  if (isLoading) return <LoadingSkeleton size="lg" width="full" />;

  if (isError || !project) {
    return (
      <WindowPanel title="project details" tone="warn" status="forensics ; details unavailable">
        <p className="text-sm text-critical">Failed to load project details.</p>
      </WindowPanel>
    );
  }

  return (
    <div className="space-y-4 bg-surface text-foreground p-4 rounded-md border border-border">
      <div className="flex items-center justify-between">
        <button
          type="button"
          onClick={() => navigate(`/forensics/projects/${projectId}`)}
          className="px-4 py-2 font-mono text-xs uppercase tracking-cyber-sm rounded-[3px] border border-border text-foreground hover:bg-elevated hover:border-border-hover transition-colors"
        >
          Back to Dashboard
        </button>
      </div>

      <div className="flex flex-wrap gap-1 border-b border-border pb-0">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2 font-mono text-xs uppercase tracking-cyber-sm rounded-t-[4px] transition-colors ${
              activeTab === tab.id
                ? "bg-surface border border-b-0 border-border text-foreground"
                : "text-text-muted hover:text-foreground hover:bg-elevated"
            }`}
            style={activeTab === tab.id ? { boxShadow: "inset 0 2px 0 var(--color-accent)" } : undefined}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div className="pt-2">
        {activeTab === "network" && (
          <div className="space-y-6">
            <NetworkAnalysisPanel projectId={projectId} />
            <CarvedFilesPanel projectId={projectId} />
          </div>
        )}
        {activeTab === "registry" && <RegistryViewer projectId={projectId} />}
        {activeTab === "timeline" && <TimelineViewer projectId={projectId} />}
        {activeTab === "via" && <VIATable projectId={projectId} />}
        {activeTab === "questions" && <QuestionsTable projectId={projectId} />}
        {activeTab === "writeups" && <WriteUpViewer projectId={projectId} />}
      </div>
    </div>
  );
}
