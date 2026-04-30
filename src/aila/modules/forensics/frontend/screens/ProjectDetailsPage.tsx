import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";

import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { CarvedFilesPanel } from "../components/CarvedFilesPanel";
import { NetworkAnalysisPanel } from "../components/NetworkAnalysisPanel";
import { QuestionsTable } from "../components/QuestionsTable";
import { RegistryViewer } from "../components/RegistryViewer";
import { TimelineViewer } from "../components/TimelineViewer";
import { VIATable } from "../components/VIATable";
import { WriteUpViewer } from "../components/WriteUpViewer";
import { useForensicsProject } from "../queries";

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
  const [activeTab, setActiveTab] = useState<TabId>("network");

  if (!projectId) {
    return (
      <AilaCard className="border-border-danger">
        <p className="text-sm text-text-danger">Invalid project ID.</p>
      </AilaCard>
    );
  }

  if (isLoading) return <LoadingSkeleton size="lg" width="full" />;

  if (isError || !project) {
    return (
      <AilaCard className="border-border-danger">
        <p className="text-sm text-text-danger">Failed to load project details.</p>
      </AilaCard>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold font-mono text-foreground">
            {project.name} — Details
          </h1>
          <p className="text-sm text-text-muted mt-1">
            Detailed analysis results and investigation outputs.
          </p>
        </div>
        <button
          type="button"
          onClick={() => navigate(`/forensics/projects/${projectId}`)}
          className="px-4 py-2 text-sm rounded-md border border-border text-foreground hover:bg-surface-secondary"
        >
          Back to Dashboard
        </button>
      </div>

      <div className="flex gap-1 border-b border-border pb-0">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2 text-sm font-medium rounded-t-md transition-colors ${
              activeTab === tab.id
                ? "bg-surface border border-b-0 border-border text-foreground"
                : "text-text-muted hover:text-foreground hover:bg-surface-secondary"
            }`}
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
