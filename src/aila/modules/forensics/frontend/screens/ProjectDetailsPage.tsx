import { useState } from "react";
import { useNavigate, useParams } from "react-router";

import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { PixelIcon } from "@/components/aila/PixelIcon";
import { SectionHeader } from "@/components/aila/mock";

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

const TABS: { id: TabId; label: string }[] = [
  { id: "network", label: "Network Analysis" },
  { id: "registry", label: "Registry" },
  { id: "timeline", label: "Timeline" },
  { id: "via", label: "V.I.A." },
  { id: "questions", label: "Questions & Answers" },
  { id: "writeups", label: "Write-Ups" },
];

const CHROME_BTN: React.CSSProperties = {
  height: 28,
  padding: "0 12px",
  fontSize: 10,
  letterSpacing: "0.08em",
  color: "var(--text-muted)",
  background: "transparent",
  border: "1px solid var(--border-soft)",
  borderRadius: 3,
  cursor: "pointer",
};

export function ProjectDetailsPage() {
  const { projectId } = useParams<{ projectId: string }>();
  const navigate = useNavigate();
  const { data: project, isLoading, isError } = useForensicsProject(
    projectId ?? "",
  );

  useUpdatePageHeader({
    title: project ? `${project.name} -- Details` : undefined,
    subtitle: undefined,
    status: null,
  });
  const [activeTab, setActiveTab] = useState<TabId>("network");

  if (!projectId) {
    return (
      <WindowPanel
        title="project details"
        tone="warn"
        status="forensics ; invalid project id"
      >
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--accent)" }}
        >
          Invalid project ID.
        </p>
      </WindowPanel>
    );
  }

  if (isLoading) return <LoadingSkeleton size="lg" width="full" />;

  if (isError || !project) {
    return (
      <WindowPanel
        title="project details"
        tone="warn"
        status="forensics ; details unavailable"
      >
        <p
          className="font-mono"
          style={{ fontSize: 11, color: "var(--accent)" }}
        >
          Failed to load project details.
        </p>
      </WindowPanel>
    );
  }

  return (
    <div className="space-y-4">
      <SectionHeader
        icon={<PixelIcon name="folder" />}
        title={`${project.name.toLowerCase()} \u2014 details`}
        actions={
          <button
            type="button"
            onClick={() => navigate(`/forensics/projects/${projectId}`)}
            className="font-mono uppercase"
            style={CHROME_BTN}
          >
            {"\u2190"} back to dashboard
          </button>
        }
      />

      {/* Tab strip -- mock chip toggle. */}
      <div className="flex flex-wrap" style={{ gap: 6 }}>
        {TABS.map((tab) => {
          const active = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              className="font-mono uppercase"
              style={{
                height: 28,
                padding: "0 14px",
                fontSize: 10,
                letterSpacing: "0.08em",
                borderRadius: 3,
                color: active ? "var(--text-on-accent)" : "var(--text-muted)",
                background: active ? "var(--accent)" : "var(--surface-sunk)",
                border: `1px solid ${
                  active ? "var(--accent)" : "var(--border-soft)"
                }`,
                cursor: "pointer",
              }}
            >
              {tab.label}
            </button>
          );
        })}
      </div>

      <div>
        {activeTab === "network" && (
          <div className="space-y-4">
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
