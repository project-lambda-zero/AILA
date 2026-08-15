import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { DataGrid, MonoBadge } from "@/components/aila/mock";

import { useProjectLeads } from "../queries";
import type { PromotedLead } from "../types";

function scoreTone(score: number): string {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  if (score >= 20) return "low";
  return "info";
}

export function VIATable({ projectId }: { projectId: string }) {
  const { data: leads, isLoading } = useProjectLeads(projectId, 100);

  if (isLoading) return <LoadingSkeleton size="lg" width="full" />;

  const items = leads ?? [];

  if (items.length === 0) {
    return (
      <WindowPanel
        title="v.i.a."
        tone="muted"
        status="forensics ; no artifacts identified"
      >
        <p
          className="font-mono"
          style={{
            fontSize: 11,
            color: "var(--text-muted)",
            padding: "24px 0",
            textAlign: "center",
          }}
        >
          No Very Important Artifacts identified yet.
        </p>
      </WindowPanel>
    );
  }

  return (
    <div aria-label="Verified-in-action rows">
      <DataGrid<PromotedLead>
        columns={[
          { label: "score", width: "80px" },
          { label: "family", width: "140px" },
          { label: "reason", width: "minmax(0, 2fr)" },
          { label: "question families", width: "minmax(0, 1fr)" },
        ]}
        rows={items}
        getKey={(l) => l.id}
        renderCells={(l) => [
          <MonoBadge key="s" tone={scoreTone(l.score)}>
            {l.score.toFixed(1)}
          </MonoBadge>,
          <span
            key="f"
            className="font-mono"
            style={{ fontSize: 10.5, color: "var(--text-primary)" }}
          >
            {l.artifact_family}
          </span>,
          <span
            key="r"
            className="font-mono"
            style={{
              fontSize: 10.5,
              color: "var(--text-primary)",
              display: "block",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
            title={l.reason}
          >
            {l.reason}
          </span>,
          <span key="qf" className="flex flex-wrap" style={{ gap: 4 }}>
            {l.question_families.map((qf) => (
              <MonoBadge key={qf} tone="muted">
                {qf}
              </MonoBadge>
            ))}
          </span>,
        ]}
      />
    </div>
  );
}
