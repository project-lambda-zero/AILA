import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { useProjectLeads } from "../queries";
import type { PromotedLead } from "../types";

function scoreSeverity(score: number): "critical" | "high" | "medium" | "low" | "info" {
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
      <AilaCard>
        <p className="text-sm text-text-muted text-center py-8">
          No Very Important Artifacts identified yet.
        </p>
      </AilaCard>
    );
  }

  return (
    <div className="border border-border rounded-md overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="bg-surface-secondary">
          <tr>
            <th className="text-left px-3 py-2 text-text-muted font-medium">Score</th>
            <th className="text-left px-3 py-2 text-text-muted font-medium">Family</th>
            <th className="text-left px-3 py-2 text-text-muted font-medium">Reason</th>
            <th className="text-left px-3 py-2 text-text-muted font-medium">Question Families</th>
          </tr>
        </thead>
        <tbody>
          {items.map((lead: PromotedLead) => (
            <tr key={lead.id} className="border-t border-border hover:bg-surface-secondary">
              <td className="px-3 py-2">
                <AilaBadge severity={scoreSeverity(lead.score)} size="sm">
                  {lead.score.toFixed(1)}
                </AilaBadge>
              </td>
              <td className="px-3 py-2 text-foreground font-mono text-xs">{lead.artifact_family}</td>
              <td className="px-3 py-2 text-foreground text-xs max-w-md truncate">{lead.reason}</td>
              <td className="px-3 py-2">
                <div className="flex flex-wrap gap-1">
                  {lead.question_families.map((qf) => (
                    <span key={qf} className="px-1.5 py-0.5 text-xs bg-surface-secondary rounded text-text-muted">
                      {qf}
                    </span>
                  ))}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
