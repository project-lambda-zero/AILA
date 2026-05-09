import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import type { MachineReadinessResult } from "../types";

interface Props {
  readinessResult: MachineReadinessResult | null;
  isLoading: boolean;
  onRetry: () => void;
  onContinue: () => void;
}

const statusIcon: Record<string, string> = {
  installed: "\u2714",
  missing: "\u2718",
  install_failed: "\u26A0",
  installing: "\u23F3",
};

const statusSeverity: Record<string, "low" | "critical" | "high" | "medium" | "info"> = {
  installed: "low",
  missing: "critical",
  install_failed: "high",
  installing: "medium",
};

export function MachineReadinessCheck({ readinessResult, isLoading, onRetry, onContinue }: Props) {
  if (isLoading) {
    return (
      <AilaCard>
        <div className="space-y-3">
          <h2 className="text-lg font-semibold font-mono text-foreground">Checking Readiness...</h2>
          <LoadingSkeleton size="md" width="full" />
          <p className="text-sm text-text-muted">
            Connecting to analyzer machine and checking installed tools.
          </p>
        </div>
      </AilaCard>
    );
  }

  if (!readinessResult) {
    return (
      <AilaCard>
        <p className="text-sm text-text-muted">No readiness check result available.</p>
      </AilaCard>
    );
  }

  return (
    <AilaCard>
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold font-mono text-foreground">Machine Readiness</h2>
          <AilaBadge severity={readinessResult.ready ? "low" : "high"} size="sm">
            {readinessResult.ready ? "Ready" : "Not Ready"}
          </AilaBadge>
        </div>

        <p className="text-sm text-text-muted">{readinessResult.message}</p>

        <div className="border border-border rounded-md bg-card text-card-foreground overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-surface-secondary">
              <tr>
                <th className="text-left px-3 py-2 text-text-muted font-medium">Tool</th>
                <th className="text-left px-3 py-2 text-text-muted font-medium">Required</th>
                <th className="text-left px-3 py-2 text-text-muted font-medium">Status</th>
                <th className="text-left px-3 py-2 text-text-muted font-medium">Version</th>
              </tr>
            </thead>
            <tbody>
              {readinessResult.tools.map((tool) => (
                <tr key={tool.tool_name} className="border-t border-border">
                  <td className="px-3 py-2 font-mono text-foreground">{tool.tool_name}</td>
                  <td className="px-3 py-2 text-text-muted">{tool.required ? "Yes" : "No"}</td>
                  <td className="px-3 py-2">
                    <AilaBadge severity={statusSeverity[tool.status] ?? "info"} size="sm">
                      {statusIcon[tool.status] ?? ""} {tool.status}
                    </AilaBadge>
                  </td>
                  <td className="px-3 py-2 text-text-muted text-xs font-mono">
                    {tool.version ?? tool.message ?? "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onRetry}
            className="px-4 py-2 text-sm rounded-md border border-border text-foreground hover:bg-surface-secondary"
          >
            Retry Check
          </button>
          <button
            type="button"
            onClick={onContinue}
            className="px-4 py-2 text-sm font-medium rounded-md bg-accent text-white hover:bg-accent/90"
          >
            Continue
          </button>
        </div>
      </div>
    </AilaCard>
  );
}
