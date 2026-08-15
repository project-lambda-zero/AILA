import { AilaBadge } from "@/components/aila/AilaBadge";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";

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
      <WindowPanel title="machine readiness" status="readiness ; checking tools">
        <div className="space-y-3">
          <LoadingSkeleton size="md" width="full" />
          <p className="text-sm text-text-muted">
            Connecting to analyzer machine and checking installed tools.
          </p>
        </div>
      </WindowPanel>
    );
  }

  if (!readinessResult) {
    return (
      <WindowPanel title="machine readiness" tone="muted" status="readiness ; no result">
        <p className="text-sm text-text-muted">No readiness check result available.</p>
      </WindowPanel>
    );
  }

  return (
    <WindowPanel
      title="machine readiness"
      tone={readinessResult.ready ? "ok" : "warn"}
      actions={
        <AilaBadge severity={readinessResult.ready ? "low" : "high"} size="sm">
          {readinessResult.ready ? "Ready" : "Not Ready"}
        </AilaBadge>
      }
    >
      <div className="space-y-4">
        <p className="text-sm text-text-muted">{readinessResult.message}</p>
    
        <div className="border border-border rounded-md bg-surface text-foreground overflow-hidden">
          <table className="w-full text-sm" aria-label="Machine readiness checks">
            <caption className="sr-only">Prerequisite checks for the analyzer host, with status and remediation notes.</caption>
            <thead className="bg-elevated">
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
                    {tool.version ?? tool.message ?? "--"}
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
            className="px-4 py-2 font-mono text-xs uppercase tracking-cyber-sm rounded-[3px] border border-border text-foreground hover:bg-elevated hover:border-border-hover transition-colors"
          >
            Retry Check
          </button>
          <button
            type="button"
            onClick={onContinue}
            className="px-4 py-2 font-mono text-xs uppercase tracking-cyber-sm rounded-[3px] bg-accent text-badge-text hover:brightness-110 transition-[filter]"
            style={{ boxShadow: "var(--bevel-key)" }}
          >
            Continue
          </button>
        </div>
      </div>
    </WindowPanel>
  );
}
