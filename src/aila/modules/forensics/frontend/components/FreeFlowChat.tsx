import { useState } from "react";

import { WindowPanel } from "@/components/aila/WindowPanel";

import { useStartInvestigation } from "../mutations";
import { useProjectInvestigations } from "../queries";
import type { InvestigationSummary } from "../types";

const statusColors: Record<string, string> = {
  pending: "text-text-muted",
  running: "text-accent",
  completed: "text-mint",
  exhausted: "text-amber-400",
  failed: "text-critical",
};

export function FreeFlowChat({ projectId }: { projectId: string }) {
  const [question, setQuestion] = useState("");
  const [maxAttempts, setMaxAttempts] = useState(10);
  const startInvestigation = useStartInvestigation();
  const { data: investigations, isLoading } = useProjectInvestigations(projectId);

  async function handleSubmit() {
    if (!question.trim()) return;
    await startInvestigation.mutateAsync({
      projectId,
      question: question.trim(),
      maxAttempts,
    });
    setQuestion("");
  }

  return (
    <div className="space-y-4">
      <WindowPanel title="free-flow investigator"><div className="space-y-3">
        <textarea
          aria-label="Question for the investigator"
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          placeholder="Ask a question about the evidence..."
          rows={3}
          className="w-full px-3 py-2 text-sm rounded-md border border-border bg-surface text-foreground resize-none"
        />
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <label className="text-xs text-text-muted" htmlFor="ffchat-max-attempts">Max attempts:</label>
            <input
              id="ffchat-max-attempts"
              type="number"
              min={1}
              max={50}
              value={maxAttempts}
              onChange={(e) => setMaxAttempts(Number(e.target.value))}
              className="w-16 px-2 py-1 text-xs rounded border border-border bg-surface text-foreground"
            />
          </div>
          <button
            type="button"
            onClick={handleSubmit}
            disabled={!question.trim() || startInvestigation.isPending}
            className="px-4 py-2 font-mono text-xs uppercase tracking-cyber-sm rounded-[3px] bg-accent text-badge-text hover:brightness-110 transition-[filter] disabled:opacity-50"
            style={{ boxShadow: "var(--bevel-key)" }}
          >
            {startInvestigation.isPending ? "Starting..." : "Investigate"}
          </button>
        </div>
      </div></WindowPanel>

      <div className="space-y-2">
        <h4 className="font-mono text-2xs uppercase tracking-cyber-sm text-muted-foreground">
          Investigations ({investigations?.length ?? 0})
        </h4>
        {isLoading && <p className="text-xs text-text-muted">Loading...</p>}
        {(investigations ?? []).map((inv: InvestigationSummary) => (
          <div
            key={inv.id}
            className="px-3 py-2 border border-border rounded-md bg-surface text-sm"
          >
            <div className="flex items-center justify-between">
              <p className="text-foreground font-medium truncate mr-2">{inv.question}</p>
              <span className={`text-xs font-mono ${statusColors[inv.status] ?? "text-text-muted"}`}>
                {inv.status}
              </span>
            </div>
            <div className="flex gap-4 mt-1 text-xs text-text-muted">
              <span>Attempts: {inv.attempts_used}</span>
              {inv.confidence && <span>Confidence: {inv.confidence}</span>}
            </div>
            {inv.final_answer && (
              <div className="mt-2 px-2 py-1 bg-mint/10 border border-mint/30 rounded text-xs text-mint font-mono">
                {inv.final_answer}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
