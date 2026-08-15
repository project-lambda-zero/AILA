import { useState } from "react";

import { WindowPanel } from "@/components/aila/WindowPanel";
import { DataGrid, MonoBadge } from "@/components/aila/mock";

import { useStartInvestigation } from "../mutations";
import { useProjectInvestigations } from "../queries";
import type { InvestigationSummary } from "../types";

// Status -> MonoBadge tone. Mirrors the module-wide status severity table
// (pending=muted, running=medium, completed=ok, exhausted=warn, failed=critical).
const STATUS_TONE: Record<string, string> = {
  pending: "muted",
  running: "medium",
  completed: "ok",
  exhausted: "warn",
  failed: "critical",
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

  const rows: InvestigationSummary[] = investigations ?? [];
  const disabled = !question.trim() || startInvestigation.isPending;

  return (
    <div className="space-y-3">
      <WindowPanel title="free-flow investigator" tone="accent">
        <div className="space-y-3">
          <textarea
            aria-label="Question for the investigator"
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="Ask a question about the evidence..."
            rows={3}
            className="w-full font-mono"
            style={{
              padding: "8px 10px",
              fontSize: 12,
              lineHeight: 1.5,
              background: "var(--surface-sunk)",
              border: "1px solid var(--border-soft)",
              color: "var(--text-primary)",
              borderRadius: 3,
              resize: "vertical",
              minHeight: 72,
            }}
          />
          <div className="flex items-center justify-between" style={{ gap: 12 }}>
            <div className="flex items-center" style={{ gap: 8 }}>
              <label
                htmlFor="ffchat-max-attempts"
                className="font-mono uppercase"
                style={{
                  fontSize: 9,
                  letterSpacing: "0.12em",
                  color: "var(--text-faint)",
                }}
              >
                Max attempts
              </label>
              <input
                id="ffchat-max-attempts"
                type="number"
                min={1}
                max={50}
                value={maxAttempts}
                onChange={(e) => setMaxAttempts(Number(e.target.value))}
                className="font-mono"
                style={{
                  width: 64,
                  height: 26,
                  padding: "0 8px",
                  fontSize: 11,
                  background: "var(--surface-sunk)",
                  border: "1px solid var(--border-soft)",
                  color: "var(--text-primary)",
                  borderRadius: 3,
                }}
              />
            </div>
            <button
              type="button"
              onClick={handleSubmit}
              disabled={disabled}
              className="font-mono uppercase"
              style={{
                height: 28,
                padding: "0 14px",
                fontSize: 10,
                letterSpacing: "0.1em",
                color: "var(--text-on-accent)",
                background: "var(--accent)",
                border: "1px solid var(--accent)",
                borderRadius: 3,
                cursor: disabled ? "not-allowed" : "pointer",
                opacity: disabled ? 0.5 : 1,
                boxShadow: "var(--bevel-key)",
              }}
            >
              {startInvestigation.isPending ? "Starting\u2026" : "Investigate"}
            </button>
          </div>
        </div>
      </WindowPanel>

      <WindowPanel
        title={`investigations (${investigations?.length ?? 0})`}
        flush
      >
        {isLoading ? (
          <div
            className="font-mono"
            style={{
              padding: 12,
              fontSize: 12,
              color: "var(--text-muted)",
            }}
          >
            Loading...
          </div>
        ) : (
          <div>
            <DataGrid<InvestigationSummary>
              columns={[
                { label: "STATUS", width: "110px" },
                { label: "QUESTION", width: "1fr" },
                { label: "ATTEMPTS", width: "90px", align: "right" },
                { label: "CONFIDENCE", width: "110px" },
              ]}
              rows={rows}
              getKey={(inv) => inv.id}
              renderCells={(inv) => [
                <MonoBadge key="st" tone={STATUS_TONE[inv.status] ?? "muted"}>
                  {inv.status}
                </MonoBadge>,
                <span
                  key="q"
                  title={inv.question}
                  className="truncate"
                  style={{
                    fontSize: 11,
                    color: "var(--text-primary)",
                    display: "block",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {inv.question}
                </span>,
                <span
                  key="att"
                  style={{ fontSize: 11, color: "var(--text-muted)" }}
                >
                  {inv.attempts_used}
                </span>,
                <span
                  key="c"
                  style={{ fontSize: 11, color: "var(--text-muted)" }}
                >
                  {inv.confidence ?? "-"}
                </span>,
              ]}
            />
            {rows.some((inv) => inv.final_answer) && (
              <div
                className="space-y-1"
                style={{
                  padding: 12,
                  borderTop: "1px solid var(--border-soft)",
                  background: "var(--surface-card)",
                }}
              >
                {rows
                  .filter((inv) => inv.final_answer)
                  .map((inv) => (
                    <div
                      key={inv.id}
                      className="flex items-start"
                      style={{ gap: 8 }}
                    >
                      <MonoBadge tone="ok">final answer</MonoBadge>
                      <span
                        className="font-mono"
                        title={inv.final_answer ?? undefined}
                        style={{
                          fontSize: 11,
                          color: "var(--status-ok)",
                          lineHeight: 1.5,
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          display: "-webkit-box",
                          WebkitLineClamp: 2,
                          WebkitBoxOrient: "vertical",
                        }}
                      >
                        {inv.final_answer}
                      </span>
                    </div>
                  ))}
              </div>
            )}
          </div>
        )}
      </WindowPanel>
    </div>
  );
}
