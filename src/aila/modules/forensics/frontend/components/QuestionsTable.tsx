import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { DataGrid, MonoBadge } from "@/components/aila/mock";

import { useProjectAnswers } from "../queries";
import type { AnswerCandidate } from "../types";

// Confidence -> mock semantic tone. Preserves the earlier confidenceColor
// mapping but speaks the mock tone vocabulary.
const CONFIDENCE_TONE: Record<string, string> = {
  exact: "ok",
  strong: "ok",
  medium: "medium",
  caveated: "high",
};

export function QuestionsTable({ projectId }: { projectId: string }) {
  const { data: answers, isLoading } = useProjectAnswers(projectId);

  if (isLoading) return <LoadingSkeleton size="lg" width="full" />;

  const items = answers ?? [];

  if (items.length === 0) {
    return (
      <WindowPanel
        title="questions & answers"
        tone="muted"
        status="forensics ; no answers yet"
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
          No questions answered yet. Use the free-flow investigator to ask
          questions.
        </p>
      </WindowPanel>
    );
  }

  return (
    <div aria-label="Investigation questions">
      <DataGrid<AnswerCandidate>
        columns={[
          { label: "question", width: "minmax(0, 2fr)" },
          { label: "answer", width: "minmax(0, 2fr)" },
          { label: "confidence", width: "120px" },
          { label: "format", width: "120px" },
        ]}
        rows={items}
        getKey={(a) => a.id}
        renderCells={(a) => [
          <span
            key="q"
            className="font-mono"
            style={{
              fontSize: 11,
              color: "var(--text-primary)",
              display: "block",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
            title={a.question_text}
          >
            {a.question_text}
          </span>,
          <span
            key="a"
            className="font-mono"
            style={{
              fontSize: 10.5,
              color: "var(--status-ok)",
              display: "block",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
            title={a.answer_text ?? undefined}
          >
            {a.answer_text || "--"}
          </span>,
          <MonoBadge
            key="c"
            tone={CONFIDENCE_TONE[a.confidence] ?? "info"}
          >
            {a.confidence}
          </MonoBadge>,
          <span
            key="f"
            className="font-mono"
            style={{ fontSize: 10, color: "var(--text-faint)" }}
          >
            {a.format_hint || "--"}
          </span>,
        ]}
      />
    </div>
  );
}
