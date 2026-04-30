import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaCard } from "@/components/aila/AilaCard";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";

import { useProjectAnswers } from "../queries";
import type { AnswerCandidate } from "../types";

const confidenceColor: Record<string, "critical" | "high" | "medium" | "low" | "info"> = {
  exact: "low",
  strong: "low",
  medium: "medium",
  caveated: "high",
};

export function QuestionsTable({ projectId }: { projectId: string }) {
  const { data: answers, isLoading } = useProjectAnswers(projectId);

  if (isLoading) return <LoadingSkeleton size="lg" width="full" />;

  const items = answers ?? [];

  if (items.length === 0) {
    return (
      <AilaCard>
        <p className="text-sm text-text-muted text-center py-8">
          No questions answered yet. Use the free-flow investigator to ask questions.
        </p>
      </AilaCard>
    );
  }

  return (
    <div className="border border-border rounded-md overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="bg-surface-secondary">
          <tr>
            <th className="text-left px-3 py-2 text-text-muted font-medium">Question</th>
            <th className="text-left px-3 py-2 text-text-muted font-medium">Answer</th>
            <th className="text-left px-3 py-2 text-text-muted font-medium">Confidence</th>
            <th className="text-left px-3 py-2 text-text-muted font-medium">Format</th>
          </tr>
        </thead>
        <tbody>
          {items.map((answer: AnswerCandidate) => (
            <tr key={answer.id} className="border-t border-border hover:bg-surface-secondary">
              <td className="px-3 py-2 text-foreground max-w-sm">
                <p className="truncate">{answer.question_text}</p>
              </td>
              <td className="px-3 py-2 text-green-300 font-mono text-xs max-w-xs">
                {answer.answer_text || "—"}
              </td>
              <td className="px-3 py-2">
                <AilaBadge severity={confidenceColor[answer.confidence] ?? "info"} size="sm">
                  {answer.confidence}
                </AilaBadge>
              </td>
              <td className="px-3 py-2 text-text-muted text-xs font-mono">
                {answer.format_hint || "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
