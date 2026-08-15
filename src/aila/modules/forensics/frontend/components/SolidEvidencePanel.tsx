import { useNavigate } from "react-router";

import { AilaBadge } from "@/components/aila/AilaBadge";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { WindowPanel } from "@/components/aila/WindowPanel";
import { Button } from "@/components/ui/button";

import { useUntagSolidEvidence } from "../mutations";
import { useSolidEvidence } from "../queries";
import type { SolidEvidence } from "../types";

interface Props {
  projectId: string;
}

function formatStamp(iso: string): string {
  if (!iso) return "";
  try {
    const d = new Date(iso);
    return `${d.toLocaleDateString()} ${d.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    })}`;
  } catch {
    return iso;
  }
}

export function SolidEvidencePanel({ projectId }: Props) {
  const navigate = useNavigate();
  const { data, isLoading, isError } = useSolidEvidence(projectId);
  const untag = useUntagSolidEvidence(projectId);

  if (isLoading) return <LoadingSkeleton size="lg" width="full" />;
  if (isError) {
    return (
      <WindowPanel title="solid evidence" tone="warn" status="forensics ; solid evidence unavailable">
        <p className="text-sm text-critical">Failed to load solid evidence.</p>
      </WindowPanel>
    );
  }

  const rows: SolidEvidence[] = data ?? [];

  if (rows.length === 0) {
    return (
      <WindowPanel title="solid evidence" tone="muted" status="forensics ; no tagged findings"><div className="py-6 text-center space-y-1">
        <p className="text-sm text-text-muted">
          No analyst-tagged findings yet.
        </p>
        <p className="text-xs text-text-muted">
          Open a completed investigation and hit{" "}
          <span className="font-mono text-mint">Tag as TRUE</span> or{" "}
          <span className="font-mono" style={{ color: "var(--color-amber)" }}>Tag as FALSE</span> to
          promote its answer to solid evidence. Tagged findings are injected
          into every future investigation's prompt so the agent treats them
          as ground truth / known dead-ends.
        </p>
      </div></WindowPanel>
    );
  }

  const trueCount = rows.filter((r) => r.verdict === "true").length;
  const falseCount = rows.length - trueCount;

  const handleUntag = (id: string) => {
    if (!window.confirm("Remove this row from Solid Evidence? Its linked directive will also be deactivated.")) return;
    untag.mutate(id);
  };

  const openSourceInvestigation = (e: SolidEvidence) => {
    if (!e.source_investigation_id) return;
    navigate(
      `/forensics/projects/${projectId}/investigations/${e.source_investigation_id}`,
    );
  };

  return (
    <WindowPanel title="solid evidence" status={`total ${rows.length} ; true ${trueCount} ; false ${falseCount}`}>
      <div className="rounded-md border border-border overflow-hidden bg-surface text-foreground">
        <table className="w-full text-sm" aria-label="Solid-evidence tags">
          <caption className="sr-only">Analyst-confirmed and disproved findings tagged as solid evidence.</caption>
          <thead className="bg-elevated text-xs text-text-muted">
            <tr>
              <th className="text-left px-3 py-2 font-semibold w-20">Verdict</th>
              <th className="text-left px-3 py-2 font-semibold">Question</th>
              <th className="text-left px-3 py-2 font-semibold">Answer</th>
              <th className="text-left px-3 py-2 font-semibold w-24">Confidence</th>
              <th className="text-left px-3 py-2 font-semibold w-36">Tagged</th>
              <th className="text-left px-3 py-2 font-semibold w-32">Source</th>
              <th className="px-3 py-2 w-20" />
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr
                key={r.id}
                className="border-t border-border align-top hover:bg-elevated/30"
              >
                <td className="px-3 py-2">
                  <AilaBadge
                    severity={r.verdict === "true" ? "low" : "high"}
                    size="sm"
                  >
                    {r.verdict === "true" ? "TRUE" : "FALSE"}
                  </AilaBadge>
                </td>
                <td className="px-3 py-2 text-foreground">{r.question}</td>
                <td className="px-3 py-2 text-foreground">
                  <div className="whitespace-pre-wrap">{r.answer}</div>
                  {r.notes && (
                    <div className="mt-1 text-xs text-text-muted italic">
                      Notes: {r.notes}
                    </div>
                  )}
                  {r.primary_artifact && (
                    <div className="mt-1 text-xs font-mono text-text-muted">
                      artifact={r.primary_artifact}
                    </div>
                  )}
                  {r.corroboration.length > 0 && (
                    <div className="mt-1 text-xs text-text-muted">
                      corroborated by:{" "}
                      {r.corroboration.map((c, i) => (
                        <code
                          key={i}
                          className="ml-1 px-1.5 py-0.5 bg-surface rounded font-mono"
                        >
                          {c}
                        </code>
                      ))}
                    </div>
                  )}
                </td>
                <td className="px-3 py-2 text-xs font-mono text-text-muted">
                  {r.confidence}
                </td>
                <td className="px-3 py-2 text-xs text-text-muted">
                  <div>{formatStamp(r.tagged_at)}</div>
                  {r.tagged_by && (
                    <div className="font-mono text-2xs">{r.tagged_by}</div>
                  )}
                </td>
                <td className="px-3 py-2 text-xs">
                  {r.source_investigation_id ? (
                    <button
                      type="button"
                      onClick={() => openSourceInvestigation(r)}
                      className="text-accent hover:underline font-mono"
                    >
                      {r.source_investigation_id.slice(0, 8)}…
                    </button>
                  ) : (
                    <span className="text-text-muted">--</span>
                  )}
                </td>
                <td className="px-3 py-2 text-right">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleUntag(r.id)}
                    disabled={untag.isPending}
                  >
                    Untag
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </WindowPanel>
  );
}
