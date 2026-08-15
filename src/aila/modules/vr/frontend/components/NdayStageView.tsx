import { AilaBadge } from "@/components/aila/AilaBadge";
import { PixelIcon, type PixelIconName } from "@/components/aila/PixelIcon";

/** N-day 4-stage view from 08_FRONTEND_UX.md §1.11.
 *
 *  Stages render top-to-bottom as a vertical thread. Each has:
 *    - Title + status badge
 *    - Stage payload (patch info / RC excerpt / trigger hex view / exploit link)
 *    - Optional rewind button (drops everything from this stage forward) */
export type NdayStage = "patch_acquired" | "root_cause" | "trigger" | "exploit";
export type StageStatus = "pending" | "in_progress" | "complete" | "failed";

export interface StageData {
  id: NdayStage;
  title: string;
  description: string;
  status: StageStatus;
  evidence?: React.ReactNode;
  rewindable?: boolean;
  onRewind?: () => void;
}

const STATUS_TONE: Record<
  StageStatus,
  "info" | "low" | "medium" | "high" | "critical"
> = {
  pending: "info",
  in_progress: "medium",
  complete: "low",
  failed: "critical",
};

const STATUS_ICON: Record<StageStatus, PixelIconName> = {
  pending: "status",
  in_progress: "cycle",
  complete: "ok",
  failed: "close",
};

export function NdayStageView({ stages }: { stages: ReadonlyArray<StageData> }) {
  return (
    <ol className="space-y-3">
      {stages.map((stage, idx) => (
        <li key={stage.id} className="relative">
          {idx < stages.length - 1 && (
            <div
              className="absolute left-3 top-8 bottom-0 w-px bg-border"
              aria-hidden
            />
          )}
          <div className="flex items-start gap-3">
            <div
              className={
                "w-6 h-6 rounded-[2px] flex items-center justify-center text-3xs font-bold border-2 relative z-10 bg-base " +
                (stage.status === "complete"
                  ? "border-mint text-mint"
                  : stage.status === "failed"
                    ? "border-critical text-critical"
                    : stage.status === "in_progress"
                      ? ""
                      : "border-border text-text-muted")
              }
              style={
                stage.status === "in_progress"
                  ? { borderColor: "var(--color-amber)", color: "var(--color-amber)" }
                  : undefined
              }
            >
              <PixelIcon name={STATUS_ICON[stage.status]} size={12} />
            </div>
            <div className="flex-1 min-w-0 border border-border rounded-md p-3 bg-surface/40">
              <div className="flex items-center justify-between gap-2 flex-wrap mb-1">
                <h3 className="text-sm font-semibold text-foreground">
                  {idx + 1}. {stage.title}
                </h3>
                <div className="flex items-center gap-1.5">
                  <AilaBadge severity={STATUS_TONE[stage.status]} size="sm">
                    {stage.status.replace("_", " ")}
                  </AilaBadge>
                  {stage.rewindable && stage.onRewind && (
                    <button
                      type="button"
                      onClick={() => {
                        if (
                          window.confirm(
                            `Rewind from "${stage.title}"? Everything downstream is dropped and the engine re-enters from the previous stage.`,
                          )
                        ) {
                          stage.onRewind!();
                        }
                      }}
                      className="inline-flex items-center gap-1 text-3xs font-mono px-2 py-0.5 rounded bg-surface border border-border hover:bg-elevated"
                    >
                      <PixelIcon name="cycle" size={11} />
                      rewind
                    </button>
                  )}
                </div>
              </div>
              <p className="text-xs text-text-muted">{stage.description}</p>
              {stage.evidence && (
                <div className="mt-2 pt-2 border-t border-border">
                  {stage.evidence}
                </div>
              )}
            </div>
          </div>
        </li>
      ))}
    </ol>
  );
}
