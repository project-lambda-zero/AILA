import { WindowPanel, type WindowPanelTone } from "@/components/aila/WindowPanel";
import { MonoBadge } from "@/components/aila/mock";
import { PixelIcon, type PixelIconName } from "@/components/aila/PixelIcon";

/** N-day 4-stage view from 08_FRONTEND_UX.md §1.11.
 *
 *  Stages render top-to-bottom as a stack of WindowPanels. Each has:
 *    - Title (stage n: <title>) + status MonoBadge
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

const STATUS_TONE: Record<StageStatus, "info" | "ok" | "warn" | "critical"> = {
  pending: "info",
  in_progress: "warn",
  complete: "ok",
  failed: "critical",
};

const PANEL_TONE: Record<StageStatus, WindowPanelTone> = {
  pending: "muted",
  in_progress: "warn",
  complete: "ok",
  failed: "accent",
};

const STATUS_ICON: Record<StageStatus, PixelIconName> = {
  pending: "status",
  in_progress: "cycle",
  complete: "ok",
  failed: "close",
};

export function NdayStageView({ stages }: { stages: ReadonlyArray<StageData> }) {
  return (
    <ol style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {stages.map((stage, idx) => {
        const tone = STATUS_TONE[stage.status];
        return (
          <li key={stage.id}>
            <WindowPanel
              title={`stage ${idx + 1}: ${stage.title}`}
              tone={PANEL_TONE[stage.status]}
              actions={
                <div className="flex items-center" style={{ gap: 6 }}>
                  <MonoBadge tone={tone}>
                    <span
                      className="inline-flex items-center"
                      style={{ gap: 4 }}
                    >
                      <PixelIcon name={STATUS_ICON[stage.status]} size={10} />
                      {stage.status.replace("_", " ")}
                    </span>
                  </MonoBadge>
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
                      className="font-mono uppercase inline-flex items-center"
                      style={{
                        height: 22,
                        padding: "0 8px",
                        gap: 4,
                        fontSize: 9,
                        letterSpacing: "0.08em",
                        color: "var(--text-muted)",
                        background: "transparent",
                        border: "1px solid var(--border-soft)",
                        borderRadius: 2,
                        cursor: "pointer",
                      }}
                      onMouseOver={(e) => {
                        e.currentTarget.style.color = "var(--accent)";
                        e.currentTarget.style.borderColor = "var(--accent)";
                      }}
                      onMouseOut={(e) => {
                        e.currentTarget.style.color = "var(--text-muted)";
                        e.currentTarget.style.borderColor = "var(--border-soft)";
                      }}
                    >
                      <PixelIcon name="cycle" size={10} />
                      rewind
                    </button>
                  )}
                </div>
              }
            >
              <p
                style={{
                  fontFamily: "var(--font-sans)",
                  fontSize: 12,
                  lineHeight: 1.5,
                  color: "var(--text-muted)",
                }}
              >
                {stage.description}
              </p>
              {stage.evidence && (
                <div
                  style={{
                    marginTop: 10,
                    paddingTop: 10,
                    borderTop: "1px solid var(--border-soft)",
                  }}
                >
                  {stage.evidence}
                </div>
              )}
            </WindowPanel>
          </li>
        );
      })}
    </ol>
  );
}
