import type { ReactNode } from "react";

export interface WizardLayoutProps {
  /** Overall completion percent 0-100 */
  overallPct: number;
  /** Left sidebar content (WizardProgressSidebar) */
  sidebar: ReactNode;
  /** Center content (WizardSection + complete bar) */
  content: ReactNode;
  /** Right panel content (WizardSubtaskPanel) */
  panel: ReactNode;
}

export function WizardLayout({ overallPct, sidebar, content, panel }: WizardLayoutProps) {
  const clampedPct = Math.min(100, Math.max(0, overallPct));

  return (
    <div
      className="flex flex-col bg-base overflow-hidden"
      style={{ minHeight: "calc(100vh - 64px)", borderRadius: "var(--radius-lg)" }}
    >
      {/* Top progress strip */}
      <div className="flex items-center gap-3 px-5 py-3 border-b border-border">
        <span
          className="font-mono uppercase tracking-wider text-accent whitespace-nowrap"
          style={{ fontSize: 10 }}
        >
          Assessment progress
        </span>
        <div className="flex-1 h-1 bg-border rounded-full">
          <div
            className="h-full bg-accent rounded-full transition-all"
            style={{ width: `${clampedPct}%` }}
            role="progressbar"
            aria-valuenow={clampedPct}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label="Overall wizard progress"
          />
        </div>
        <span
          className="font-mono text-xs font-semibold text-accent text-right"
          style={{ minWidth: 32 }}
        >
          {clampedPct}%
        </span>
      </div>

      {/* 3-column grid */}
      <div
        className="grid flex-1 overflow-hidden"
        style={{ gridTemplateColumns: "260px 1fr 280px" }}
      >
        <aside className="border-r border-border overflow-y-auto p-4 bg-surface">
          <div
            className="font-mono uppercase tracking-wider text-accent mb-3"
            style={{ fontSize: 10 }}
          >
            Sections
          </div>
          {sidebar}
        </aside>

        <main className="overflow-y-auto p-7 flex flex-col">{content}</main>

        <aside className="border-l border-border overflow-y-auto p-4 bg-surface">
          <div
            className="font-mono uppercase tracking-wider text-accent mb-3"
            style={{ fontSize: 10 }}
          >
            Component impact
          </div>
          {panel}
        </aside>
      </div>
    </div>
  );
}
