import type { SectionProgressResponse, SectionResponse } from "../types";

export interface WizardProgressSidebarProps {
  sections: SectionResponse[];
  sectionProgress: SectionProgressResponse[];
  activeSectionKey: string | undefined;
  projectName?: string;
  onNavigate: (sectionKey: string) => void;
}

export function WizardProgressSidebar({
  sections,
  sectionProgress,
  activeSectionKey,
  projectName,
  onNavigate,
}: WizardProgressSidebarProps) {
  const progressByKey = new Map<string, SectionProgressResponse>(
    sectionProgress.map((p) => [p.section_key, p]),
  );

  const sortedSections = [...sections].sort((a, b) => a.display_order - b.display_order);

  return (
    <nav aria-label="Wizard section navigation" className="flex flex-col gap-1">
      {projectName && (
        <p
          className="font-mono text-[10px] text-text-muted uppercase tracking-wider px-2 pb-3 mb-2 border-b border-border truncate"
          title={projectName}
        >
          {projectName}
        </p>
      )}
      {sortedSections.map((section) => {
        const progress = progressByKey.get(section.section_key);
        const visibleCount = progress?.visible_count ?? 0;
        const answeredCount = progress?.answered_count ?? 0;
        const pct = visibleCount > 0 ? Math.round((answeredCount / visibleCount) * 100) : 0;

        const isActive = section.section_key === activeSectionKey;
        const isComplete = pct === 100 && visibleCount > 0;

        const buttonClass = [
          "w-full flex flex-col gap-2 px-3 py-2.5 rounded-[var(--radius-md)] border-l-2 transition-colors text-left",
          isActive
            ? "border-accent bg-accent-muted"
            : isComplete
              ? "border-accent/40 hover:bg-elevated"
              : "border-transparent hover:bg-elevated",
        ].join(" ");

        const labelClass = `font-sans text-sm ${
          isActive ? "text-accent font-semibold" : "text-text"
        }`;

        return (
          <button
            key={section.section_key}
            className={buttonClass}
            type="button"
            onClick={() => onNavigate(section.section_key)}
            aria-current={isActive ? "step" : undefined}
            aria-label={`${section.label} — ${pct}% complete`}
          >
            <span className={labelClass}>{section.label}</span>
            <div className="flex items-center gap-2">
              <div className="flex-1 h-0.5 bg-border rounded-full overflow-hidden">
                <div
                  className="h-full bg-accent rounded-full transition-[width] duration-200"
                  style={{ width: `${pct}%` }}
                />
              </div>
              {isComplete ? (
                <span className="text-[11px] text-accent" aria-hidden="true">
                  ✓
                </span>
              ) : (
                <span className="font-mono text-[10px] text-text-muted">{pct}%</span>
              )}
            </div>
          </button>
        );
      })}
    </nav>
  );
}
