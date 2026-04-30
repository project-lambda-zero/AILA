import type { SectionProgressResponse, SectionResponse } from "../types";

export interface WizardBreadcrumbProps {
  sections: SectionResponse[];
  sectionProgress: SectionProgressResponse[];
  activeSectionKey: string | undefined;
  projectName?: string;
  onNavigate: (sectionKey: string) => void;
}

function progressFor(
  sectionKey: string,
  sectionProgress: SectionProgressResponse[],
): SectionProgressResponse | undefined {
  return sectionProgress.find((p) => p.section_key === sectionKey);
}

type ItemState = "active" | "visited" | "upcoming";

function itemState(
  sectionKey: string,
  activeSectionKey: string | undefined,
  hasAnswers: boolean,
): ItemState {
  if (sectionKey === activeSectionKey) return "active";
  if (hasAnswers) return "visited";
  return "upcoming";
}

const ITEM_BASE = "px-3 py-2 rounded-[var(--radius-md)]";
const ITEM_VARIANTS: Record<ItemState, string> = {
  active: "bg-accent-muted border-l-2 border-accent",
  visited: "border-l-2 border-[color:var(--color-accent)]/40",
  upcoming: "border-l-2 border-transparent",
};

export function WizardBreadcrumb({
  sections,
  sectionProgress,
  activeSectionKey,
  projectName,
  onNavigate,
}: WizardBreadcrumbProps) {
  return (
    <nav className="flex flex-col" aria-label="Assessment sections">
      {projectName && (
        <div className="font-mono text-[10px] text-text-muted uppercase tracking-wider px-3 pb-2 mb-2 border-b border-border truncate">
          {projectName}
        </div>
      )}
      <ol className="flex flex-col gap-0.5 list-none p-0 m-0" role="list">
        {sections.map((section) => {
          const progress = progressFor(section.section_key, sectionProgress);
          const hasAnswers = progress !== undefined && progress.answered_count > 0;
          const isActive = section.section_key === activeSectionKey;
          const state = itemState(section.section_key, activeSectionKey, hasAnswers);

          const iconColor =
            state === "active"
              ? "var(--color-accent)"
              : state === "visited"
                ? "var(--color-text)"
                : "var(--color-text-muted)";

          const labelClass = isActive
            ? "font-sans text-sm text-accent font-semibold"
            : "font-sans text-sm text-text";

          return (
            <li
              key={section.section_key}
              className={`${ITEM_BASE} ${ITEM_VARIANTS[state]}`}
              aria-current={isActive ? "step" : undefined}
            >
              <button
                className="w-full flex items-center gap-2 text-left cursor-pointer bg-transparent border-none"
                type="button"
                onClick={() => onNavigate(section.section_key)}
                aria-label={`${section.label}${hasAnswers ? " (visited)" : ""}`}
              >
                <span className="text-xs" style={{ color: iconColor }}>
                  {sections.indexOf(section) + 1}
                </span>
                <span className={labelClass}>{section.label}</span>
                {progress && (
                  <span
                    className="font-mono text-[10px] text-text-muted ml-auto"
                    aria-label={`${progress.answered_count} of ${progress.visible_count} answered`}
                  >
                    {progress.answered_count}/{progress.visible_count}
                  </span>
                )}
              </button>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
