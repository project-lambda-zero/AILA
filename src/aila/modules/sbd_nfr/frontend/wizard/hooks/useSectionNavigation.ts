import { useCallback, useMemo } from "react";
import { useNavigate, useParams } from "react-router";

import type { SectionResponse } from "../../types";
import { getVisibleSections } from "./useSkipLogic";

export interface SectionNavigationResult {
  activeSectionKey: string | undefined;
  visibleSections: SectionResponse[];
  nextSection: SectionResponse | undefined;
  prevSection: SectionResponse | undefined;
  navigateToSection: (sectionKey: string) => void;
}

/**
 * Section key ↔ URL param sync hook (D-04, D-18).
 *
 * Reads :sessionId and :sectionKey from the current URL via useParams.
 * navigateToSection() updates the URL by replacing the history entry so that
 * the back button takes the user to the previous page rather than cycling
 * through every section visited.
 *
 * Security (T-137-01): encodeURIComponent() applied to all URL params before
 * embedding them in navigation paths.
 */
export function useSectionNavigation(
  sections: SectionResponse[],
  answers: Record<string, string>,
): SectionNavigationResult {
  const navigate = useNavigate();
  const { sessionId, sectionKey } = useParams<{ sessionId: string; sectionKey: string }>();

  const visibleSections = useMemo(
    () => getVisibleSections(sections, answers),
    [sections, answers],
  );

  const activeSectionKey = useMemo(() => {
    if (sectionKey && visibleSections.some((section) => section.section_key === sectionKey)) {
      return sectionKey;
    }
    return visibleSections[0]?.section_key;
  }, [sectionKey, visibleSections]);

  const activeIndex = useMemo(
    () => visibleSections.findIndex((section) => section.section_key === activeSectionKey),
    [visibleSections, activeSectionKey],
  );

  const nextSection = useMemo(
    () => (activeIndex >= 0 ? visibleSections[activeIndex + 1] : undefined),
    [activeIndex, visibleSections],
  );

  const prevSection = useMemo(
    () => (activeIndex > 0 ? visibleSections[activeIndex - 1] : undefined),
    [activeIndex, visibleSections],
  );

  const navigateToSection = useCallback(
    (targetSectionKey: string) => {
      if (!sessionId) {
        return;
      }
      void navigate(
        `/assessments/${encodeURIComponent(sessionId)}/wizard/${encodeURIComponent(targetSectionKey)}`,
        { replace: true },
      );
    },
    [navigate, sessionId],
  );

  return {
    activeSectionKey,
    visibleSections,
    nextSection,
    prevSection,
    navigateToSection,
  };
}
