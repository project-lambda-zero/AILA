export function firstWizardPath(sessionId: string, firstSectionKey: string | undefined): string | null {
  if (!firstSectionKey) {
    return null;
  }
  return `/assessments/${encodeURIComponent(sessionId)}/wizard/${encodeURIComponent(firstSectionKey)}`;
}

export function canShowResults(status: string): boolean {
  return ['resolved', 'in_review', 'approved', 'report_generated'].includes(status);
}

export function assessmentStatusDestination(
  sessionId: string,
  status: string,
  firstSectionKey: string | undefined,
): string | null {
  if (status === 'in_review') {
    return `/assessments/${encodeURIComponent(sessionId)}/review`;
  }
  if (status === 'approved' || status === 'report_generated') {
    return `/assessments/${encodeURIComponent(sessionId)}/report`;
  }
  if (status === 'resolved') {
    return `/assessments/${encodeURIComponent(sessionId)}/results`;
  }
  return firstWizardPath(sessionId, firstSectionKey);
}
