import { describe, expect, it } from 'vitest';

import {
  assessmentStatusDestination,
  canShowResults,
  firstWizardPath,
} from '../sessionFlow';

describe('sessionFlow', () => {
  it('routes resolved sessions to results', () => {
    expect(assessmentStatusDestination('abc', 'resolved', 'scope')).toBe('/assessments/abc/results');
  });

  it('routes in-review sessions to review', () => {
    expect(assessmentStatusDestination('abc', 'in_review', 'scope')).toBe('/assessments/abc/review');
  });

  it('routes approved and report-generated sessions to report', () => {
    expect(assessmentStatusDestination('abc', 'approved', 'scope')).toBe('/assessments/abc/report');
    expect(assessmentStatusDestination('abc', 'report_generated', 'scope')).toBe('/assessments/abc/report');
  });

  it('builds a wizard path with the first section key', () => {
    expect(firstWizardPath('abc', 'scope')).toBe('/assessments/abc/wizard/scope');
  });

  it('returns null when no wizard section exists', () => {
    expect(firstWizardPath('abc', undefined)).toBeNull();
  });

  it('recognizes results-capable statuses', () => {
    expect(canShowResults('resolved')).toBe(true);
    expect(canShowResults('in_review')).toBe(true);
    expect(canShowResults('approved')).toBe(true);
    expect(canShowResults('report_generated')).toBe(true);
    expect(canShowResults('draft')).toBe(false);
  });
});
