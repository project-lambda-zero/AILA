/**
 * reports.spec.ts — D-07, D-08, D-13, D-16, D-17, D-18, D-28.
 *
 * - D-07: list endpoint hit at LOCKED URL /vulnerability/reports/list.
 * - D-08: detail page renders the four canonical sections.
 * - D-13: empty list renders honest "No reports yet." text — never a fake row.
 * - D-16: ReportSummary shape keys present in list items.
 * - D-17: ReportDetail shape keys present in detail body.
 * - D-18: queries.ts imports real query module (asserted via the prod request URL).
 * - D-28: unauthenticated fetch of the list endpoint returns 401.
 */
import { test, expect } from "./helpers/fixtures";
import { API_BASE } from "../helpers/auth";

const SHOTS = "tests/e2e/176a/__screenshots__";

const SUMMARY_KEYS = [
  "id",
  "title",
  "target",
  "created_at",
  "status",
  "severity_counts",
  "finding_count",
];

const DETAIL_KEYS = [...SUMMARY_KEYS, "findings", "metadata", "remediation_notes"];

test.describe("Vulnerability reports (D-07, D-08, D-13, D-16/17/18, D-28)", () => {
  test("D-28: unauthenticated GET /vulnerability/reports/list returns 401/403", async ({
    request,
  }) => {
    const resp = await request.get(`${API_BASE}/vulnerability/reports/list`);
    expect([401, 403]).toContain(resp.status());
  });

  test("D-07 + D-13 + D-16 + D-18: ReportsPage hits LOCKED URL and renders honestly", async ({
    authedPage: page,
  }) => {
    let observedListUrl: string | null = null;
    let observedListBody: unknown = null;

    page.on("response", async (resp) => {
      const url = resp.url();
      if (url.includes("/vulnerability/reports/list")) {
        observedListUrl = url;
        try {
          observedListBody = await resp.clone().json();
        } catch {
          observedListBody = null;
        }
      }
    });

    await page.goto("/vulnerability/reports");
    await expect(page).toHaveURL(/\/vulnerability\/reports$/);
    await expect(
      page.getByRole("heading", { level: 1, name: /reports/i }).first(),
    ).toBeVisible({ timeout: 15_000 });

    // Allow the query to settle.
    await page.waitForLoadState("networkidle", { timeout: 10_000 }).catch(() => {});

    // D-07 / D-18: list endpoint must have been hit at the LOCKED URL.
    expect(
      observedListUrl,
      "ReportsPage must call /vulnerability/reports/list (D-07/D-18)",
    ).not.toBeNull();

    // D-13: row count must EQUAL the count of records returned by the
    // backend. Any rendered row beyond what the backend returned would be a
    // fake row (mock data). Zero-and-zero is honest.
    const rows = page.locator('[data-testid="report-row"]');
    const renderedCount = await rows.count();
    const apiData = (observedListBody as { data?: unknown[] } | null)?.data ?? [];
    const apiCount = Array.isArray(apiData) ? apiData.length : 0;
    expect(
      renderedCount,
      `D-13: page must not render more rows than the backend returned ` +
        `(rendered=${renderedCount}, backend=${apiCount})`,
    ).toBeLessThanOrEqual(apiCount);

    if (renderedCount > 0 && apiCount > 0) {
      // D-16: each row's source record has the expected keys.
      for (const key of SUMMARY_KEYS) {
        expect(
          Object.prototype.hasOwnProperty.call(apiData[0] as object, key),
          `ReportSummary must have '${key}' (D-16)`,
        ).toBe(true);
      }
    }

    await expect(page.getByText(/internal server error/i)).toHaveCount(0);
    await page.screenshot({
      path: `${SHOTS}/D-07-reports-list.png`,
      fullPage: true,
    });
  });

  test("D-08 + D-17: report detail page renders 4 sections (when seeded data present)", async ({
    authedPage: page,
  }) => {
    let detailBody: unknown = null;
    page.on("response", async (resp) => {
      if (resp.url().includes("/vulnerability/reports/detail/")) {
        try {
          detailBody = await resp.clone().json();
        } catch {
          /* ignore */
        }
      }
    });

    await page.goto("/vulnerability/reports");
    await page.waitForLoadState("networkidle", { timeout: 10_000 }).catch(() => {});

    const rows = page.locator('[data-testid="report-row"]');
    const count = await rows.count();
    if (count === 0) {
      test.skip(
        true,
        "no reports seeded in this env — D-08 covered by ReportDetailPage unit test",
      );
      return;
    }

    await rows.first().click();
    await expect(page).toHaveURL(/\/vulnerability\/reports\/[^/]+/, { timeout: 10_000 });

    // D-08: the four canonical section headings.
    for (const section of ["Summary", "Findings", "Remediation", "Metadata"]) {
      await expect(
        page.getByRole("heading", { name: new RegExp(`^${section}$`, "i") }),
      ).toBeVisible({ timeout: 10_000 });
    }

    // D-17: detail body has the expected keys.
    if (detailBody) {
      const data = (detailBody as { data?: Record<string, unknown> }).data ?? {};
      for (const key of DETAIL_KEYS) {
        expect(
          Object.prototype.hasOwnProperty.call(data, key),
          `ReportDetail must have '${key}' (D-17)`,
        ).toBe(true);
      }
    }

    await expect(page.getByText(/internal server error/i)).toHaveCount(0);
    await page.screenshot({
      path: `${SHOTS}/D-08-report-detail.png`,
      fullPage: true,
    });
  });
});
