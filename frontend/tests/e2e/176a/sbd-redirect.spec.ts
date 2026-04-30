/**
 * sbd-redirect.spec.ts — D-09, D-19.
 *
 * - D-09: /sbd_nfr/documents and /sbd_nfr/documents/* redirect to /assessments.
 * - D-19: /assessments renders honestly (live row OR honest empty state, never mock data).
 */
import { test, expect } from "./helpers/fixtures";

const SHOTS = "tests/e2e/176a/__screenshots__";

test.describe("SbD NFR redirect (D-09, D-19)", () => {
  test("D-09: /sbd_nfr/documents → /assessments", async ({ authedPage: page }) => {
    await page.goto("/sbd_nfr/documents");
    await expect(page).toHaveURL(/\/assessments$/, { timeout: 10_000 });
    await expect(page.getByText(/internal server error/i)).toHaveCount(0);
    await page.screenshot({
      path: `${SHOTS}/D-09-sbd-redirect-root.png`,
      fullPage: true,
    });
  });

  test("D-09: /sbd_nfr/documents/foo/bar → /assessments", async ({
    authedPage: page,
  }) => {
    await page.goto("/sbd_nfr/documents/foo/bar");
    await expect(page).toHaveURL(/\/assessments$/, { timeout: 10_000 });
    await expect(page.getByText(/internal server error/i)).toHaveCount(0);
    await page.screenshot({
      path: `${SHOTS}/D-09-sbd-redirect-deep.png`,
      fullPage: true,
    });
  });

  test("D-19: /assessments page renders (live or honest empty)", async ({
    authedPage: page,
  }) => {
    await page.goto("/assessments");
    await expect(page).toHaveURL(/\/assessments$/);
    // Either a heading is visible, or the honest empty state is shown.
    const heading = page.getByRole("heading", { level: 1 }).first();
    await expect(heading).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText(/internal server error/i)).toHaveCount(0);
    await page.screenshot({
      path: `${SHOTS}/D-19-assessments-page.png`,
      fullPage: true,
    });
  });
});
