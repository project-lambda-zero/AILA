/**
 * docs-tab.spec.ts — D-03, D-33.
 *
 * - D-03: sidebar Docs entry navigates to /docs and the page renders.
 * - D-33: /docs renders the FIVE locked H2 sections (gap-fix-03 #7).
 *   The five strings are inlined here; if DocsPage is updated, both must
 *   change in lockstep.
 *
 * Every test asserts URL + render + no-error per D-30.
 */
import { test, expect } from "./helpers/fixtures";

const SHOTS = "tests/e2e/176a/__screenshots__";

const LOCKED_SECTIONS = [
  "What this tool does",
  "How to register a system",
  "How to run a scan",
  "How to read results",
  "Where to set the API key",
];

test.describe("Docs tab (D-03, D-33)", () => {
  test("Docs nav navigates to /docs", async ({ authedPage: page }) => {
    await page.goto("/");
    const docsLink = page.getByRole("link", { name: /docs/i }).first();
    await expect(docsLink).toBeVisible({ timeout: 15_000 });
    await docsLink.click();

    // (a) URL
    await expect(page).toHaveURL(/\/docs$/);

    // (b) Render
    await expect(
      page.getByRole("heading", { level: 1, name: /operator docs/i }),
    ).toBeVisible({ timeout: 10_000 });

    // (c) No-error
    await expect(page.getByText(/internal server error/i)).toHaveCount(0);

    // (d) Screenshot
    await page.screenshot({
      path: `${SHOTS}/D-03-docs-page.png`,
      fullPage: true,
    });
  });

  test("D-33: /docs has the 5 locked sections, no README dump", async ({
    authedPage: page,
  }) => {
    await page.goto("/docs");
    await expect(page).toHaveURL(/\/docs$/);

    for (const section of LOCKED_SECTIONS) {
      await expect(
        page.getByRole("heading", { level: 2, name: section }),
      ).toBeVisible({ timeout: 10_000 });
    }

    // README marker — operator docs MUST NOT be a verbatim README dump.
    const bodyText = (await page.locator("body").innerText()).toLowerCase();
    expect(bodyText.includes("# aila")).toBe(false);
    // "readme" appearing inside arbitrary running prose is OK; the harsher
    // assertion is the H1 must be the operator docs heading, not "AILA".
    await expect(
      page.getByRole("heading", { level: 1, name: /^aila$/i }),
    ).toHaveCount(0);

    // No-error
    await expect(page.getByText(/internal server error/i)).toHaveCount(0);

    await page.screenshot({
      path: `${SHOTS}/D-33-docs-locked-sections.png`,
      fullPage: true,
    });
  });
});
