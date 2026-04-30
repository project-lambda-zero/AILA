/**
 * module-id.spec.ts — D-06, D-15.
 *
 * - D-06: TaskQueue passes the real module_id, NOT the literal "__platform__".
 *   Backend constant `MODULE_ID_PLATFORM` is the source of truth (BE-G).
 * - D-15: frontend has no display-time `__platform__` fallback.
 *
 * Asserts that no rendered Tasks page text contains the literal
 * "__platform__" substring.
 */
import { test, expect } from "./helpers/fixtures";

const SHOTS = "tests/e2e/176a/__screenshots__";

test.describe("module_id rendering (D-06, D-15)", () => {
  test("D-06 + D-15: 'Tasks' page DOM contains no '__platform__' literal", async ({
    authedPage: page,
  }) => {
    await page.goto("/tasks");
    await expect(page).toHaveURL(/\/tasks$/);
    await expect(
      page.getByRole("heading", { level: 1, name: /tasks/i }).first(),
    ).toBeVisible({ timeout: 10_000 });

    const body = await page.locator("body").innerText();
    expect(
      body.includes("__platform__"),
      "no '__platform__' literal should reach the rendered DOM",
    ).toBe(false);

    await expect(page.getByText(/internal server error/i)).toHaveCount(0);
    await page.screenshot({
      path: `${SHOTS}/D-06-module-id.png`,
      fullPage: true,
    });
  });
});
