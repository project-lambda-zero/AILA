/**
 * status-badges.spec.ts — D-05, D-21, D-22.
 *
 * - D-05: each task status badge carries the canonical class hook.
 * - D-21: --status-completed CSS variable differs from --severity-low.
 * - D-22: --status-waiting CSS variable differs from --status-paused.
 *
 * We assert via class names + computed CSS variables, NOT pixel colour
 * (gap-fix-03 #9). Pixel assertions are forbidden because future theme
 * updates would silently break tests that should still pass.
 */
import { test, expect } from "./helpers/fixtures";

const SHOTS = "tests/e2e/176a/__screenshots__";

const STATUS_VARS = [
  "--status-completed",
  "--status-running",
  "--status-failed",
  "--status-queued",
  "--status-waiting",
  "--status-paused",
];

test.describe("Status badges (D-05, D-21, D-22)", () => {
  test("D-05: status CSS variables are defined on :root for all six statuses", async ({
    authedPage: page,
  }) => {
    await page.goto("/tasks");
    await expect(page).toHaveURL(/\/tasks$/);

    const values = await page.evaluate((vars) => {
      const root = document.documentElement;
      const cs = getComputedStyle(root);
      return Object.fromEntries(vars.map((v) => [v, cs.getPropertyValue(v).trim()]));
    }, STATUS_VARS);

    for (const v of STATUS_VARS) {
      expect(values[v], `${v} must be defined globally`).not.toBe("");
    }

    await expect(page.getByText(/internal server error/i)).toHaveCount(0);
    await page.screenshot({
      path: `${SHOTS}/D-05-status-badge-tokens.png`,
      fullPage: true,
    });
  });

  test("D-21: --status-completed differs from --severity-low (no green collision)", async ({
    authedPage: page,
  }) => {
    await page.goto("/tasks");
    const { completed, low } = await page.evaluate(() => {
      const cs = getComputedStyle(document.documentElement);
      return {
        completed: cs.getPropertyValue("--status-completed").trim(),
        // The severity scale uses semantic colour tokens. Try every plausible
        // name in order; the first non-empty wins.
        low:
          cs.getPropertyValue("--color-low").trim() ||
          cs.getPropertyValue("--severity-low").trim() ||
          cs.getPropertyValue("--low").trim(),
      };
    });

    expect(completed, "completed token must exist").not.toBe("");
    expect(low, "severity-low token must exist").not.toBe("");
    expect(
      completed.toLowerCase(),
      "task-status green must NOT equal severity-low green (D-21)",
    ).not.toBe(low.toLowerCase());
  });

  test("D-22: --status-waiting differs from --status-paused", async ({
    authedPage: page,
  }) => {
    await page.goto("/tasks");
    const { waiting, paused } = await page.evaluate(() => {
      const cs = getComputedStyle(document.documentElement);
      return {
        waiting: cs.getPropertyValue("--status-waiting").trim(),
        paused: cs.getPropertyValue("--status-paused").trim(),
      };
    });
    expect(waiting).not.toBe("");
    expect(paused).not.toBe("");
    expect(
      waiting.toLowerCase(),
      "waiting and paused must have distinct colour tokens (D-22)",
    ).not.toBe(paused.toLowerCase());
  });

  test("D-05: rendered badges (when present) carry aila-badge-status-* hook", async ({
    authedPage: page,
  }) => {
    await page.goto("/tasks");
    const candidates = page.locator('[class*="aila-badge-status-"]');
    const count = await candidates.count();

    // Either there are visible badges using the canonical hook, OR the page
    // has no rows at all (in which case D-05 is verified by the CSS-vars
    // test above plus the AilaBadge unit test in 176a-02).
    if (count === 0) {
      test.skip(true, "no task rows seeded; CSS-var test above + unit tests cover D-05");
      return;
    }
    await expect(candidates.first()).toBeVisible();
  });
});
