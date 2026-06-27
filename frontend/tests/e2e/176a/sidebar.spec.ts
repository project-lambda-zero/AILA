/**
 * sidebar.spec.ts -- D-01, D-02, D-27.
 *
 * - D-01: sidebar renders the "Console" label (the rename from "Scans").
 * - D-02: sidebar DOM has zero nested <li> hydration violations.
 * - D-27: persist a DOM snapshot for audit trail.
 *
 * Every test asserts URL + render + no-error per D-30.
 */
import { writeFileSync } from "node:fs";
import { join } from "node:path";

import { test, expect } from "./helpers/fixtures";

const SHOTS = "tests/e2e/176a/__screenshots__";

test.describe("Sidebar (D-01, D-02, D-27)", () => {
  test("D-01 + D-02 + D-27: Console label visible, no nested <li>, snapshot saved", async ({
    authedPage: page,
  }) => {
    await page.goto("/");

    // (a) URL
    await expect(page).toHaveURL(/\/$|\/$/);

    // (b) Render -- sidebar present, "Console" label visible.
    const consoleEntry = page.getByRole("link", { name: /console/i }).first();
    await expect(consoleEntry).toBeVisible({ timeout: 15_000 });

    // Docs entry exists (D-03 cross-check).
    await expect(page.getByRole("link", { name: /docs/i }).first()).toBeVisible();

    // The old "Scans" label should be GONE (D-01 acceptance).
    await expect(page.getByRole("link", { name: /^scans$/i })).toHaveCount(0);

    // (c) D-02: count nested <li> elements.
    const nestedLi = await page.locator("li li").count();
    expect(nestedLi, "no nested <li> hydration violations").toBe(0);

    // (c) No-error sentinel.
    await expect(page.getByText(/internal server error/i)).toHaveCount(0);
    await expect(page.getByText(/something went wrong/i)).toHaveCount(0);

    // (d) Screenshot.
    await page.screenshot({
      path: `${SHOTS}/D-01-sidebar-console-label.png`,
      fullPage: true,
    });

    // D-27: persist DOM snapshot for audit trail.
    const navHtml = await page.locator("nav, aside").first().innerHTML().catch(() => "");
    writeFileSync(
      join(SHOTS, "D-02-dom-snapshot.html"),
      `<!-- D-02 / D-27 sidebar audit snapshot -->\n${navHtml}\n`,
      { encoding: "utf-8" },
    );
  });
});
