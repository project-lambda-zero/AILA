/**
 * findings-kanban.spec.ts
 *
 * E2E tests for the /vulnerability/findings Kanban view.
 * Uses REAL PostgreSQL backend — no mocks.
 *
 * Coverage:
 *   - Kanban view renders 5 workflow-state columns
 *   - Each column has the correct header label
 *   - ?view=kanban URL param activates kanban on load
 *   - Table button navigates back to table view
 */
import { test, expect } from "@playwright/test";

import { getTokens, injectAuthState, type TokenPair } from "../helpers/auth";

const WORKFLOW_COLUMNS = ["New", "Investigating", "Mitigated", "Verified", "Closed"];

test.describe("Findings Kanban", () => {
  let tokens: TokenPair;

  test.beforeAll(async ({ request }) => {
    tokens = await getTokens(request);
  });

  test("kanban view renders via view toggle", async ({ page }) => {
    await injectAuthState(page, tokens);
    await page.goto("/vulnerability/findings");

    await page.getByRole("button", { name: "Kanban view" }).click();

    await expect(page.locator('[data-testid="findings-kanban"]')).toBeVisible({
      timeout: 10_000,
    });
  });

  test("kanban URL param activates kanban on load", async ({ page }) => {
    await injectAuthState(page, tokens);
    await page.goto("/vulnerability/findings?view=kanban");

    await expect(page.locator('[data-testid="findings-kanban"]')).toBeVisible({
      timeout: 10_000,
    });
  });

  test("all 5 workflow-state column headers are visible", async ({ page }) => {
    await injectAuthState(page, tokens);
    await page.goto("/vulnerability/findings?view=kanban");

    await expect(page.locator('[data-testid="findings-kanban"]')).toBeVisible({
      timeout: 10_000,
    });

    for (const label of WORKFLOW_COLUMNS) {
      await expect(
        page.locator(`[data-testid="kanban-column-${label.toLowerCase()}"]`),
      ).toBeVisible({ timeout: 5_000 });
    }
  });

  test("kanban columns have correct aria-labels or text labels", async ({ page }) => {
    await injectAuthState(page, tokens);
    await page.goto("/vulnerability/findings?view=kanban");

    await expect(page.locator('[data-testid="findings-kanban"]')).toBeVisible({
      timeout: 10_000,
    });

    // Column headings rendered as text
    for (const label of WORKFLOW_COLUMNS) {
      await expect(page.getByText(label, { exact: true }).first()).toBeVisible({
        timeout: 5_000,
      });
    }
  });

  test("returning to table view hides kanban", async ({ page }) => {
    await injectAuthState(page, tokens);
    await page.goto("/vulnerability/findings?view=kanban");

    await expect(page.locator('[data-testid="findings-kanban"]')).toBeVisible({
      timeout: 10_000,
    });

    await page.getByRole("button", { name: "Table view" }).click();

    await expect(page.locator('[data-testid="findings-kanban"]')).not.toBeVisible({
      timeout: 5_000,
    });
  });
});
