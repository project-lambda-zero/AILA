import type { TestRunnerConfig } from "@storybook/test-runner"
import { waitForPageReady } from "@storybook/test-runner"

/**
 * Storybook test-runner configuration for visual regression screenshots (D-23).
 *
 * Uses Playwright's `toHaveScreenshot` to capture baseline images for all stories.
 * Baselines are stored at `frontend/.storybook/__snapshots__/*.png` and committed to git.
 *
 * First run creates baselines. Subsequent runs diff against them with a 1% threshold.
 *
 * Usage:
 *   # Start Storybook in one terminal:
 *   npm run storybook
 *
 *   # In another terminal — create/update baselines:
 *   npm run test-storybook -- --update-snapshot
 *
 *   # In CI — compare against baselines:
 *   npm run test-storybook
 */
const config: TestRunnerConfig = {
  async postVisit(page, context) {
    // Wait for all animations, fonts and async content to settle
    await waitForPageReady(page)

    // Capture visual regression screenshot keyed by story ID
    await expect(page).toHaveScreenshot(`${context.id}.png`, {
      // 1% pixel difference threshold for minor anti-aliasing variation
      threshold: 0.01,
      // Allow up to 50 differing pixels for sub-pixel rendering differences
      maxDiffPixels: 50,
    })
  },
}

export default config
