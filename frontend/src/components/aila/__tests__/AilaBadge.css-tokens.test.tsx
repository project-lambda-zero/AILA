import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * jsdom does not run the full CSS pipeline (tailwind + @layer), so we cannot
 * reliably read resolved `getComputedStyle(document.documentElement)
 * .getPropertyValue('--status-completed')` values. Instead we verify the
 * CSS variable NAMES are declared in the canonical stylesheet (FE-E), and
 * that the helper classes reference `var(--status-*)` rather than hardcoded
 * hex pixel values (gap-fix-02 #4).
 */

const GLOBALS_CSS_PATH = resolve(
  __dirname,
  "..",
  "..",
  "..",
  "styles",
  "globals.css",
);

const CSS_TEXT = readFileSync(GLOBALS_CSS_PATH, "utf8");

describe("status-* CSS tokens", () => {
  const required = [
    "--status-completed",
    "--status-running",
    "--status-failed",
    "--status-queued",
    "--status-waiting",
    "--status-paused",
  ];

  for (const token of required) {
    it(`declares ${token}`, () => {
      expect(CSS_TEXT).toContain(token);
    });
  }

  it("status helper classes reference var(--status-*)", () => {
    for (const status of ["completed", "running", "failed", "queued", "waiting", "paused"]) {
      const re = new RegExp(
        `\\.aila-badge-status-${status}[^{]*\\{[^}]*var\\(--status-${status}\\)`,
        "s",
      );
      expect(CSS_TEXT).toMatch(re);
    }
  });

  it("status classes do not use raw hex colours in their declarations", () => {
    // Grab only the .aila-badge-status-* rule blocks and check those for hex.
    const matches = CSS_TEXT.match(/\.aila-badge-status-\w+\s*\{[^}]+\}/g) ?? [];
    expect(matches.length).toBeGreaterThanOrEqual(6);
    for (const block of matches) {
      expect(block).not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
    }
  });
});
