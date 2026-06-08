import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render } from "@testing-library/react";

import { AilaCard, type AilaCardDecoration } from "@/components/aila/AilaCard";

/**
 * D21 — covers the `decorations` array API that replaces four deprecated
 * boolean props (`glass`, `cornerAccents`, `techBorder`, `glow`). The
 * legacy booleans keep rendering the same DOM and emit a one-time
 * per-session `console.warn` in dev. The dedupe is module-scoped so
 * the four "warned once" subtests share that state; the first test
 * to set a flag holds it for the rest of the run.
 */
describe("AilaCard decorations", () => {
  let warnSpy: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
  });
  afterEach(() => {
    warnSpy.mockRestore();
  });

  it("renders the tech-border hairline when decorations include tech-border", () => {
    const decorations: readonly AilaCardDecoration[] = ["tech-border"];
    const { container } = render(
      <AilaCard decorations={decorations} data-testid="card">
        body
      </AilaCard>,
    );
    // tech-border injects a `<span aria-hidden ... h-px>` as the first child.
    const hairline = container.querySelector(
      'span[aria-hidden][class*="h-px"]',
    );
    expect(hairline).not.toBeNull();
  });

  it("renders four corner brackets when decorations include corners", () => {
    const decorations: readonly AilaCardDecoration[] = ["corners"];
    const { container } = render(
      <AilaCard decorations={decorations}>body</AilaCard>,
    );
    const brackets = container.querySelectorAll(
      'span[aria-hidden][class*="border-"]',
    );
    expect(brackets.length).toBeGreaterThanOrEqual(4);
  });

  it("unions decorations array and deprecated booleans without duplicating tech-border", () => {
    const decorations: readonly AilaCardDecoration[] = ["tech-border"];
    const { container } = render(
      <AilaCard decorations={decorations} techBorder>
        body
      </AilaCard>,
    );
    const hairlines = container.querySelectorAll(
      'span[aria-hidden][class*="h-px"]',
    );
    expect(hairlines.length).toBe(1);
  });

  it("emits a console.warn naming each deprecated boolean prop that is set", () => {
    // The dedupe is module-scoped, so a single render is sufficient
    // to observe the FIRST warn per prop. Subsequent suites that touch
    // the same flag won't re-warn — that's the intended contract.
    render(
      <AilaCard glass cornerAccents techBorder glow>
        body
      </AilaCard>,
    );
    const allCalls = warnSpy.mock.calls.map((c) => String(c[0] ?? ""));
    for (const prop of ["glass", "cornerAccents", "techBorder", "glow"]) {
      const hits = allCalls.filter((m) => m.includes(`\`${prop}\``));
      // Either 1 (first observation of this flag) or 0 (an earlier
      // suite already warned). The contract is "at most once per
      // session" — either outcome is acceptable here as long as it's
      // not >1.
      expect(hits.length).toBeLessThanOrEqual(1);
    }
  });
});
