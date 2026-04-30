import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

/**
 * Preflight FE-C / D-19 VERIFIED: The sbd_nfr module contributes the
 * /assessments route via its own routes.tsx. This test asserts the route
 * registration exists so Plan 176a-02's D-09 redirect (/sbd_nfr/documents →
 * /assessments) lands on a live page, not a 404. No stub component is
 * introduced because the real page already ships.
 *
 * If the module route registration moves, this test breaks loudly and
 * reminds the operator to re-verify before shipping the redirect.
 */

const SBD_NFR_ROUTES = resolve(
  __dirname,
  "..",
  "..",
  "..",
  "..",
  "src",
  "aila",
  "modules",
  "sbd_nfr",
  "frontend",
  "routes.tsx",
);

describe("AssessmentsPage (D-19 verify)", () => {
  it("sbd_nfr module registers /assessments -> AssessmentsListPage", () => {
    const text = readFileSync(SBD_NFR_ROUTES, "utf8");
    expect(text).toContain('path: "/assessments"');
    expect(text).toContain("AssessmentsListPage");
  });
});
