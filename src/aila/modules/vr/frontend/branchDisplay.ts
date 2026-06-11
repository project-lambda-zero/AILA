/**
 * Branch display-name helper — single source of truth for the
 * `persona_voice → human label` mapping the UI renders in branch
 * lists, tree nodes, evidence-graph nodes, and reactive labels.
 *
 * Background. Migration 064 made
 * `vr_investigation_branches.persona_voice` NOT NULL with default
 * `'unspecified'`, after W3 E4 §177/§178/§180 closed every writer
 * site that previously left it NULL. This helper is therefore
 * defense-in-depth: a legacy row, a future writer drift, or a
 * back-fill that pre-dates the migration can still surface a null
 * or marker value, and we want a single rendering choice instead
 * of four duplicate fallbacks across the codebase.
 *
 * Replaces (closes §181 — duplicate-fallback drift):
 *   - `queries.ts:useBranchLabel`
 *   - `screens/BranchTreePage.tsx` ReactFlow node label
 *   - `screens/EvidenceGraphPage.tsx` graph node label
 *
 * Closes §176 (literal "branch" string in the UI), §179 (writer
 * fallback would still render under this helper as
 * "Unnamed branch" rather than "branch"), and §54 (consistent
 * label after pause/resume mutation invalidation).
 */
import type { VRBranchSummary } from "./types";

/**
 * Title-cased label for each canonical persona name. Static
 * lookup table — every value the LLM router picks lives here.
 */
const PERSONA_LABEL: Record<string, string> = {
  halvar: "Halvar",
  noor: "Noor",
  maddie: "Maddie",
  yuki: "Yuki",
  renzo: "Renzo",
  wei: "Wei",
};

/**
 * Writer-side markers that map to one "Unnamed branch" label.
 * `unspecified` is the migration 064 NOT NULL default for legacy
 * NULL backfill; `fork_unnamed` is what the operator-initiated
 * fork endpoint writes when the operator skipped the persona
 * picker.
 */
const UNNAMED_MARKER: Record<string, true> = {
  unspecified: true,
  fork_unnamed: true,
};

const MERGE_MARKER = "merge_result";  // §177 — merge result rows
const UNNAMED_LABEL = "Unnamed branch";

/**
 * Human-readable label for one branch.
 *
 * Mapping:
 *   - halvar/noor/maddie/yuki/renzo/wei  → Title-Cased persona name
 *   - `merge_result`                     → "Merged"
 *   - `fork_unnamed` / `unspecified`     → "Unnamed branch"
 *   - any other non-empty string         → returned verbatim
 *   - null / undefined / empty string    → "Unnamed branch"
 *
 * Does NOT append the `@t{fork_at_turn}` suffix — callers that need
 * to disambiguate siblings spawned by the same persona compose:
 *
 *     formatBranchDisplayName(b) + (b.fork_at_turn != null ? ` @t${b.fork_at_turn}` : "")
 */
export function formatBranchDisplayName(branch: VRBranchSummary): string {
  const raw = (branch.persona_voice ?? "").trim();
  if (raw === "") return UNNAMED_LABEL;
  if (PERSONA_LABEL[raw] !== undefined) return PERSONA_LABEL[raw];
  if (raw === MERGE_MARKER) return "Merged";
  if (UNNAMED_MARKER[raw] === true) return UNNAMED_LABEL;
  return raw;
}
