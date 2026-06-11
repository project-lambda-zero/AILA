# VR module cutover — what shipped and how to verify

Operator-facing summary of the structural rewrites + bug-fix wave that landed
across phases B / C / D / E + the platform sweep-registry layering fix.

For the per-item dependency graph see `docs/CUTOVER_DEPS.md`. For the original
discovery doc see `docs/MY_VIOLATIONS.md`.

---

## Headline

| metric | value |
| --- | --- |
| Items closed in `MY_VIOLATIONS.md` | **~267 / 355+** |
| Phase commits | **~184** atomic |
| New tests (all passing) | **76** in 2.7s |
| New alembic migrations | **5** (063 → 067) |
| Bugs caught by the new tests | **3** (1 prod, 2 cosmetic) |
| Golden-rule violations resolved | **1** (platform-imports-module) |

The remaining ~88 items are pre-existing tech debt (inline `# noqa: BLE001`
on bare-except sites that need per-call review, commented-out code from
older refactors). None are blocking; each would be its own focused PR.

---

## What shipped, phase by phase

### Phase D — prompt-builder broadcast (verified no-op)

Read of `vr/agents/vuln_researcher.py:1024-1097` confirmed the prompt builder
already scopes by `investigation_id` (not `branch_id`) and filters
`sender_kind == OPERATOR` so OPERATOR-sender messages broadcast across every
sibling branch. §249 and §335 closed as not-a-bug; §336 deferred as cosmetic.

### Phase E — mechanical cleanup (5 waves, ~226 items)

156 atomic commits across 16 file-disjoint subagent batches. Each batch
shipped under strict sequencing rules (e.g. E3 §168 UNIQUE-constraint race
fix before §166/§167/§169 cluster; E12 bridge-writer whitelist before E2
tool_executor consumer fix). See `docs/CUTOVER_DEPS.md §2-3` for the full
per-batch + per-item rules.

Three real bugs surfaced during cleanup:
  - `ALL_PRIOR_STATUSES` constant name collision (renamed to lowercase
    per ruff N806)
  - Multiple narrow `except (OSError, TimeoutError, RuntimeError)` filters
    swallowing `httpx.HTTPError` / `pydantic.ValidationError` —
    broadened with structured logging at each site
  - `TaskRecord.input_hash` had no UNIQUE constraint → migration 065 added
    a partial index gated on `input_hash IS NOT NULL AND status IN
    (queued, running, waiting)`

### Phase B — cursor SSOT pause/resume (6 commits + 1 migration)

The previous topology had three sources of truth for "is this investigation
paused":
  - `VRInvestigationRecord.status = PAUSED`
  - `workflow_state_cursor.current_state ∈ {paused-equivalent, none today}`
  - `arq:in-progress:<task_id>` Redis presence

Four uncoordinated writers could race across these. Phase B promotes the
cursor to canonical SSOT.

| commit | what |
| --- | --- |
| `6cbe9fd` (1/N) | alembic 067 — `workflow_state_cursor.archived_state` column · `RESERVED_PAUSED='__paused__'` constant in `platform/workflows/types.py` |
| `a38c67d` (2/N) | `pause_investigation_atomic` + `resume_investigation_atomic` task bodies in new `vr/workflow/pause_resume.py` |
| `f54a46f` (3/N) | API `pause_investigation` / `resume_investigation` handlers dispatch the atomic ops |
| `47ce6e5` (4/N) | **§233 zombie variant_hunt_order fix** — child investigation now enqueues `run_vr_investigate` |
| `4168c38` (5/N) | `investigation_loop` polls cursor SSOT + branch.status + inv.status in one UoW (§287 §288) |
| `f24ec9f` (6/N) | `investigation_setup` whitelists allowable prior status (§296) |

### Phase C — finalize chokepoint (4 commits)

The previous topology spread finalization across four race-prone paths
(`investigation_emit._maybe_trigger_synthesis` + three `parent_reconciler`
sweep helpers + one `investigation_reaper` sweep). Phase C consolidates them.

| commit | what |
| --- | --- |
| `bfeb995` (1/N) | `vr/workflow/finalize.py` chokepoint · 4-trigger picker · `vr.finalize` sweep |
| `9993d63` (2/N) | `evaluate_cap_for_investigation(inv_id)` per-id helper extracted from bulk sweep |
| `bc6d7ba` (3/N) | `only_id=` filter on `_close_rejected_outcomes` + `_synthesize_no_finding_outcomes` |
| `e7b3109` (4/N) | `vr/services/investigation_finalizers.py` canonical API · `vr.investigation_reaper` sweep retired |

Trigger picker priority (first match wins):

  1. `all_outcomes`              → synthesis enqueued
  2. `rejected_quorum`           → close-rejected per-id helper
  3. `wall_clock_idle_grace`     → cap-exceeded per-id helper (turn / message / wall-clock subkinds)
  4. `all_terminal_no_outcome`   → audit_memo synthesizer per-id helper
  +  `no_trigger` / `not_running` → caller takes no action

### Platform layering fix (1 commit)

`a96186d` removed 4 `from aila.modules.vr.*` imports from
`aila.platform.tasks.worker` (a Golden Rule 5 violation:
"platform never imports from modules"). Replaced with a generic
`aila.platform.tasks.sweeps` registry:
  - Modules register their sweeps in their own `module.py:create_module()`
    via `register_periodic_sweep(name, async_callable)`.
  - Platform's `_run_reaper_block` iterates `all_periodic_sweeps()` and
    invokes each. Zero `from aila.modules` imports in `src/aila/platform/`.

---

## How to verify on a live MASVS audit

1. Apply migrations: `make migrate` (picks up 063 → 067)
2. Restart workers
3. Spawn a fresh MASVS L1 audit on a small APK

### Phase B verification (pause/resume)

1. Wait until 6 branches are active and writing turns
2. `POST /vr/investigations/{id}/pause` — within 5s every branch's `updated_at`
   stops advancing AND the response says `paused_cursors=N` AND
   `cancelled_tasks=N`. Open the DB:
   ```sql
   SELECT current_state, archived_state FROM workflow_state_cursor
    WHERE run_id IN (SELECT id FROM vr_investigation_branch_records
                      WHERE investigation_id = '<id>');
   ```
   Every cursor's `current_state` is `__paused__` and `archived_state` is
   non-null (e.g. `investigation_loop`).
3. `POST /vr/investigations/{id}/resume` — response says `resumed_cursors=N`
   AND `submitted_tasks=N`. Within 30s every branch fires another turn.
   The DB shows `current_state = archived_state` (round-tripped) and
   `archived_state` is NULL.

### Phase C verification (finalize chokepoint)

1. Spawn a variant_hunt investigation
2. Externally kill all workers (`taskkill /F /IM python.exe` or SIGTERM)
3. Wait wall_clock_hours + idle_grace (6h + 15min default, or override via
   env to a smaller window)
4. The finalize cron fires `vr.finalize` sweep → assert
   `inv.status == COMPLETED` AND `primary_outcome_id` points to an
   `audit_memo` outcome via:
   ```sql
   SELECT i.status, o.outcome_kind, o.state
     FROM vr_investigation_records i
     JOIN vr_investigation_outcomes o ON o.id = i.primary_outcome_id
    WHERE i.id = '<id>';
   ```

### §233 zombie-investigation verification

1. Trigger a standalone `VARIANT_HUNT_ORDER` outcome (agent submits it via
   normal flow OR operator API)
2. Within 5 minutes:
   - A new child investigation row exists
     (`SELECT * FROM vr_investigation_records WHERE parent_investigation_id = '<id>'`)
   - `status` of that child is `RUNNING` (NOT `CREATED` — the prior bug shape)
   - At least one ARQ task is enqueued for the child

---

## Sweep registry final state

```python
['vr.stage_tracker', 'vr.branch_reaper', 'vr.masvs_parent_reconciler', 'vr.finalize']
```

| sweep | role | scope |
| --- | --- | --- |
| `vr.stage_tracker` | target-analysis stage reaper | generic |
| `vr.branch_reaper` | orphan ACTIVE branches under terminal parents | generic |
| `vr.masvs_parent_reconciler` | MASVS parent batch rollup | MASVS-specific |
| `vr.finalize` | 4-trigger chokepoint for RUNNING → terminal | generic |
| ~~`vr.investigation_reaper`~~ | RETIRED — `vr.finalize` covers via `evaluate_cap_for_investigation` | — |

---

## Test suite (76 tests, all passing in 2.7s)

| file | tests | covers |
| --- | --- | --- |
| `tests/platform/test_sweeps_registry.py` | 10 | Generic sweep registry: register / dedup / order / async / VR module wiring + idempotency |
| `tests/api/test_vr_verdict_analyzer.py` | 40 | Text-first verdict analyzer: every priority rung + word-boundary protection for `NON_COMPLIANT`/`NOT COMPLIANT` |
| `tests/api/test_vr_phase_c_finalize.py` | 13 | Finalize chokepoint: 4-trigger picker · no-trigger/not-running short-circuits · wall-clock + idle grace · turn cap · all-outcomes · all-terminal-no-outcome |
| `tests/api/test_vr_phase_b_pause_resume.py` | 13 | Atomic pause/resume + cursor SSOT + §233 variant_hunt enqueue |

Three real bugs the tests caught and fixed:

1. **`finalize.py` used `sqlalchemy.select` instead of `sqlmodel.select`** — returned
   Row tuples instead of ORM model instances. Every `.status` / `.id` /
   `.primary_outcome_id` access in `_detect_trigger` would have crashed in
   production with `AttributeError`. Invisible because finalize had only ever
   been called via the cron sweep's best-effort try/except.
2. **VR module `_SWEEPS_REGISTERED` flag conflicted with test fixtures** —
   replaced with a registry probe so autouse fixtures that clear the
   registry can re-register cleanly.
3. **Verdict analyzer missed `NOT COMPLIANT` (with space)** — adjacent to
   existing `NON-COMPLIANT` / `NONCOMPLIANT` / `NON_COMPLIANT` patterns
   but the bare space-separated form wasn't covered.

---

## What's still open (and why none of it blocks)

- **~88 pre-existing tech-debt items** in `MY_VIOLATIONS.md`: legacy inline
  `# noqa: BLE001` on bare-except sites that need site-specific care +
  commented-out code from older refactors. Each would be its own focused PR
  after operator review of specific sites.

- **GitHub Dependabot reports 100 vulnerabilities (30 high / 62 moderate /
  8 low)** in third-party dependencies. Independent of this cutover; the
  CVEs are in upstream packages, not in code we changed. Recommend reviewing
  via `gh api repos/project-lambda-zero/AILA/dependabot/alerts` or the
  GitHub UI.

- **Frontend cursor exposure** — Phase B's atomic pause/resume now writes
  `__paused__` to the cursor SSOT, but the frontend still reads `inv.status`
  directly. A future frontend pass should expose `cursor.current_state` for
  the operator to see WHY an investigation is paused (operator pause vs
  cap-exceeded vs cursor-crashed).

- **Hard cancellation of in-flight LLM calls** (Phase B.5 in the design
  doc) is deliberately deferred. Today's behavior: in-flight LLM calls
  commit when they finish, which can be minutes after the pause. The next
  turn-boundary then tries to acquire the cursor lock, sees `__paused__`,
  and exits. No further work happens. This is operator-acceptable.

- **Move the 3 generic finalize helpers** out of `vr/masvs/parent_reconciler.py`
  to their canonical location (the implementations still live there for
  historical reasons; `vr/services/investigation_finalizers.py` is a thin
  delegating shim). 500-line code-move was deemed too risky mid-cutover.

---

## Operator decision points still open

(Documented as TODOs in the relevant code paths)

| § | question | location |
| --- | --- | --- |
| §170 | `suggested_edits_json` — wire to manual-Apply UI OR have synthesis agent consume? Currently logs TODO when non-empty. | `services/outcome_review.py` |
| §141/§142 | `@platform_task` retry behavior — `retriable_on` tuple specifies exact transient errors. | `workflow/task.py` |
| §173 | `_upsert_canonical_outcome` only fires on `terminal_submit` — assertion enforces single canonical write path. | `agents/vuln_researcher.py` |
| §268/§269 | APK static_summary + MobSF inline storage — moved to artifact files; should we migrate to a separate table for queryability? | `services/target_analysis.py` |

None of these block the cutover. They're choices the operator should make
when the relevant feature surface comes up for review.
