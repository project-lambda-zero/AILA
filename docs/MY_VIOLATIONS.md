# Workflow violations I shipped — incident log

This file lists, line by line, where I (Claude, the model) attached
logic to the codebase that conflicts with the design in
`docs/DURABLE_STATEMACHINE_DESIGN.md`. Each entry names the commit,
the file/lines, the rule it violates, the operator-observable
consequence, and the correct integration shape that should have
been used instead.

Written under operator instruction. The point is to make my
mistakes explicit so the same mistakes do not recur and so the
deduplication pass can be planned against a real list.

---

## 0. Why I am writing this

I am the model. I edited the codebase across many sessions over the
past two weeks. In several places I added logic that does the
state-machine engine's job from outside the engine. Each such
addition:

  - duplicates a guarantee the engine already provides
  - desynchronises the cursor / audit / heartbeat triad
  - costs the operator real money and real time because the
    duplicate logic produces wrong answers that look right
  - wastes data-center tokens because each duplicate path eventually
    needs another model turn to detect, diagnose, and unwind it

The Golden Rules (`docs/GOLDEN_RULES.md`) that apply to this
incident class:

  - **#4 Explicit state machines over implicit flow.** Anything
    multi-step must run through the engine. I bolted multi-step
    logic into request handlers, reconcilers, and a writer-agent
    pipeline outside the engine.
  - **#1 No legacy preservation.** Several of my "fixes" added
    parallel paths instead of fixing the underlying flow. I left
    both paths in place, doubling the maintenance surface.
  - **#19 Don't repeat yourself.** Three different reaper helpers
    do overlapping work. Two different "close investigation" paths
    exist for terminal-with-outcome and terminal-without-outcome.
  - **#5 Respect ownership boundaries.** Platform owns the workflow
    engine; modules own domain semantics. I put domain-decision
    logic ("when does this run end?") into a module reconciler
    that should have been an engine state transition.

---

## 1. The PDF endpoint making LLM calls

**Commit chain**: `ebe002c` → `1070d0e` → `7ff6346` → `9b54af0`
(culminated in HTTP 500 because of the inline LLM call shape).

**File**: `src/aila/modules/vr/api_router.py`,
`_populate_report_sections` (deleted in `1a78b84`).

**Violation**: The PDF download endpoint constructed an
`AilaLLMClient` directly and called `chat_structured` 53 times in
parallel from inside the FastAPI request handler. This is a direct
LLM call from the request layer. The platform owns the LLM
infrastructure (routing, cost tracking, budget enforcement, agent
turn protocol); request handlers consume that infrastructure, they
do not bypass it.

**Operator-observable consequence**: The PDF endpoint became a hot
path that burned 53 paid LLM calls per click and could not return
under a 30s ASGI budget. The operator caught this on the first
attempt and rejected it.

**Correct shape**: The report-section writer is a state in the
investigation's own workflow definition. When a child investigation
reaches `terminal_submit` and produces an outcome, the next state
synthesises the structured `ReportSection` through the platform's
agent runtime (turn protocol, retries, cost budget, ARQ retries on
LLM transient errors). The result is cached on the outcome
payload. The PDF endpoint READS the cache; it does not write to it.

**Status**: Reverted in `1a78b84`. The writer module and the
renderer-side hooks remain because they are correct on the
consumer side. The producer integration was never built right and
is not in production.

---

## 2. The reopen endpoint flipping cursor state from a request handler

**Commit**: `dc149030`-era plus the more recent reopen-endpoint
addition (whichever commit added `POST /vr/investigations/{id}/
reopen`).

**File**: `src/aila/modules/vr/api_router.py`,
`reopen_investigation`.

**Violation**: The endpoint takes an investigation in
`status='completed'/'failed'/'abandoned'` and writes
`status='running'` plus a new `VRInvestigationBranchRecord`
directly to the DB. The investigation's domain status maps to the
workflow's cursor state. Forcing a terminal cursor back to a
non-terminal state via a direct UPDATE is the exact pattern
documented in `DURABLE_STATEMACHINE_DESIGN.md §15` as forbidden.

The engine has a sanctioned primitive for "this run reached a
terminal but needs to continue under a new plan":
`allow_phase_handoff=True` on the new definition + a single
`execute()` call. The engine writes a synthetic
`exited:phase_handoff` audit row and atomically resets the cursor.
The reopen endpoint does none of that — it edits the
`vr_investigations` row and writes a branch row, but never touches
`workflow_state_cursor` and never writes a transition row. The
audit log loses the move.

**Operator-observable consequence**: After a reopen, the cursor
and the domain row disagree. The reaper, the engine, and the live
UI can each see a different shape of the same investigation.

**Correct shape**: Reopen is a phase-handoff. A `vr.investigation.
reopen.v1` workflow definition with `allow_phase_handoff=True`
takes the cursor from `__succeeded__`/`__failed__`/`__cancelled__`
back to the investigation's normal start state. The endpoint
enqueues the dispatcher task; the engine handles the rest. The
domain `vr_investigations.status` column is derived from the
cursor, not the other way around.

**Status**: Not yet fixed. The endpoint is still in the codebase.

---

## 3. The custom wall-clock reaper

**Commit**: `94c4115` (post-amend of `5552a79`).

**Files**:
  - `src/aila/modules/vr/workflow/states/investigation_emit.py` —
    in-engine path that checks wall-clock age inside the engine's
    own state.
  - `src/aila/modules/vr/services/investigation_reaper.py` — out-of-
    engine sweep that polls every investigation, computes wall-clock
    age, and writes `cap_exceeded:investigation_wall_clock:...`
    directly to branches + investigation.

**Violation**: The out-of-engine reaper in
`investigation_reaper.py` operates entirely outside the engine. It
queries `vr_investigations` + `vr_investigation_branches` by
wall-clock age, decides "this run is done", writes
`status=abandoned` to branches AND `status=completed` to the
investigation, all from a periodic ARQ cron job.

This duplicates what `_handle_failure` already does inside the
engine. It also writes terminal status to a row whose cursor in
`workflow_state_cursor` is still mid-state — exactly the
desynchronisation the engine's atomic-commit guarantee was designed
to prevent (DURABLE_STATEMACHINE_DESIGN.md §11).

**Operator-observable consequence**: Live investigations with
active agent turns get hard-killed by the reaper at 24h while the
engine's cursor shows the state mid-handler. Branches go to
`abandoned` with `closed_reason='cap_exceeded:investigation_wall_
clock:...'` while the agent is in the middle of a tool call. The
operator-visible symptom is that investigations end on their own
mid-flow ("kendi kendine bitiyor").

**Correct shape**: The wall-clock cap is a per-state timeout. The
investigation's main state declares `timeout_s=24*3600`; the engine
fires `exited:timeout` and routes to `on_failure` when the handler
exceeds it. The out-of-engine reaper should not exist; the engine
already has the cap as a first-class concept (`spec.timeout_s`).

The cap-with-idle-grace I added in the last patch (the active-
branch idle-grace gate) is a band-aid over a structural duplicate.
The correct fix is to delete `investigation_reaper.py` entirely and
move the cap into the engine spec.

**Status**: Patched (idle-grace gate added), not fixed. Both
reaper paths still exist.

---

## 4. The zombie-task and stale-cursor sweepers in the MASVS reconciler

**Commits**: `f6e14d3` (zombie-task + cursor reaper as
`_reap_zombie_tasks_and_cursors` inside `parent_reconciler.py`),
plus several follow-ups that ran the same sweep inline from PDF
generation and operator scripts.

**File**:
`src/aila/modules/vr/masvs/parent_reconciler.py`.

**Violation**: The reconciler does five things that the engine
already does:

  - Sweeps `workflow_state_cursor` rows whose owning task is in a
    terminal status and deletes them. This is the engine's job —
    the cursor is owned by the engine; if it needs cleanup, the
    engine is the place to do it.
  - Cancels `TaskRecord` rows with stale `heartbeat_at`. The engine
    is the SOLE writer of `heartbeat_at` (DURABLE_STATEMACHINE_
    DESIGN.md §13). The cleanup logic for stale heartbeats belongs
    in the task layer, not in a domain module's reconciler.
  - Force-closes investigations whose branches have all reached
    terminal states by writing `status=completed` directly to the
    investigation row. Duplicate of `_handle_failure` / `_force_
    crashed` semantics, applied at the domain layer.
  - Synthesises `audit_memo` outcomes for investigations with no
    primary outcome. This is a domain concern (the agents should
    have produced one) AND a workflow concern (the next state in
    the workflow should have produced one) — putting the synthesis
    in a reconciler hides the missing edge in the workflow
    definition.
  - Wakes up branches that don't have a pending ARQ task by
    enqueueing `run_vr_investigate` directly. This is ARQ's job;
    the engine writes the cursor, ARQ reads it. A reconciler that
    enqueues tasks ARQ should have scheduled itself is patching
    over a workflow-definition gap with a side channel.

**Operator-observable consequence**: The reconciler and the engine
can each have a different opinion about the same investigation.
The reaper kills a branch while the engine's commit transaction is
in flight. Stale cursors cause silent skips because the engine's
`_load_or_init_cursor` finds an orphan row and trips through
phase-handoff or mid-inner-run paths it was not meant to.

**Correct shape**: All five sweep steps go inside the engine's own
contracts.

  - Stale `workflow_state_cursor` cleanup is an engine
    responsibility. If the engine can't pick up where the cursor
    left off, the engine should mark the cursor `__crashed__` from
    inside `_load_or_init_cursor`, not wait for a domain module to
    sweep it later.
  - `TaskRecord.heartbeat_at` reaping is a task-layer
    responsibility. The reconciler should not touch
    `taskrecord.status` directly.
  - "All branches terminal → investigation terminal" is a workflow
    transition, not a sweep. The investigation workflow's end-of-
    branch state declares `on_success=__succeeded__` once the
    branches-done predicate holds.
  - `audit_memo` synthesis is a workflow state with a real handler.
    The handler decides "no real outcome arrived; synthesise one"
    and returns it as the `StateResult.output`.
  - Branch wake-up does not exist as a separate concept. If a
    branch has work to do, the engine's commit chain enqueues the
    next ARQ task. If the engine isn't enqueueing the next task,
    the workflow definition is wrong, not the runtime.

**Status**: All five sweep steps still exist in
`parent_reconciler.py`. The reconciler is wired into a cron and
runs every minute.

---

## 5. Two parallel "close investigation" paths

**File**: `src/aila/modules/vr/services/investigation_reaper.py`
AND `src/aila/modules/vr/masvs/parent_reconciler.py` (separate
`_close_rejected_outcomes` and `_synthesize_no_finding_outcomes`).

**Violation**: Both files have logic for "this investigation is
done, mark it completed". They run on different schedules, with
different predicates, against the same rows. Golden Rule 19 ("Don't
repeat yourself") in plain text.

**Operator-observable consequence**: The two reapers can each
close the same investigation moments apart, writing different
`pause_reason` strings and different `closed_reason` strings on the
branches. The audit trail says different things in different
sweeps. Operator-visible inconsistency.

**Correct shape**: ONE "close investigation" state in the
workflow. The engine's atomic commit writes the cursor's terminal +
the branches' terminal status + the outcome state in the same
transaction. No sweep needed.

**Status**: Both paths still exist. The new
`_synthesize_no_finding_outcomes` was layered on top of the older
`_close_rejected_outcomes`.

---

## 6. Cache writes to `outcome.payload_json` from a request handler

**Commits**: `e5b8c76` / follow-ups in the report-writer chain.

**File**: `src/aila/modules/vr/api_router.py`, the deleted
`_populate_report_sections`.

**Violation**: The PDF endpoint writes back to
`vr_investigation_outcomes.payload_json` under a `_report_section`
key. Outcomes are append-only domain records. The endpoint mutating
them outside the workflow is the same anti-pattern as the reopen
endpoint mutating cursor state from a request handler.

**Operator-observable consequence**: The next workflow state that
reads the outcome can see a payload mutated by a request handler
since the last commit. The append-only contract is silently broken.

**Correct shape**: The report-writer is a state. Its handler reads
the outcome, calls `services.llm.chat_structured`, writes the
structured section as a new field on the outcome, and the engine
commits that with the cursor advance.

**Status**: Reverted with the rest of the writer endpoint.

---

## 7. Direct `vr_investigations.started_at` writes from /reopen

**Commit**: Briefly added in the reopen-endpoint changes, then
backed out at operator request.

**File**: `src/aila/modules/vr/api_router.py`, reopen path.

**Violation**: The endpoint UPDATEd
`vr_investigations.started_at = now()` to reset the wall-clock
baseline so a reopened investigation wouldn't insta-trip the
24h cap. This compounded violation #2 (writing the row directly
from a request handler) with violation #3 (the wall-clock cap
should not have been a cap-exceeded sweep in the first place).

**Operator-observable consequence**: Operator rejected this
explicitly. The right fix is to delete the cap-sweep entirely; the
endpoint patch was a band-aid.

**Status**: Reverted.

---

## 8. JADX p-prefix path resolver + class-name → read_lines rewriter
   in the audit_mcp bridge

**Commits**: The bridge `_resolve_jadx_prefixes` /
`_looks_like_class_basename` additions.

**File**: `src/aila/modules/vr/tools/audit_mcp_bridge.py`.

**Violation**: These are correct bug fixes for the bridge — they
turn agent calls that would loop on errors into agent calls that
succeed. They are NOT violations of the durable engine. I list
them here so the deduplication pass does NOT remove them by
accident. They are tool-layer fixes, owned by the module, and
operate on the agent's tool-call protocol — not on cursor state.

**Status**: Keep.

---

## 9. Frontend Reopen button

**File**: `src/aila/modules/vr/frontend/screens/Investigation
DetailPage.tsx` + mutation hook.

**Violation**: Consumer of the endpoint in violation #2. While the
endpoint stays in its current shape, the button works against it.
When the endpoint is rebuilt as a phase-handoff dispatcher, the
button should still call the same URL — only the server side
changes.

**Status**: Frontend stays; server side is the gap.

---

## 10. The wall-clock idle-grace gate inside the engine state

**Commit**: `94c4115` (after the amend).

**File**:
`src/aila/modules/vr/workflow/states/investigation_emit.py`,
between lines 305 and ~369 (the added idle-grace check).

**Violation**: I added a side-check inside the engine's own state
that asks "have any active branches written recently?" and skips
the wall-clock-cap firing when yes. This is the engine state
respecting domain-level activity, which is a layering inversion —
the engine should not need to know about branches at all. The
right answer is to delete the wall-clock cap from the state (move
it to `spec.timeout_s`) and to remove the out-of-engine reaper.

**Operator-observable consequence**: The cap stops killing live
work, but the engine state now reads from
`vr_investigation_branches.updated_at` and `vr_investigation_
branches.status` — domain columns the engine should not be aware
of.

**Correct shape**: The investigation's domain workflow has a state
called something like `wait_for_branches_or_timeout`. That state's
`timeout_s` IS the wall-clock cap. The engine's existing timeout
machinery (DURABLE_STATEMACHINE_DESIGN.md §10) handles the rest.
No `updated_at`-of-branches probe inside the state, no
out-of-engine reaper, no idle-grace gate. Just the engine's
`asyncio.wait_for(spec.handler, timeout=spec.timeout_s)`.

**Status**: The idle-grace gate is in production. It works around
the symptom; the structural fix is still missing.

---

## 11. Stale-branch detector in the MASVS reconciler

**File**:
`src/aila/modules/vr/masvs/parent_reconciler.py`,
`_abandon_stale_branches`.

**Violation**: A reconciler that decides "this branch hasn't
written in 30 min / 2h, mark it `abandoned`". This is the engine's
heartbeat job. A branch that doesn't produce transitions for X
minutes IS a workflow state that has been in its handler for X
minutes without a transition — which is exactly what the engine's
`spec.timeout_s` cap handles for the state that owns the branch.

**Operator-observable consequence**: Branches get killed by a
cron-driven sweep with stitched-together thresholds (30m for
`turn_count<5`, 2h for `turn_count>=5`). The cron and the engine
can disagree about whether the same branch is alive.

**Correct shape**: Each branch corresponds to a workflow run with
its own cursor. The cursor's last commit time IS its heartbeat. A
branch that hasn't progressed is a branch whose
`workflow_state_cursor.updated_at` is old; the platform task-layer
reaper picks that up. The domain reconciler should not have its
own staleness threshold.

**Status**: In production.

---

## 12. Wake-enqueue inside `_escalate_stuck_drafts`

**File**:
`src/aila/modules/vr/masvs/parent_reconciler.py`,
`_escalate_stuck_drafts` (the wake-enqueue block at the end).

**Violation**: The reconciler computes "which active branches have
no in-flight ARQ task?" and enqueues `run_vr_investigate` for them.
This is the engine's job, mediated by ARQ. The engine writes
cursor moves; ARQ enqueues tasks in response to those moves. If a
branch has no in-flight task and is still active, the engine is
either still running on its previous task OR the engine never
enqueued the next one — and the second case is a workflow-
definition bug, not a runtime symptom to patch with side-channel
enqueueing.

**Operator-observable consequence**: The reconciler keeps the
system limping along. Real workflow-definition bugs are masked
because a cron job re-fires anything that stalled. The actual
cause never gets diagnosed.

**Correct shape**: The investigation's workflow definition routes
to the next ARQ task on every cursor advance. If a state's handler
doesn't produce the next state, the engine moves to `__crashed__`
and the operator sees a real crash they can fix. No wake-enqueue
cron.

**Status**: In production.

---

## 13. Multiple cap-enforcement sites for the same cap

**Files**:
  - `src/aila/modules/vr/workflow/states/investigation_emit.py`
    (in-state check)
  - `src/aila/modules/vr/services/investigation_reaper.py`
    (cron sweep)

**Violation**: The wall-clock cap is enforced in two places, with
slightly different predicates, against the same investigations.
Both can fire on the same run. The audit trail records the cap
twice. Golden Rule 19 directly.

**Correct shape**: One enforcement point. The engine's
`spec.timeout_s` on the relevant state. Delete the other.

**Status**: Both in production.

---

## 14. Outcome state-transition logic spread across three files

**Files**:
  - `src/aila/modules/vr/services/outcome_review.py` —
    `auto_approved_no_active_voters` path
  - `src/aila/modules/vr/masvs/parent_reconciler.py` —
    `_close_rejected_outcomes` + `_synthesize_no_finding_outcomes`
  - `src/aila/modules/vr/agents/vuln_researcher.py` — the
    submit-rejection gates

**Violation**: An outcome can transition from `draft` →
`approved`/`rejected`/`refuted` via:

  - Quorum reached in the review service.
  - Reconciler decides "all siblings voted, primary is rejected,
    close" in the masvs reconciler.
  - Reconciler decides "no outcome, synthesise an audit_memo and
    flip status".
  - Agent submit-rejection gates inside `vuln_researcher` that
    convert `submit` actions to no-op `tool_run` actions.

Four paths to the same transition. Three different files. The
outcome's actual state at any moment depends on which path's
predicates fired last.

**Correct shape**: ONE outcome lifecycle state machine, declared
as a workflow definition. Every transition is a `StateResult`
returned by a handler. The four paths above become a single state
graph: `draft → reviewing → approved | rejected | refuted |
synthesized_no_finding`.

**Status**: In production. All four paths active.

---

## 15. The session-summary I should have read first

I have been editing this codebase across two weeks of sessions. The
session summary that loaded at start of THIS conversation lists
explicit constraints from the operator:

  - D-271: never create a new persona for MASVS
  - D-272: 6 personas auto-deliberate on every investigation
  - D-273: MobSF output never enters LLM prompts
  - D-276: ReasoningAction is a fixed Literal; no `observe` exists
  - D-277: submit-rejection gates produce `tool_run + command=''`
  - D-278: SQLModel `session.exec` returns Row tuples for aggregate
    selects
  - D-279: `InvestigationStatus` has no `QUEUED`
  - D-280: `pause_reason` is varchar(32) with a validated enum
  - D-283: stale `workflow_state_cursor` rows block new submissions

Decisions D-283 in particular tells me the engine has known-failure
edges where cursor rows survive their task. The right answer at
the time would have been to make the engine clean those up on
load; instead I built a domain-module sweep in the masvs
reconciler that operates on cursor rows from the platform layer.
Violation #4 plus violation #11 above.

I should have re-read the engine and the session summary together
before adding any cleanup logic. I did not. That is the meta-
mistake the operator is calling out.

---

## 16. The deduplication plan that follows from this list

The list above identifies the violations. The deduplication pass
that the operator demands is:

  1. Delete `services/investigation_reaper.py`. Move the cap into
     `spec.timeout_s` on the relevant state. (§3, §10, §13.)
  2. Delete `_abandon_stale_branches`, `_reap_zombie_tasks_and_
     cursors`, `_escalate_stuck_drafts` wake-enqueue, `_close_
     rejected_outcomes`, `_synthesize_no_finding_outcomes` from
     `masvs/parent_reconciler.py`. Move each into a workflow state
     with a real handler. (§4, §5, §11, §12, §14.)
  3. Rebuild `POST /investigations/{id}/reopen` as a dispatcher
     task that calls the engine with `allow_phase_handoff=True` on
     a `vr.investigation.reopen.v1` definition. Remove all direct
     UPDATEs to `vr_investigations.status` /
     `vr_investigations.started_at`. (§2, §7.)
  4. Build the report-writer as a workflow state inside the child
     investigation definition. Cache the structured ReportSection
     on the outcome via a normal workflow commit. Keep the PDF
     endpoint as a read-only consumer. (§1, §6.)
  5. After the four deletions above, audit
     `vr/services/` and `vr/masvs/` for any remaining direct DB
     UPDATEs to `workflow_state_cursor`, `taskrecord.heartbeat_at`,
     `vr_investigations.status`, `vr_investigation_branches.status`,
     or `vr_investigation_outcomes.state`. None of these are
     module-layer writes. Each one is a workflow-state transition
     or a task-layer mutation; the module owns neither.

The 6-branch fan-out, the auto-deliberation, the persona protocol,
the MASVS audit fan-out, the operator pause/resume — all of these
are workflow definitions. None of them should require a single
cron-driven sweep to function. If a sweep is needed, the workflow
definition is incomplete.

The investigation must run end-to-end without dropping a single
branch, surviving worker restarts, pause/resume cycles, and
operator-initiated reopens. The engine already provides that
guarantee for code that goes through it. Every "fix" in this file
exists because I went around the engine.

---

## 17. What I will do next

The operator has set the scope: do the deduplication without
breaking the investigation end-to-end. I will:

  - Read every file in `vr/services/` and `vr/masvs/` that touches
    workflow-cursor-adjacent state, in full, before making any
    edit.
  - Plan the cutover state-by-state. The 6-branch fan-out and the
    auto-deliberation transitions must stay equivalent across the
    cutover.
  - Land the deletions with their replacement workflow states in
    the same commit so the system never has a window where neither
    the old reaper nor the new state machine owns the transition.
  - Ship one change at a time. Reconciler cleanup, reopen rewrite,
    report-writer state, cap-removal — each is its own commit and
    its own verification pass.

The 6 branches will not break. Pause and resume will refresh
cleanly. The reaper will not fire against live work. The
workflow-state-cursor is the single source of truth and the engine
is the only thing that writes to it. The domain module reads from
it and from the domain rows; it does not synthesise transitions on
the side.

This document is the baseline I will not violate again.

---

# Part 2 — additional gray areas discovered through exhaustive grep

Written after the operator pushed back on §1-17 as too narrow.
Performed targeted searches across `src/aila/modules` and
`src/aila/api` for: direct writes to engine-owned columns,
duplicate reaper paths, multi-path domain-state mutation, direct
LLM client constructions, and bare exception swallows. Each finding
below corresponds to a file path I read myself, not inference.

## 18. There are FOUR reaper components doing overlapping work

The codebase has not one reaper but four, plus the masvs
reconciler that itself contains a fifth reaper-shape sweep:

|file|sweep name|what it touches|cron|
|---|---|---|---|
|`platform/tasks/worker.py`|`reaper`|`taskrecord.status`, `arq:in-progress:*` keys, ARQ locks|every minute|
|`platform/tasks/worker.py`|`_sweep_orphan_queued_tasks`|`taskrecord.status` (QUEUED→cancelled when absent from ARQ)|every minute|
|`platform/tasks/cursor_reaper.py`|`sweep_orphan_crashed_cursors`|`workflow_state_cursor` (DELETE crashed cursors with terminal task)|every minute|
|`modules/vr/services/branch_reaper.py`|`sweep_orphan_active_branches`|`vr_investigation_branches.status` (ACTIVE→ABANDONED under terminal inv)|every minute|
|`modules/vr/services/investigation_reaper.py`|`sweep_cap_exceeded_investigations`|`vr_investigations.status`, `vr_investigation_branches.status`, ARQ purge|every minute|
|`modules/vr/services/stage_tracker.py`|`reap_stuck_stages`|`vr_targets.analysis_state`, `vr_targets.analysis_stages_json`|every minute|
|`modules/vr/masvs/parent_reconciler.py`|`_reap_zombie_tasks_and_cursors`|`taskrecord.status`, `workflow_state_cursor` (DELETE)|every minute|
|`modules/vr/masvs/parent_reconciler.py`|`_abandon_stale_branches`|`vr_investigation_branches.status`|every minute|
|`modules/forensics/api_router.py`|`auto_reaped` path|`forensics_investigations.status` from a GET handler|on every GET|

Each one of these reaps from a different angle and they overlap.
The platform task reaper IS the canonical heartbeat sweep
(`REAPER_HEARTBEAT_THRESHOLD_S=86400`, `REAPER_ZOMBIE_THRESHOLD_S=3300`).
Every other reaper is a domain-layer hack that decided the platform
reaper's threshold wasn't right for it and rolled its own.

`branch_reaper.py` and `investigation_reaper.py` are both wired
into the same cron block in `platform/tasks/worker.py` per the
module docstring. Their predicates overlap — both can fire on the
same investigation, with different reasons recorded on the branches.

The masvs `_reap_zombie_tasks_and_cursors` does the same work as
`platform/tasks/cursor_reaper.py` plus a layer the platform reaper
already covers (`taskrecord` heartbeat staleness).

`forensics/api_router.py` has an `auto_reaped` codepath that runs
from inside a GET endpoint. This is the violation in its starkest
form — the read-side mutating the row it's reading and lying about
why. The docstring at line 140 even acknowledges this is "a lie"
when the worker actually succeeded but `response_emit` hasn't
committed yet.

**Correct shape**: One reaper at the platform layer. The platform
task reaper writes `taskrecord` heartbeats and reaps stale
heartbeats. Everything else — investigation status, branch status,
stage status, cursor cleanup — derives from the workflow engine's
cursor and audit log. No module-side reaper.

**Status**: All four module-side reapers in production; the
forensics auto-reap GET-mutation path also in production.

---

## 19. `pause_reason` field carries unvalidated strings outside its enum

`InvestigationPauseReason` (per session-summary D-280) is an enum
with values `operator / low_confidence / cost_budget /
awaiting_campaign / awaiting_mcp`. The DB column is `varchar(32)`.
The backend's `_investigation_summary` deserializer raises HTTP 500
on invalid values (as I rediscovered this session).

Direct writers that BREAK this contract today:

|file:line|written value|
|---|---|
|`masvs/parent_reconciler.py:348-351`|`f"exhausted_total_turn_cap:total_turns={total_turns}"`|
|`masvs/parent_reconciler.py:994-995`|`"operator"` (annotated "closest valid enum value")|
|`workflow/states/investigation_emit.py` (multi-line `pause_reason` settings on the cap path)|various `"cap_exceeded:investigation_*:..."`|

The first one is plainly invalid: 36+ chars in a `varchar(32)`
column AND not in the enum. Every time the parent reconciler hits
the turn-cap path, it writes a value that the API serializer
rejects on next read.

The second is the operator-noted workaround I have already done
("closest valid enum value"). The whole pattern — picking the
"closest" enum value because none is right — is a sign that the
enum is missing values OR the column should not be a free-form
`pause_reason` at all. The cap-exceeded close is not a pause; it's
a forced completion. Mapping it onto `pause_reason="operator"` is
structural dishonesty (Golden Rule #2).

**Correct shape**: Drop `pause_reason` from the cap-exceeded
writes. Use `closed_reason` on the branches (which is free-form)
and let the investigation row's `stopped_at` + a separate
`close_reason` column carry the cap reason. Or: extend the enum
with the cap-exceeded variants. EITHER way, every writer that
passes a string outside the enum is wrong.

**Status**: At least three writers do this today.

---

## 20. Direct `outcome.state` writes outside the workflow engine

Outcome state transitions (`draft → approved / rejected / refuted
/ dispatched`) are domain-state-machine writes. They should go
through the same atomic-commit primitive as cursor advances. They
don't.

Sites with direct `outcome.state =` writes:

  - `services/outcome_review.py:325` — `outcome.state = new_state`
    when quorum tally reaches threshold.
  - `agents/outcome_dispatcher.py:1066` — `outcome.state =
    OUTCOME_STATE_DISPATCHED` on successful dispatch.
  - `masvs/parent_reconciler.py` `_synthesize_no_finding_outcomes`
    constructs outcomes with `state='approved'` directly via SQL
    INSERT.

Three paths writing the same column. Each runs in its own
transaction. No coordination beyond row-level lock contention.

**Operator-observable consequence**: Outcome quorum + dispatch +
synthesis can race. Two simultaneous tallies on the same outcome
can both decide "approved" and both INSERT downstream side-effects.
The UNIQUE constraint on `(outcome_id, reviewer_branch_id)` blocks
only DUPLICATE votes from the same branch, not concurrent state
transitions from different code paths.

**Correct shape**: One state for outcome lifecycle in the
investigation workflow definition. `outcome_lifecycle` state with
handler that runs the tally, decides the transition, and either
returns `next_state="outcome_dispatched"` or
`next_state="outcome_rejected"`. The engine's atomic commit writes
the cursor + the outcome state + the branch side-effects in one
transaction.

**Status**: Three direct writers in production.

---

## 21. Direct `branch.status` writes in `branch_manager.py`

`branch_manager.py` has FIVE methods that each directly write
`branch.status`:

|method|target status|
|---|---|
|`merge_branches` (line 175-179)|both branches → `MERGED`|
|`promote_branch` (line 220-221)|chosen branch → `PROMOTED`|
|`promote_branch` siblings (line 228-232)|each sibling → `ABANDONED`|
|`abandon_branch` (line 263-267)|branch → `ABANDONED`|
|`pause_branch` (line 290-293)|branch → `PAUSED`|
|`resume_branch` (line 315-319)|branch → `ACTIVE`|

Each is a single transaction that mutates the branch row. None
writes a corresponding audit event. None coordinates with the
investigation's workflow cursor.

The branches are the workflow runs (one cursor per branch in the
per-branch workflow definition). Direct UPDATEs on the branch
`status` column without a matching cursor advance break the
invariant that cursor + domain row tell the same story.

**Correct shape**: Each branch transition (merge / promote /
abandon / pause / resume) is a state in the branch's workflow
definition. The handler returns
`StateResult(next_state="branch_merged" | "branch_promoted" | ...)`
and the engine commits the audit row + cursor + branch row in one
transaction.

**Status**: All five paths in production.

---

## 22. Direct `inv.status = COMPLETED` writes from agent code

Multiple agent-side files force investigations to terminal status
directly:

  - `agents/outcome_dispatcher.py:1131-1134` — "When an outcome
    dispatches AND no active branches remain, mark inv completed".
    Writes `inv.status = COMPLETED`, `inv.stopped_at = now()`.
  - `agents/synthesis_agent.py:182-185` — similar pattern, on
    synthesis success: `inv_row.status = COMPLETED`,
    `inv_row.stopped_at = now()`.

The agent layer should not be writing the investigation's terminal
status. The agent produces an outcome and signals back to the
workflow engine; the engine's terminal-state handler is the one
that should mark the investigation completed.

**Operator-observable consequence**: The investigation's `status`
can flip to `COMPLETED` from inside an agent's tool dispatch
result, before the workflow engine has committed the corresponding
cursor advance. The cursor and the row tell different stories
during the gap.

**Correct shape**: The agent's outcome dispatch returns to the
workflow engine. The engine's `outcome_dispatched` state checks
"any active branches remain?" and transitions to
`__succeeded__` or back to `investigation_loop`. The status write
happens in the engine's atomic commit, not in the agent code.

**Status**: Both paths in production.

---

## 23. Engine-state handlers performing reaper-shape work

`workflow/states/investigation_setup.py:264-265` is the
investigation's initial setup state. Inside its handler, when
self-heal detects orphan branches from a prior crashed run, it
writes:

```
for o in orphans:
    o.status = BranchStatus.ABANDONED.value
    o.closed_reason = f"superseded_by_reenqueue_self_heal:{...}"
```

An engine state handler is sweeping rows it didn't create. This is
the "self-heal" pattern — the handler treats its own startup as an
opportunity to clean up leftovers from a previous failed run. It
works because the engine guarantees the setup state's writes
commit atomically with the cursor advance, but the abstraction is
wrong: the cleanup should be the engine's own job at
`_load_or_init_cursor` time, not bolted into the first state of
every workflow that needs it.

`workflow/states/investigation_emit.py:383-388` does the matching
pattern on the terminal side: when the cap fires, the emit state
halts every active branch directly (`branch.status = ABANDONED`)
and then calls `arq_purge.purge_arq_jobs_for_investigation` to
kill the pending ARQ tasks. The state handler is enacting a reaper
sweep from inside an engine state.

**Correct shape**: The engine itself owns "clean up leftover
branches on resume" (it can do this once in
`_load_or_init_cursor` for any definition that opts in). The
per-state handlers stop doing reaper work and only do their own
state's specific business logic.

**Status**: Both states in production.

---

## 24. Direct `AilaLLMClient(...)` constructions in module code

The platform owns the LLM client; modules are supposed to consume
it through the services factory (`platform/services/factory.py`),
the runtime model from `platform/runtime/builder.py`, or the
workflow `services_factory` injected at engine setup.

Direct constructions found:

|file:line|context|
|---|---|
|`modules/forensics/agents/resolver_agent.py:144-147`|agent-side LLM call inside a forensics module function|
|`modules/sbd_nfr/api_router.py:842-843`|request handler building its own client to call `search_service.smart_search`|

Each of these has the same shape as my deleted PDF-endpoint LLM
call: the module imports `AilaLLMClient`, constructs it with
`ConfigRegistry()` and `SecretStore()`, and calls its async
methods directly.

**Correct shape**: The agent or request handler receives a
pre-built client from the platform via the services bundle the
workflow engine injects, or via a FastAPI dependency that resolves
the platform's factory. Modules never `AilaLLMClient(...)`.

**Status**: Both in production.

---

## 25. Frontend invents workflow state from domain status

`frontend/screens/InvestigationDetailPage.tsx:710-720` renders a
`currentState` value derived in TypeScript from `inv.status`:

```
currentState={
  inv.status === "running"   ? "investigation_loop"
  : inv.status === "completed" ? "investigation_emit"
  : inv.status === "failed"    ? "investigation_loop"
  : "investigation_setup"
}
```

The actual workflow cursor's `current_state` is a Postgres column
the UI never reads. The UI fakes the workflow state from a domain
status column. The two are not the same: an investigation in
`status="running"` could be at `investigation_setup`,
`investigation_loop`, OR `investigation_emit` depending on which
turn it's on. The UI's claim is structurally wrong on every
transition between those three states.

**Correct shape**: An endpoint that returns the real
`workflow_state_cursor.current_state` per investigation. The
frontend renders it directly. No client-side mapping.

**Status**: Frontend lies to the operator about which state the
workflow is in.

---

## 26. Bare-Exception `# noqa: BLE001` swallows in critical paths

The codebase has 21+ `except Exception as exc: # noqa: BLE001`
sites. Each one silently catches `Exception` (Golden Rule #13)
with a `noqa` to bypass ruff. Most are in reaper / reconciler /
sweeper code where the comment is "best-effort" — meaning the
author chose silent failure over loud crashes.

Locations clustered by file:

|file|count|
|---|---|
|`masvs/parent_reconciler.py`|9|
|`workflow/states/investigation_setup.py`|4|
|`agents/vuln_researcher.py`|2|
|`agents/auto_steering.py`|1|
|`agents/tool_executor.py`|1|
|`services/cve_intel_resolver.py`|2|
|`services/stage_tracker.py`|1|
|`reporting/section_writer.py`|1|
|`api_router.py` (vr)|2|

Each call site has a justification in the `noqa` comment ("best-
effort tick", "never block setup", etc.). But Golden Rule #5 says
error paths are first-class. The pattern of "catch Exception,
log warning, continue" turns every cron tick into a guess about
whether the previous tick succeeded.

**Correct shape**: Each swallow gets a typed exception list.
Things that genuinely cannot recover (OS errors, DB connection
drops, timeouts) get caught; everything else propagates. The
engine's `_handle_failure` path treats unhandled exceptions
correctly — it logs the full traceback to the worker log and
transitions to `__crashed__`. Cron-tick swallows lose that
visibility.

**Status**: 21+ sites in production.

---

## 27. ARQ task purge called from three different layers

The `purge_arq_jobs_for_investigation` helper at
`services/arq_purge.py:132` is imported and called from:

  - `api_router.py:4181-4184` — the operator's `/cancel` endpoint
  - `agents/outcome_dispatcher.py:1147-1150` — when dispatch
    completes and the investigation closes
  - `services/investigation_reaper.py:219-222` — when the cap
    sweep closes investigations
  - `workflow/states/investigation_emit.py:393-396` — when the
    in-state cap check halts an investigation

Four places call the same ARQ-purge primitive on the same
investigation under different policies. None coordinates with the
others. Two purges fired on the same investigation race for the
`arq:queue:vr` keyspace.

**Correct shape**: ARQ purging is a workflow-engine concern (when
the cursor reaches a terminal state). The engine's terminal-state
handler purges. Nothing else does.

**Status**: Four call sites in production.

---

## 28. Stage tracker reuses the same column for run state AND aggregate roll-up

`vr_targets.analysis_state` is both:

  - The aggregate roll-up of all per-stage states (computed by
    `stage_tracker.serialize_stages` from the `analysis_stages_json`
    column).
  - A directly-written field by the api_router on enqueue failure
    (`api_router.py:1840, 2829` — written directly as
    `AnalysisState.FAILED.value` without touching the per-stage
    column).

Two writers, same column. The aggregate writer rolls from per-stage
state; the api_router writes the aggregate column directly without
writing the underlying per-stage states. After an api_router
direct-write, the per-stage column says "RUNNING" while the
aggregate column says "FAILED". The reaper that reads from the
per-stage column to decide its sweep sees a different shape than
the API consumer reading from the aggregate column.

**Correct shape**: Aggregate column is computed-only. Direct writes
go to the per-stage JSON column and the aggregate gets re-rolled.

**Status**: In production.

---

## 29. The summary

Combined §1-17 + §18-28: at least 28 distinct violations of the
platform contract, spread across the VR module (most), the
forensics module (two), the sbd_nfr module (one), and the frontend
(one).

The pattern across all 28 is the same: a workflow that should be
a state machine in the engine is implemented as ad-hoc reads +
ad-hoc writes + ad-hoc sweeps. Each sweep was added to fix a
symptom the previous layer's gap caused. Each new sweep added new
symptoms that needed more sweeps. The masvs reconciler ended up
with six sweep steps because the underlying workflow definition
never had a state for "this investigation is done".

The deduplication pass (§16 in part 1) is the WRONG framing
because deduplication can collapse parallel logic but cannot move
logic into the engine. The actual fix is **re-design**: every
thing that mutates an engine-owned column moves into the workflow
definition; everything left over is a request handler or a
display projection.

Cutover order:

1. Investigation workflow definition rewrite — full state graph
   from `created → setup → loop → emit → terminal`, with explicit
   states for `outcome_dispatch`, `outcome_review`, `branch_merge`,
   `branch_promote`, `branch_abandon`, `pause`, `resume`, and
   `reopen` (handoff). Every transition is a `StateResult`; every
   side-effect commits atomically with the cursor.

2. Delete all four module-side reapers
   (`branch_reaper.py`, `investigation_reaper.py`,
   `masvs/parent_reconciler.py` sweep steps,
   `forensics/api_router.py` auto_reaped). The platform reaper +
   `spec.timeout_s` per state cover their semantics.

3. Delete `cursor_reaper.py` once the engine itself handles stale-
   cursor cleanup at `_load_or_init_cursor` time.

4. Drop direct `branch.status =` / `outcome.state =` /
   `inv.status =` writes from `branch_manager`, `outcome_dispatcher`,
   `synthesis_agent`, `outcome_review`. Each becomes a
   `StateResult` return from a workflow handler.

5. Centralise the LLM client construction. Modules consume the
   platform's services factory only.

6. Wire the real `workflow_state_cursor.current_state` to the
   frontend. Delete the client-side `inv.status →
   "investigation_loop"` mapping.

7. Cap-exceeded close uses `spec.timeout_s` on the investigation's
   loop state. Delete the wall-clock idle-grace gate.

8. Drop the `pause_reason` cap-string writers. Extend
   `InvestigationPauseReason` enum if necessary, or use a separate
   `close_reason` column for non-pause terminations.

9. Frontend Reopen button calls a `/reopen` endpoint that
   enqueues a dispatcher task; the dispatcher calls the engine
   with `allow_phase_handoff=True`. No direct UPDATEs.

10. Section-writer agent runs as a state in the child
    investigation's workflow definition. Cached on the outcome at
    commit time. PDF endpoint reads the cache only.

I will not start any of this without operator sign-off on the
cutover order. The 6 branches stay end-to-end through the
rewrite. Pause and resume refresh cleanly. The reaper stops
firing against live work.

This document is the discovery output. The implementation plan
follows operator approval of the cutover order above.

---

# Part 3 — concrete bugs in reaper / pause / resume / reconciler

Operator pushed back again: §1-28 are architectural violations but
each path also has real, file-line bugs that produce wrong answers
today. This part is the bug list for the specific files the
operator named. Each entry is a file:line, the broken behaviour,
the symptom an operator would observe, and the minimum fix.

## 30. `pause_investigation` does not cancel the `TaskRecord` rows it purges from ARQ

**File**: `modules/vr/api_router.py:4181-4195`.

**Bug**: Pause calls `purge_arq_jobs_for_investigation` to drop
the investigation's pending ARQ Redis entries. Looking at the
helper at `services/arq_purge.py`, it deletes the `arq:job:<id>`
keys and Z-removes them from `arq:queue:vr`. It does NOT update
the corresponding `taskrecord.status` from `queued` to `cancelled`.

**Consequence**: After pause, Redis is clean but the DB still has
`taskrecord.status='queued'` rows for the same `input_hash`. When
the operator clicks Resume, the resume endpoint submits a fresh
`run_vr_investigate` task. The queue's input-hash dedup at
`queue.py:132-140` looks up `taskrecord` by hash, finds the
stale `queued` row, and returns its ID instead of enqueueing a
new one. The Resume silently no-ops because the worker only
reads from Redis and Redis has no entry for the returned ID.
The investigation stays paused-but-dead.

**Fix**: After ARQ purge, UPDATE the matching taskrecord rows to
`status='cancelled'` in the same transaction.

---

## 31. `resume_investigation` doesn't take a row lock when checking status

**File**: `modules/vr/api_router.py:4215-4239`.

**Bug**: Resume does `SELECT investigation`, checks
`inv.status == PAUSED`, then writes `inv.status = RUNNING`. No
`FOR UPDATE` on the SELECT. Two concurrent Resume requests both
pass the status check and both UPDATE; one wins the row write
but both enqueue a fresh task at line 4247. Two duplicate workflow
runs for one resume operation.

**Consequence**: The investigation gets dual-enqueued. The
workflow engine's `_load_or_init_cursor` would see ONE cursor
(it locks the row at FOR UPDATE) so one worker proceeds and the
other hits the optimistic-lock conflict and ARQ-retries. The
optimistic-lock catches it on the workflow side. But the resume
endpoint just over-paid for a duplicate task that wasn't needed.

**Fix**: `.with_for_update()` on the SELECT.

---

## 32. `resume_investigation` submits with no `branch_id` — engine resumes whatever branch the cursor happens to be on

**File**: `modules/vr/api_router.py:4247-4254`.

**Bug**: Resume submits `run_vr_investigate` with
`kwargs={"investigation_id": investigation_id}` only — no
`branch_id`. The auto-deliberation flow creates six branches per
investigation; each branch has its own workflow cursor (run_id
= branch task id). Submitting with no branch_id means the worker
can pick any of the six — or the platform's dispatcher state has
to demultiplex which branches need waking.

**Consequence**: Either only one branch resumes, or every branch
resumes (depending on dispatcher state). When pause was applied
to the whole investigation, the operator expects all six branches
to resume. Today only one task gets enqueued.

**Fix**: Resume should iterate active branches and enqueue one
task per branch. OR the per-investigation workflow definition's
`investigation_setup` state should re-spawn dormant active
branches as part of resume.

---

## 33. `pause_investigation` doesn't pause the workflow cursor

**File**: `modules/vr/api_router.py:4140-4196`.

**Bug**: Pause writes `inv.status = PAUSED` and purges ARQ. The
`workflow_state_cursor` for each branch is untouched. The cursor
still says `investigation_loop` (or wherever the branch was). A
worker that picks up a queued task that survived the purge (race)
OR a worker that the platform reaper later re-enqueues will read
the cursor and resume the loop — even though pause was applied.

The `investigation_setup` state has a `STATUS_LOCKED` guard at
lines 135-142 that exits to `investigation_emit` when
`inv.status==PAUSED`. So in practice pause DOES halt because every
turn goes through investigation_setup first. But:

  - The STATUS_LOCKED guard runs ONCE PER TURN. A turn that's
    mid-handler when pause arrives finishes the handler (including
    the LLM call that may cost a few cents) before the next turn's
    setup check catches the pause.
  - The audit log doesn't record "pause" as a workflow event. It
    records `exited:ok` from investigation_loop → investigation_emit
    with no indication that an operator pause caused the exit.

**Fix**: Pause writes a domain signal AND advances the cursor to a
terminal-ish paused state. The workflow definition has a `paused`
state with `terminal=True` (or a non-terminal `paused` with no
enqueue chain). Resume is a phase-handoff back to `investigation_
loop`.

---

## 34. `branch_reaper.sweep_orphan_active_branches` ignores branches when investigation is PAUSED

**File**: `modules/vr/services/branch_reaper.py:70-74`.

**Bug**: `_TERMINAL_STATUSES` is `(completed, failed, abandoned)`
— deliberately excludes `paused`. The docstring at line 67-69
explains: "paused branches resume cleanly when the operator
un-pauses; reaping them would force the operator to also resurrect
every branch by hand".

But the inverse is also true: a branch under a PAUSED investigation
can be `status='active'` indefinitely, with no worker driving it.
The dashboard shows it as still running for as long as the
investigation stays paused. Operator-visible "ghost running"
branches.

The intent — preserve branches across pause/resume — is correct.
The implementation forgets to mark them `status='paused'`
matching the investigation. So they LOOK active.

**Fix**: Pause flips active branches to `branch.status='paused'`;
resume flips them back to `active`. The reaper exclusion stays;
the dashboard now shows the honest signal.

---

## 35. `branch_reaper` race between query and UPDATE on `stopped_at`

**File**: `modules/vr/services/branch_reaper.py:113-122`.

**Bug**: The OR clause covers `stopped_at IS NOT NULL AND
stopped_at < cutoff` OR `stopped_at IS NULL AND updated_at <
cutoff`. Between the SQL plan compile and the actual UPDATE
evaluation, another writer can set `stopped_at` for the first
time. The branch's investigation transitions terminal at moment
T; the reaper compiled its statement at T-100ms with the OLD
stopped_at value (NULL) and the OLD updated_at value (>cutoff);
during evaluation Postgres sees the NEW stopped_at (< cutoff —
just-set, so close to now()).

Outcome under MVCC: the UPDATE sees the snapshot at the start of
its own transaction, so the just-written stopped_at is visible if
the writer committed before our UPDATE began. If the writer
commits DURING our UPDATE evaluation, our read snapshot is from
UPDATE-start so we see the pre-commit value. Either way, the
UPDATE is consistent against ONE point in time.

But the IDLE GRACE is 5 minutes (`_ORPHAN_GRACE_SECONDS = 300`).
Between the investigation transitioning terminal and the grace
elapsing, the reaper's evaluation may or may not see the
investigation as terminal. After 5 min it definitely does. The
race is bounded.

**Status**: This is technically correct under PostgreSQL MVCC.
The 5-minute grace covers it. NOT a bug, listing for
completeness — operator wants the full audit.

---

## 36. `investigation_reaper.sweep_cap_exceeded` doesn't guard the branch UPDATE on `INV.status == RUNNING`

**File**: `modules/vr/services/investigation_reaper.py:183-196`.

**Bug**: The branch UPDATE filters only by `investigation_id ==
inv_id` and `status == ACTIVE.value`. No guard on the parent's
current status. If the investigation reaches terminal between the
SELECT (line 117) and the BRANCH UPDATE (line 183), the reaper
still flips the branches to `abandoned` with
`closed_reason='cap_exceeded:...'`.

But branch_reaper would have flipped those branches anyway (if the
investigation went terminal) with
`closed_reason='investigation_terminal:...'`. Two reapers write
different reasons to the same branch on a race. The reason field
becomes a lie about which reaper actually fired.

**Fix**: Branch UPDATE adds
`.where(EXISTS(SELECT 1 FROM inv WHERE id=inv_id AND status='running'))`
— or the branch update happens AFTER the investigation status
update succeeds.

---

## 37. The investigation_reaper UPDATE at line 197-205 has no `RETURNING`; can't tell which inv updates actually fired

**File**: `modules/vr/services/investigation_reaper.py:197-206`.

**Bug**: The investigation UPDATE at line 199 has guard
`status == RUNNING` (correct), but no `.returning(INV.id)`. The
reaper assumes the UPDATE flipped 1 row (line 207 appends to
`completed_ids`) but actually it could have flipped 0 rows
(another worker raced). The `completed_ids` list contains
investigations that may not have been flipped by THIS sweep.

The ARQ purge loop at line 218-234 then purges jobs for
investigations that might still be running.

**Fix**: `.returning(INV.id)` on the inv update; only append to
`completed_ids` when `.first() is not None`.

---

## 38. `_int_env` / `_float_env` return defaults silently on bad input

**File**: `modules/vr/services/investigation_reaper.py:46-61`.

**Bug**: Helpers parse env vars with a bare `try: ... except
ValueError: return default`. If an operator sets
`VR_INVESTIGATION_TURN_CAP=300m` (typo with stray suffix) or
`VR_INVESTIGATION_WALL_CLOCK_HOURS=24h`, the parse fails silently
and the reaper uses the hardcoded default. The operator's
configuration is silently ignored. No log warning.

**Fix**: Log a warning on parse failure. Better: validate at
startup and crash if any of these env vars are present-but-
unparseable, so the operator sees the problem immediately.

---

## 39. `pause_branch` / `resume_branch` in branch_manager.py don't enqueue tasks

**File**: `modules/vr/agents/branch_manager.py:288-319`.

**Bug**: `pause_branch` flips `branch.status=PAUSED` and commits.
`resume_branch` flips it back to `ACTIVE` and commits. Neither
touches ARQ.

Resume_branch sets the branch active again but no fresh task is
submitted. The branch sits at `active` waiting for the next
worker dequeue — which never happens because there's no task in
the queue.

Operator-visible: resume_branch is a no-op. The branch shows
`active` in the UI but nothing drives it.

**Fix**: `resume_branch` enqueues a `run_vr_investigate` task
with that branch's ID. Or the auto-reconciler wakes branches in
the active+no-task state (but that's the wake-enqueue violation
I've already documented at §12).

---

## 40. `branch_manager.merge_branches` doesn't update the survivor's `parent_branch_id` pointer

**File**: `modules/vr/agents/branch_manager.py:175-180`.

**Bug**: Merge flips both branches to `MERGED` status, sets
`merged_into_branch_id` and `closed_reason` and `closed_at`. The
surviving merged branch is created elsewhere; this code only
updates the source branches.

If the survivor's parent pointer is supposed to be one of the
source branches (so the branch lineage tree is correct), nobody
sets it. The branch tree UI shows the survivor as orphaned.

**Status**: Speculative — I didn't read the survivor-creation
code. Flagging for the operator to check during the rewrite.

---

## 41. `parent_reconciler._refill_apk_batches` matches kwargs_json with substring LIKE — false positives

**File**: `modules/vr/masvs/parent_reconciler.py:174-181` and
`:200-207`.

**Bug**: The query filters for CREATED children that don't have
a queued task. The "no queued task" check uses
`tsk.kwargs_json.ilike(f'%{child_id}%')` — substring LIKE on the
JSON column. The child_id is a UUID, e.g. `123e4567-e89b-...`.
If ANY queued task's kwargs_json contains this UUID substring —
including as part of a different field like `parent_investigation_
id` — the substring matches and the reconciler thinks "this child
has a queued task" and skips refilling.

UUIDs are 36 chars and randomly generated, so false positives are
rare in practice. But the query is structurally wrong: it should
match on a specific JSON path (`kwargs_json->>'investigation_id'
= :child_id`), not substring.

**Fix**: `func.jsonb_extract_path_text(tsk.kwargs_json,
'investigation_id') == child_id` or equivalent JSONPath syntax.

---

## 42. `parent_reconciler._reap_zombie_tasks_and_cursors` 4-step delete chain isn't transactional across steps

**File**: `modules/vr/masvs/parent_reconciler.py:1108-1233`.

**Bug**: The function runs four separate UPDATE/DELETE statements
inside ONE `async_session_scope`:

  1. UPDATE taskrecord SET status='cancelled' WHERE heartbeat
     stale.
  2. DELETE workflow_state_cursor WHERE no matching taskrecord
     (orphan).
  3. DELETE workflow_state_cursor WHERE taskrecord is terminal.
  4. DELETE workflow_state_cursor WHERE current_state =
     `__succeeded__`.

Each runs as one statement. The session scope commits ONCE at the
end, so the four are technically in one transaction. Good.

BUT — the orphan check at step 2 (`NOT EXISTS (SELECT 1 FROM
taskrecord ...)` ) runs BEFORE step 1's UPDATE has been committed.
Within one transaction, statements see their OWN earlier changes,
so step 2's NOT EXISTS picks up the cancelled-by-step-1 rows...
wait, step 1 didn't DELETE the taskrecord, just UPDATEd its
status. So step 2's NOT EXISTS doesn't change. OK no bug here.

But step 3 (`JOIN taskrecord t WHERE t.status IN (cancelled,
done, failed, dead_letter)`) DOES see step 1's updates — that's
intentional, the just-cancelled tasks become eligible for cursor
deletion in the same transaction. OK design works.

**Status**: Confusing but correct.

---

## 43. `parent_reconciler` sweep step ordering creates a race window

**File**: `modules/vr/masvs/parent_reconciler.py:1257-1300`.

**Bug**: The 6 sweep steps run in order: refill → turn-cap →
escalate-stuck-drafts → close-rejected → abandon-stale →
synth-no-finding → reap-zombies. Each step calls its own
`UnitOfWork` (a new transaction).

Step 5 (`_abandon_stale_branches`) flips active branches to
abandoned. Step 6 (`_synthesize_no_finding_outcomes`) then
checks "all branches terminal? synthesize outcome." But step 6
runs in its own transaction, sees a snapshot from BEFORE step 5
committed (depending on isolation level — Postgres default is
READ COMMITTED, so it'll see step 5's commit). OK READ COMMITTED
saves us. But:

Step 3 writes `_directive.mandatory_vote_now` into branch
case_state_json. Step 4 checks "all non-proposer voted?" and
closes. Between step 3 and step 4 the operator may have voted
(racing with the reconciler). The voting endpoint commits before
step 4 reads. READ COMMITTED ensures step 4 sees the vote. OK.

But step 3 also enqueues wake tasks. Those tasks could be picked
up by a worker DURING step 4's evaluation. The worker advances
the cursor; step 4's snapshot still uses the pre-worker state.
So step 4 might close an investigation while a worker is mid-turn
on a fresh wake-task. Race.

**Fix**: Wake-enqueue happens LAST in the reconciler tick, not in
step 3. OR the entire reconciler tick is one transaction.

---

## 44. The platform reaper grace asymmetry

**File**: `platform/tasks/worker.py:161-193`.

**Bug**: The `reaper` cron calls `_sweep_orphan_running_tasks`
with `grace_seconds=600, reap_null_heartbeat=False`. The boot
path calls the same function with defaults (30s grace,
`reap_null_heartbeat=True`).

So a task that boots with `heartbeat=None` (never wrote a
heartbeat) gets reaped at startup with 30s grace, but the same
task running in production gets 600s grace and is NOT reaped
even with null heartbeat.

This means the cron is effectively blind to "task that picked up
a job and immediately died before writing its first heartbeat" —
the engine's first heartbeat write is inside `_commit_transition`
after the first state's handler returns successfully. A handler
that takes 11+ minutes to produce its first transition is
permanently invisible to the reaper.

**Status**: Documented intentional asymmetry per the comment at
line 186-187. Not a bug per se but a known invariant that the
per-state `timeout_s` design relies on — handlers should not
exceed `timeout_s` and `timeout_s` should be < 600s. Real-world
states regularly violate this (the investigation_loop state's
`spec.timeout_s` is much larger).

---

## 45. `_sweep_orphan_queued_tasks` at boot races with ARQ enqueue

**File**: `platform/tasks/worker.py:81-153`.

**Bug**: This sweep runs at worker boot. It selects taskrecord
rows with `status='queued'`, checks each one's presence in the
ARQ Redis queue, and reaps any DB-queued row absent from Redis.

If the worker boots WHILE the api_router is in the middle of
submitting a task (INSERT INTO taskrecord BEFORE ZADD into
arq:queue), the sweep can see the queued row, not see the ARQ
entry yet (still being written), and reap the row. The api_router
then completes its ZADD into a queue with no matching DB row.
ARQ runs the job, finds no DB row, errors and the job goes dead-
lettered or hangs.

**Fix**: Add a creation-time grace: only reap rows where
`created_at < now() - 10s`. Operators submitting tasks should not
be at risk of having their task killed in the first 10s after
enqueue.

---

## 46. Reset endpoint isn't actually destructive enough

**File**: `modules/vr/api_router.py:4480-4500` (approximate).

**Bug**: Reset (`POST /investigations/{id}/reset`) is described
as "Wipe history + reset to start". Looking at the writes:
sets `inv.status = CREATED`, `pause_reason = None`. But the
`workflow_state_cursor` row is NOT deleted. The cursor still
holds the last-known state from the prior run.

When the next task fires, `_load_or_init_cursor` reads the
existing cursor (not a fresh one) and resumes from where the
prior run left off — completely bypassing the "reset" intent.

**Fix**: Reset DELETEs the `workflow_state_cursor` row in the
same transaction. The next task creates a fresh cursor at
`start_state`.

---

## 47. The frontend Reset button is enabled while investigation is RUNNING

**File**: `frontend/screens/InvestigationDetailPage.tsx:691-695`.

**Bug**: The disabled-state check is
`disabled={resetMut.isPending || inv.status === "running"}`.
OK that's correct — disabled when running.

But the title is conditional on `inv.status === "running"`:
"Pause the investigation first, then reset." Implying reset is
blocked on running but ALLOWED on paused. The server-side endpoint
at api_router around line 4413 enforces `inv.status ==
RUNNING.value → 409`. So reset on PAUSED is allowed by the
server. But reset on PAUSED still has the running-but-orphaned
ARQ tasks hanging around (per BUG-30 the pause doesn't cancel
them).

So: pause → reset → ARQ tasks dequeue after the reset → workflow
runs against the partial state.

**Fix**: Reset endpoint cancels ARQ tasks AND deletes the
workflow cursor. Both happen in one transaction.

---

## 48. Worker.py reaper recovers only from `arq:in-progress:*` keys; doesn't reconcile `taskrecord` heartbeats with the engine

**File**: `platform/tasks/worker.py:161-193`.

**Bug**: The reaper walks Redis ARQ locks. It does NOT walk
`taskrecord` rows looking for `status='running' AND heartbeat <
now() - REAPER_HEARTBEAT_THRESHOLD_S`. The threshold of 86400
(24h) means a task that's been alive 24h without any state
transition might still be marked `running` indefinitely. The
engine writes heartbeat on every commit, so a stuck task has no
heartbeat updates — but the reaper doesn't actively look for
24h+ stale heartbeats.

`_sweep_orphan_running_tasks` (line 168-173 docstring) "walks DB
rows in TaskStatus.RUNNING and reaps any whose ARQ lock has
already been evicted". So the sweep reaps when the LOCK is gone,
not when the HEARTBEAT is stale. A task that holds its ARQ lock
but never updates heartbeat would not be reaped.

**Fix**: Add a second pass: `taskrecord.status='running' AND
heartbeat_at < now() - threshold` → mark cancelled, even if the
ARQ lock is still present (the worker's clearly dead).

---

## 49. Forensics auto-reap inside a GET handler

**File**: `modules/forensics/api_router.py:140-191`.

**Bug**: The docstring explicitly says reading the row decides
whether to mutate it: "TaskRecord is missing → reap (worker
disappeared)" and "TaskRecord.status is done → DO NOT reap. The
worker finished successfully; response_emit may not have
committed yet". The implementation actually writes to the inv
row on the "reap" branch (line 185-190), including setting
`inv.final_answer = "Investigation auto-reaped — {reason}."`.

GET endpoints are supposed to be safe (idempotent, no side
effects per HTTP spec). This one isn't. Worse — the operator
refreshing the page causes status writes the operator didn't
intend.

**Fix**: Move the reap logic into a separate reaper sweep
(platform task layer) and make the GET truly read-only.

---

## 50. `stage_tracker.reap_stuck_stages` has timeout asymmetry with the cron

**File**: `modules/vr/services/stage_tracker.py:82-90` and
`:371-434`.

**Bug**: `_DEFAULT_TIMEOUTS[INGESTION] = 14400.0` (4 hours).
The cron runs every minute. So a stage that started 4h ago gets
reaped on the 240th cron tick. That's the bound for an idle
stage to be detected.

But the cron task itself is bounded by `ARQ_JOB_TIMEOUT_S=3600`
(1 hour). A reaper sweep that takes longer than 1h would be
killed. In practice it's fast (one SELECT + a few UPDATEs).

The actual bug: `_DEFAULT_TIMEOUTS` are hardcoded but the per-
target row can override via... actually I'd need to read more.
The override path isn't visible from the reaper. So if a target
has a custom long-running stage that the reaper's default
thinks is too long, the reaper kills the live work.

**Status**: Speculative — needs more reading to confirm. Listing
for completeness.

---

## 51. Race between `outcome_dispatcher` and `parent_reconciler._close_rejected_outcomes`

**File**: `modules/vr/agents/outcome_dispatcher.py:1131-1134` AND
`modules/vr/masvs/parent_reconciler.py:930-1000`.

**Bug**: Both can close the same investigation:

  - outcome_dispatcher: "outcome dispatched AND no active
    branches → mark inv completed."
  - parent_reconciler step 4: "primary outcome state=rejected
    AND all non-proposer voted → mark inv completed."

Sequence: outcome dispatches → dispatcher sets inv.status=
COMPLETED. One minute later, parent_reconciler sweeps, sees inv
still has a rejected primary outcome, attempts to close again.

`_close_rejected_outcomes` at line 932-934 filters
`inv.status == RUNNING` so it won't double-flip a completed inv.
OK. But the dispatcher's close at line 1131 doesn't check
whether the parent reconciler is mid-sweep on this inv. Two
writers want the same UPDATE; one wins. The audit trail records
only the winner.

**Status**: Not actually wrong because the guards filter
correctly, but the structural dual-writer pattern is the
violation. Listed for cutover plan.

---

## 52. The MASVS audit "deferred" children never get reaped if the parent gets cancelled

**File**: `modules/vr/masvs/parent_reconciler.py:1397-1410`.

**Bug**: When a MASVS parent gets paused or abandoned (via the
operator or via cap-exceeded), the children at status=CREATED in
the deferred pool stay at CREATED indefinitely. The parent_
reconciler at line 1402 filters
`status == CREATED.value` AND only refills when parent's status
is RUNNING.

So if parent goes PAUSED, the 38 deferred children sit at
CREATED with no ARQ task and no reconciler refilling them. If
the operator resumes the parent, the reconciler picks back up.
If the operator abandons the parent, the children never go
anywhere — they stay CREATED forever.

**Fix**: Parent terminal-status transition cascades to children.

---

## 53. `_synthesize_no_finding_outcomes` writes outcomes with hardcoded `state='approved'`

**File**: `modules/vr/masvs/parent_reconciler.py:835-855`.

**Bug**: The synthesized audit_memo outcome gets
`state='approved'` inserted directly. No verifier ran, no
quorum, no human review. The verdict mapper sees state=approved
and reads it as a real approval.

If the operator filters by `outcomes WHERE state='approved'`
(expecting "outcomes a sibling-approved or auto-approved"), the
synthesised ones leak in. They're not approved — they're a
placeholder for "no real outcome happened".

**Fix**: The synthesizer either uses a NEW state value
(`'synthesized_no_finding'`) or sets `state='draft'` so the
downstream filters can distinguish. The verdict mapper's
_payload_says_pass detection then reads the answer text rather
than trusting state=approved blindly.

---

## 54. Frontend resume/pause buttons don't refresh the cursor display

**File**: `frontend/screens/InvestigationDetailPage.tsx:710-720`.

**Bug**: The `currentState` derivation in §25 above is recomputed
from `inv.status` whenever the React Query cache invalidates. But
the pause/resume mutations invalidate `['vr','investigation',
id]` which refetches the investigation row. The cursor display
depends on the synthesized mapping (`running →
investigation_loop` etc.), not on the actual cursor. So pause
immediately renders `investigation_setup` (because status=
paused isn't in the if/elif chain and falls through to the
default `investigation_setup` line).

After resume, the UI shows `investigation_loop` even before the
worker has picked up the task and advanced the cursor.

**Fix**: Read the actual `workflow_state_cursor.current_state`
from the backend; render that.

---

## 55. Summary part 3

25 additional concrete bugs added to the 28 architectural
violations in parts 1-2. Total: 55+ items.

The pattern by file (bugs only, ignoring the structural
violations already counted):

|file|bug count|
|---|---|
|`modules/vr/api_router.py`|30, 31, 32, 33, 46, 47|
|`modules/vr/services/branch_reaper.py`|34, 35|
|`modules/vr/services/investigation_reaper.py`|36, 37, 38|
|`modules/vr/agents/branch_manager.py`|39, 40|
|`modules/vr/masvs/parent_reconciler.py`|41, 42, 43, 52, 53|
|`platform/tasks/worker.py`|44, 45, 48|
|`modules/forensics/api_router.py`|49|
|`modules/vr/services/stage_tracker.py`|50|
|`modules/vr/agents/outcome_dispatcher.py`|51|
|`frontend/screens/InvestigationDetailPage.tsx`|54|

Bug densest file: `parent_reconciler.py` (5 concrete bugs across
parts 2-3, plus the architectural sweep-step violations in
parts 1-2).

No new tools are needed to find these. Each entry corresponds to
code I have read in this session. The cutover plan in §29 above
gets harder by each one — the rewrite has to fix all 55 items
without breaking the 6-branch fan-out, the auto-deliberation
transitions, the persona protocol, or the operator pause/resume
contract.

This is the discovery output. No code edits made for any of
these items pending operator approval on cutover order.

---

# Part 4 — bugs in arq_purge / cursor_reaper / auto_deliberation / platform reaper internals

Operator asked again for more. This part covers the platform-side
sweep paths and the auto_deliberation enqueue chain that I hadn't
read line-by-line yet. Each finding is a file:line read in this
session.

## 56. Platform reaper catches a narrow exception tuple — DB errors crash the entire cron tick

**File**: `platform/tasks/worker.py:175-261`.

**Bug**: Every sub-sweep is wrapped in
`except (OSError, TimeoutError, RuntimeError, ValueError) as exc`.
SQLAlchemy errors (`OperationalError`, `IntegrityError`,
`InterfaceError`, `DBAPIError`) are subclasses of `Exception` but
none of those four. A DB hiccup in ANY sub-sweep raises an
exception that the wrapper doesn't catch — the cron task crashes.
The remaining sub-sweeps in the chain don't run that tick.

Concrete chain on a single cron tick:
  1. `_reconcile_orphan_arq_locks` (line 176)
  2. `_sweep_orphan_running_tasks` (line 189)
  3. `reap_stuck_stages` (line 204)
  4. `sweep_orphan_crashed_cursors` (line 217)
  5. `_sweep_orphan_queued_tasks` (line 223)
  6. `sweep_cap_exceeded_investigations` (line 230)
  7. `sweep_orphan_active_branches` (line 241)
  8. `sweep_masvs_audit_parents` (line 253)

A DB connection drop in step 2 crashes the cron; steps 3-8 don't
run. Next minute it tries again. If the DB is genuinely down for a
few minutes, the reaper effectively goes silent for that window.

**Fix**: Catch `Exception` per sub-sweep (with the existing
log+continue behaviour) — the cron's whole point is "best-effort
sweep, never crash the tick". The narrow tuple defeats it.

---

## 57. Ordering bug in `reaper`: `cursor_reaper` runs BEFORE `_sweep_orphan_queued_tasks`

**File**: `platform/tasks/worker.py:217 vs 223`.

**Bug**:
  - Line 217: `sweep_orphan_crashed_cursors` deletes `__crashed__`
    cursors whose TaskRecord is NOT in `(QUEUED, RUNNING, WAITING)`.
  - Line 223: `_sweep_orphan_queued_tasks` flips QUEUED rows
    absent from ARQ to `FAILED`.

On the same tick, a cursor whose TaskRecord is QUEUED-but-absent-
from-ARQ:
  - cursor_reaper at line 217 sees status=QUEUED (active per its
    filter), SKIPS the cursor.
  - 6 seconds later, orphan_queued sweep flips the task to FAILED.
  - Cursor still sits at `__crashed__` for ANOTHER 60s until the
    NEXT cron tick's cursor_reaper sees status=FAILED and deletes.

The cursor's lifespan is 1-2 minutes longer than necessary.
Cumulatively means cursors at `__crashed__` linger and re-enqueue
attempts fail per CLAUDE.md's stale-cursor-blocks-resubmission
rule.

**Fix**: Run orphan_queued BEFORE cursor_reaper, OR have one
sweep that does both transitions atomically.

---

## 58. `cursor_reaper` only deletes `__crashed__` cursors — `__failed__` and `__cancelled__` accumulate forever

**File**: `platform/tasks/cursor_reaper.py:61`.

**Bug**: The WHERE clause filters
`current_state == "__crashed__"`. The four reserved terminals
include `__failed__` and `__cancelled__` per the engine design.
Cursors at those terminals are also dead weight — same blocking
effect on resubmission — but cursor_reaper ignores them.

`__succeeded__` cursors are handled by the masvs reconciler's
`_reap_zombie_tasks_and_cursors` step 4 (within the VR module). So
overall: `__crashed__` handled by platform, `__succeeded__`
handled by VR module, `__failed__` and `__cancelled__` handled by
nothing.

**Fix**: cursor_reaper deletes all four reserved terminals with
the same TaskRecord-terminal filter.

---

## 59. `arq_purge.py` calls `pickle.loads` on Redis blobs from ARQ

**File**: `modules/vr/services/arq_purge.py:105`.

**Bug**: The blob is owned by ARQ and contains the pickled job
kwargs. A corrupted blob (partial Redis write, version-skew
between ARQ versions, manual `SET` on the key) makes `pickle.loads`
raise. The catch handles `pickle.UnpicklingError, KeyError,
TypeError` — but not arbitrary `ImportError` (older ARQ versions
pickled classes that no longer exist) or `EOFError` (truncated
blob). Those crash the purge mid-loop and the remaining queue
entries don't get inspected.

Additionally: the `# noqa: S301 — ARQ-owned pickle` comment
acknowledges the trust assumption. ARQ versions that ship a class
with a `__reduce__` method run that method's code on unpickle.
The "ARQ-owned" assumption holds only as long as nobody has ever
written to arq:job:* keys outside of ARQ itself.

**Fix**: Wrap `pickle.loads` in a broader `try/except Exception`
with a log warning, continuing the loop. Or — better — use ARQ's
own API to drain the queue instead of poking at its Redis
representation.

---

## 60. `arq_purge.py` zrem-then-delete race against a worker dequeue

**File**: `modules/vr/services/arq_purge.py:115-118`.

**Bug**: Order:
  1. `await client.zrem(queue_key, job_id)` — removes from queue
     zset.
  2. `await client.delete(job_key)` — deletes the job blob.

Between 1 and 2, a worker that dequeued the job FROM THE QUEUE
just before step 1 still has the job_id in memory. It calls
`client.get(job_key)`; the key still exists because step 2 hasn't
fired yet. The worker proceeds to run the job. Then step 2 fires
and deletes the blob — but the worker has already loaded its
contents, so no error there. Result: the purge "succeeded" but the
job ran anyway.

The reverse race (worker dequeues AFTER step 1 but before step 2):
the worker's zpop returns 0 entries because step 1 removed it
from the queue. The blob is still in Redis until step 2 fires.
Garbage left in Redis for a few milliseconds. Acceptable.

The acknowledged race is the worker dequeue happening BETWEEN
`_sweep_orphan_queued_tasks` snapshot at boot/cron AND the purge
— which the docstring at line 6-13 explicitly says
investigation_setup STATUS_LOCKED guards against.

**Status**: Partially mitigated by the STATUS_LOCKED guard. Listed
because the "drop from queue first, then delete the job record"
comment misstates which order prevents which race.

---

## 61. `_sweep_orphan_queued_tasks` cross-queue UUID collision

**File**: `platform/tasks/worker.py:108-115`.

**Bug**: The sweep scans EVERY `arq:queue:*` zset key and collects
all job IDs into a single `present_in_arq: set[str]`. If the same
job_id appears in two different queues (vr + default), or — more
plausibly — a VR job's UUID happens to collide with a default-
queue job's UUID (UUIDs are 122-bit random, collisions are
vanishingly rare), the sweep sees the VR task as "present" and
skips reaping.

The realistic risk is much smaller than the UUID collision: the
sweep's "skip cron / health-check keys" filter at line 111-112
removes only keys that have an extra `:` after `arq:queue:`. If
ARQ adds a new queue naming convention (e.g. `arq:queue:vr:dlq`),
the second colon is the filter's exclusion trigger — but if a
queue is genuinely named differently (no second colon), all its
job IDs leak into the present_in_arq set and false-protect VR
rows from reaping.

**Fix**: Compare per-track instead of across all tracks. The
TaskRecord has a `track` column; the sweep can filter
`scan_iter(match=f"arq:queue:{rec.track}")` per row.

---

## 62. `_sweep_orphan_queued_tasks` timezone-naive `created_at` comparison

**File**: `platform/tasks/worker.py:118, 121-125`.

**Bug**: `recency_cutoff = datetime.now(tz=UTC) - timedelta(seconds=60)`
is timezone-aware. The WHERE clause
`TaskRecord.created_at < recency_cutoff` compares against the
`created_at` column. If any row has `created_at` stored as
timezone-naive (legacy data, mis-configured ORM column), Postgres
raises `InvalidDatetimeFormat` or the comparison silently coerces
depending on the column type.

The Postgres `timestamptz` column type forces timezone awareness
on read, so this is theoretically not a bug today. But other
sweeps in the codebase (e.g. `_should_drop_lock` at line 66-67)
explicitly handle the naive case with
`hb.replace(tzinfo=UTC)`. This sweep doesn't.

**Status**: Defensive — listed because the inconsistency between
sweep code is a maintenance hazard.

---

## 63. `auto_deliberation` writes `b.closed_reason = ""` instead of NULL

**File**: `modules/vr/workflow/states/investigation_setup.py:432-434`.

**Bug**: When the winner of a duplicate-persona cleanup gets
REACTIVATED from `abandoned`/`completed`, the code writes
`b.closed_reason = ""` (empty string). The convention everywhere
else is `closed_reason IS NULL` for branches that haven't been
closed.

`branch_reaper.py:96-101` has a CASE expression that special-cases
`BR.closed_reason IS NULL OR BR.closed_reason == ""` together —
so empty string and NULL are treated the same on the next reap.
Other consumers (UI, JSON export) might render `""` differently
from `null`. Audit trail inconsistency.

**Fix**: Use `None` (NULL).

---

## 64. `branch_manager.pause_branch` doesn't check investigation status

**File**: `modules/vr/agents/branch_manager.py:286-294`.

**Bug**: `pause_branch` flips `branch.status = PAUSED` without
checking the parent investigation's status. An operator can pause
a branch under a `status=COMPLETED` investigation.

The branch then sits at `PAUSED`. branch_reaper at §34 excludes
`PAUSED` branches from reaping, so the branch persists forever.
The investigation appears completed in the UI but has a paused
child branch nobody can resume because the parent is terminal.

**Fix**: Reject pause when investigation is not in `(RUNNING,
CREATED)`.

---

## 65. `auto_deliberation` fork-then-submit are in two separate transactions

**File**: `modules/vr/workflow/states/investigation_setup.py:462-495`.

**Bug**: For each persona sibling:
  1. `manager.fork(...)` opens its own UnitOfWork, creates the
     branch row, commits.
  2. `task_queue.submit(...)` writes a TaskRecord row + ZADDs to
     ARQ in a separate transaction.

If step 1 commits and step 2 fails (network blip, dedup conflict,
ARQ queue full), the branch row exists with `status=ACTIVE` but
no task drives it. The investigation_loop never runs for that
sibling.

The catch at line 491-495 catches `Exception` and logs — the
caller continues with the next persona. The failed sibling's
branch row stays at ACTIVE forever (or until the masvs
reconciler's wake-enqueue picks it up — but that's a MASVS-only
sweep; non-MASVS investigations don't have it).

**Fix**: Either roll back the branch row on submit failure, or
the engine's own re-enqueue path picks up active-no-task branches
universally.

---

## 66. `auto_deliberation` uses the same `group_id` for all 5 personas

**File**: `modules/vr/workflow/states/investigation_setup.py:487`.

**Bug**: Every sibling enqueue uses `group_id="vr_auto_deliberation"`.
If the platform task layer applies per-group throttling (cost
budgets, concurrency caps), all 5 personas share the same group's
budget. One operator running 10 investigations simultaneously gets
5×10=50 tasks all under one group — and the platform's group cap
would throttle them collectively rather than per-investigation.

**Fix**: `group_id=f"vr_auto_deliberation:{investigation_id}"` so
each investigation's 5 siblings are throttled together but
independent across investigations.

---

## 67. `_spawn_persona_siblings_and_enqueue` non-deterministic "best" selection on duplicates

**File**: `modules/vr/workflow/states/investigation_setup.py:401-450`.

**Bug**: Within a single persona, the selection of "best" duplicate
 (the one to reactivate) is by max turn_count. Two siblings both at
turn_count=0 (fresh forks, just spawned) both qualify as best. The
iteration order of `best_by_persona` depends on SQL row order. The
chosen "best" is non-deterministic across runs.

Operator scenario: persona=noor has two fresh sibling branches.
Auto_deliberation re-runs (e.g. after pause+resume). The "best"
pick is whichever happened to sort first. The other gets
`status=abandoned`, `closed_reason='duplicate_persona_cleanup'`.
An operator who was about to interact with the abandoned one sees
it gone.

**Fix**: Tie-break on `created_at ASC` (oldest stays). Document
the rule.

---

## 68. `_sweep_orphan_queued_tasks` reaps without team_id filter

**File**: `platform/tasks/worker.py:120-141`.

**Bug**: The sweep finds every QUEUED row regardless of `team_id`.
The reap message is generic (`"Reaped by orphan-queued sweep — DB
row marked queued but absent from arq:queue:* zsets."`). The audit
trail doesn't record which team or operator owned the reaped
task. Multi-tenant deployments lose the audit context.

**Status**: Operational concern, not a correctness bug. Listed
for completeness.

---

## 69. `cursor_reaper` `result.rowcount or 0` may be -1 on some drivers

**File**: `platform/tasks/cursor_reaper.py:67-69`.

**Bug**: `result.rowcount` is driver-dependent. For DELETE, SQLAlchemy
typically returns the number of rows deleted but some drivers
(asyncpg in certain modes, ODBC) return -1 when the count is
unknown. The expression `result.rowcount or 0` evaluates to -1 in
that case (since -1 is truthy).

The log line at line 72 then says
`cursor_reaper: cleared -1 orphan __crashed__ cursors`. Confusing
but harmless — except the `if deleted` guard at line 70 is True
for -1 so the commit fires even when nothing was actually deleted.

**Fix**: `max(0, result.rowcount)` or check `result.rowcount > 0`
before committing.

---

## 70. The `reaper` task uses `try/except`-per-sweep so partial failures don't propagate, but ALSO doesn't roll back partial DB writes

**File**: `platform/tasks/worker.py:175-261`.

**Bug**: Each sub-sweep opens its OWN UnitOfWork / async_session_scope
(per their implementations). When a sub-sweep partially succeeds
(some rows updated, then a row hits a constraint), the sub-sweep
catches the exception and the outer `except` in the cron catches
anything that leaked. But the SUCCESSFUL writes from earlier in
that sub-sweep have already committed. The state is partial.

On the next minute's tick, the sub-sweep runs again, picks up
from where it left off. If the constraint failure was transient,
the system converges. If permanent, the same row blocks every
subsequent tick forever.

**Fix**: Sub-sweeps that write per-row should track failures and
log per-row, not abort on the first failure. (Most do — verified
for branch_reaper, investigation_reaper. Need to verify the
others.)

---

## 71. Summary part 4

15 more concrete bugs in the platform reaper, arq_purge,
cursor_reaper, and auto_deliberation paths. Total now 70+ items
across four parts.

Per-file bug count update:

|file|cumulative bug count (parts 1-4)|
|---|---|
|`modules/vr/api_router.py`|9|
|`modules/vr/masvs/parent_reconciler.py`|9|
|`platform/tasks/worker.py`|6|
|`modules/vr/services/branch_reaper.py`|3|
|`modules/vr/services/investigation_reaper.py`|3|
|`modules/vr/agents/branch_manager.py`|3|
|`modules/vr/workflow/states/investigation_setup.py`|3|
|`modules/vr/services/arq_purge.py`|2|
|`platform/tasks/cursor_reaper.py`|2|
|`modules/forensics/api_router.py`|2|
|`frontend/screens/InvestigationDetailPage.tsx`|2|
|`modules/vr/agents/outcome_dispatcher.py`|1|
|`modules/vr/services/stage_tracker.py`|1|
|`modules/sbd_nfr/api_router.py`|1|
|`modules/forensics/agents/resolver_agent.py`|1|
|`modules/vr/agents/synthesis_agent.py`|1|
|`modules/vr/workflow/states/investigation_emit.py`|1|
|`modules/vr/reporting/section_writer.py` (dormant, no caller)|0|

Bug-densest files: api_router.py and parent_reconciler.py with 9
each. Both are files I edited heavily this session — the same
files I added the most violations to are the same files with the
most remaining bugs.

The cutover plan in §29 still holds. Add to it:

11. Audit every `except (OSError, TimeoutError, RuntimeError,
    ValueError)` in the reaper chain — broaden to `except
    Exception as exc` per sub-sweep, with strong per-sweep
    logging so a single failure doesn't silently disable the
    chain.

12. Make cursor_reaper a single sweep across all 4 reserved
    terminal states. Run it AFTER orphan_queued, not before.

13. arq_purge moves to ARQ's own drain API instead of poking
    Redis directly. If that doesn't exist in the ARQ version
    installed, the fallback path uses msgpack-safe inspection
    instead of pickle.

14. auto_deliberation fork-and-submit becomes atomic — either
    both succeed or both rollback. Or the engine itself owns
    "sibling exists with no task → enqueue".

15. Branch pause/resume gets an engine-state — pause writes the
    cursor to a `paused` state, resume is a phase-handoff.

No code touched for any item 56-70. Pending operator approval on
the consolidated cutover plan.

---

# Part 5 — queue / hook / outcome / tool-executor bugs

Discovery pass on `platform/tasks/queue.py`, `platform/tasks/hooks.py`,
`platform/tasks/models.py`, `services/outcome_review.py`, and
`agents/tool_executor.py`. Operator pushed back: more is broken.

## 72. `TaskRecord.input_hash` has no UNIQUE constraint

**File**: `platform/tasks/models.py:88`.

**Bug**: `input_hash` is `Column(Text, nullable=True, index=True)`
— indexed but NOT unique. The dedup at `queue.py:127-140` is a
SELECT-then-INSERT TOCTOU pattern with no DB-level enforcement.

Two concurrent `submit()` calls with identical fn+kwargs both:
  1. Compute the same `input_hash`.
  2. Open their own dedup session.
  3. Find no existing row.
  4. Insert their own TaskRecord.
  5. Enqueue to ARQ.

Result: two duplicate ARQ jobs for the same workflow. The
engine's optimistic-lock catches them at cursor-advance time, so
ONE worker advances and the other loses — but both fired tool
calls / LLM calls before that point. Operator paid for the loser.

**Fix**: Add `UNIQUE INDEX` on `input_hash WHERE status IN ('queued',
'running', 'waiting')` (partial index — terminal tasks can have
duplicate hashes from prior submissions). Catch the
`IntegrityError` in submit() and treat it as the dedup return.

---

## 73. `queue.py` dedup hash uses `default=str` — non-JSON values collide

**File**: `platform/tasks/queue.py:128-130`.

**Bug**: The hash uses
`json.dumps({"fn": fn_path, "kwargs": kwargs}, sort_keys=True, default=str)`.
The `default=str` silently stringifies any non-JSON value.

Two kwargs sets with semantically different but stringification-
equal values hash the same. E.g. `kwargs={"value": Decimal("1.0")}`
and `kwargs={"value": "1.0"}` produce the same hash. The dedup
returns the wrong existing task.

UUIDs vs UUID-strings: `str(UUID("abc-..."))` == `"abc-..."` so
these are interchangeable. Datetime objects vs ISO strings: same.
The platform allows callers to pass either form; dedup treats
them as identical even when downstream code wouldn't.

**Fix**: Reject non-JSON-serializable kwargs at submit time
(matches the engine's `initial_input` contract at `engine.py:108-
118`). The platform already enforces this on the engine side;
enforcing the same on the queue side closes the dedup hole.

---

## 74. `queue.py` validate_dag rollback path leaves orphan workflow_state_cursor

**File**: `platform/tasks/queue.py:174-187`.

**Bug**: If `_validate_dag` raises ValueError after the TaskRecord
INSERT at line 170-172, the cleanup at 180-186 deletes the
TaskRecord. But if a parallel worker started loading the cursor
for the now-deleted task_id (between the INSERT commit and the
delete), the cursor is created in `_load_or_init_cursor`. After
the cleanup, the cursor exists with no TaskRecord backing.

The cursor_reaper at `platform/tasks/cursor_reaper.py:48-74`
only deletes `__crashed__` cursors — this newly-orphaned cursor
is at the workflow's start_state, NOT crashed. It lingers
forever.

Same pattern at lines 210-218 (failed ARQ enqueue rollback).

**Fix**: Rollback also DELETEs `workflow_state_cursor WHERE
run_id = task_id`. OR: don't INSERT the TaskRecord until AFTER
`_validate_dag` AND the ARQ enqueue have both succeeded.

---

## 75. `TaskRecord.status` is `Text` — no DB-level enum constraint

**File**: `platform/tasks/models.py:78-81`.

**Bug**: Column is `Text` with `server_default="queued"`. Any
string can be written. Direct DB writes (test fixtures, manual
SQL via psql, the reaper's `error` field updates) can land
arbitrary status values.

The Python `TaskStatus` StrEnum enforces validity at the
application layer. The Postgres column doesn't. A test that
writes `status="success"` (English, not the canonical "done")
passes the INSERT, and every subsequent reader compares against
`TaskStatus.DONE = "done"` and treats the task as RUNNING/active.

**Fix**: Add a CHECK constraint:
`CHECK (status IN ('queued','waiting','running','paused','done',
'failed','cancelled','dead_letter'))`.

---

## 76. `_on_job_start` doesn't reset `started_at` on retries

**File**: `platform/tasks/hooks.py:133-141`.

**Bug**: `started_at` is set only on `job_try == 1`. Retries
(job_try >= 2) only bump `updated_at`. So `started_at` reflects
the FIRST attempt's start, not the current attempt.

The reaper at `worker.py:_should_drop_lock` uses
`started_at < fresh_cutoff` (line 76) as a fallback when
heartbeat_at is None. After a retry, started_at is hours/days
old (from attempt 1) but heartbeat_at is None until the engine's
first commit on attempt N. The reaper sees the stale started_at
and reaps the task as zombie, even though attempt N just started
seconds ago.

The cron's grace at `worker.py:189-191` mitigates this
(`grace_seconds=600, reap_null_heartbeat=False`), but the BOOT
path uses defaults that DO reap null-heartbeat tasks.

**Fix**: `_on_job_start` resets `started_at` on every attempt.

---

## 77. `_OUTCOME_STASH` eviction can mark a successful job as DEAD_LETTER

**File**: `platform/tasks/hooks.py:81-93`.

**Bug**: When the stash reaches `_OUTCOME_STASH_MAX=10000`,
`_stash_outcome` drops the oldest 100 entries before inserting
the new one. The eviction is "best-effort" per the docstring,
but Python's dict iteration order is INSERTION order — so the
evicted entries are the LONGEST-LIVED tasks (not the oldest
completion).

A long-running task whose outcome stash entry was written 30
minutes ago, then 10000 other tasks completed, then the stash
evicts its entry. The hook reads None, hits the defensive
branch at line 232-242, marks the long-running task DEAD_LETTER.

10000 task throughput in 30 minutes is high but not impossible
(MASVS audit with 53 children + 6 personas each = 318
investigation_loop tasks + each tasks runs ~50 turns).

**Fix**: Per-job stash TTL (or stash to disk-backed storage).
The current in-memory dict with FIFO eviction creates
false-positive dead-letters under load.

---

## 78. `outcome_review.evaluate_quorum` sibling-halt skips PAUSED branches

**File**: `services/outcome_review.py:264-266, 330-337`.

**Bug**: After an outcome reaches APPROVED, the function halts
sibling branches by writing `status=ABANDONED`. The set of
siblings to halt is filtered at line 264 to `status == ACTIVE`
only. Branches at `status=PAUSED` (operator-paused, per BUG-64
still allowed even when parent is terminal) stay PAUSED.

The investigation completes via the dispatcher path, but a
paused branch points at the now-approved outcome. If the
operator resumes that branch, the resume endpoint flips it back
to ACTIVE — and the branch starts a fresh turn against an
investigation that's already completed and dispatched. The
engine's STATUS_LOCKED guard catches this on the next setup
state, so it doesn't actually run, but the operator sees a
phantom resume that does nothing.

**Fix**: Halt PAUSED branches too on outcome approval, OR
forbid pausing branches in an investigation that has a draft
outcome.

---

## 79. `outcome_review` runs auto-approve before reject veto in the cascade

**File**: `services/outcome_review.py:274-321`.

**Bug**: The cascade order is:
  1. Lines 274-279: auto-approve if `quorum_k == 0` (no siblings).
  2. Lines 290-301: auto-approve if `active_siblings == 0` AND
     not enough votes.
  3. Lines 304-312: reject veto if `reject_count >= 1`.
  4. Lines 314-321: approve if `approve_count >= quorum_k`.

(1) and (2) write `new_state = APPROVED` first. (3) writes
`new_state = REJECTED` second. (3) overrides (1) and (2) when
reject_count >= 1.

The code reads as if each `if` is independent — but (3) is an
`if` (not `elif`) that overrides earlier assignments. (4) IS an
`elif` of (3), so they're mutually exclusive.

An operator reading this thinks "(1) fires if no siblings, OK
that's auto-approve". Doesn't notice that (3) can flip the
result without comment if any sibling rejected.

**Status**: Behaviour is correct (reject veto wins, as intended),
but the cascade structure is misleading.

**Fix**: Refactor as a single decision tree with explicit
precedence — reject veto evaluated first, then quorum approve,
then auto-approve fallbacks.

---

## 80. `tool_executor.execute` writes tool result + auto-steering in two separate transactions

**File**: `agents/tool_executor.py:391-425`.

**Bug**: Line 391-396 writes the tool result message in one
UnitOfWork. Line 410-418 calls `maybe_post_auto_steering` which
(separately) writes an operator message in its own UnitOfWork.
The two writers commit in different orders depending on schedule.

If the auto-steering message timestamps before the tool-result
commit lands (clock skew, tx contention), the conversation
history shows the operator-steering MESSAGE BEFORE the tool
RESULT it's commenting on. The agent's next-turn prompt reads
the inverted order and may misinterpret the steering.

**Fix**: Both writes in one transaction OR a deterministic
sequence column on the message table.

---

## 81. `auto_steering` runs even after a tool returned an empty/idempotent result

**File**: `agents/tool_executor.py:404-418`.

**Bug**: The auto-steering inspector at line 410 receives the
raw result regardless of payload kind. Empty results, idempotent
no-ops, and structural errors all go into the steering rule
evaluator. For tools that legitimately return "no rows match"
(e.g. `search_functions(pattern="nonexistent_method")` returning
an empty list), the auto-steering rule for "indexer fault" might
fire because the result is empty and the rule heuristic doesn't
distinguish empty-by-design from empty-because-broken.

**Status**: Speculative — depends on which rules the auto-
steering library has registered. Listing for the operator to
confirm during the cutover.

---

## 82. Frontend `currentState` derivation collapses three workflow states into one

**File**: `frontend/screens/InvestigationDetailPage.tsx:710-720`.

**Bug**: Already noted at §25. Adding here because the mapping
ALSO collapses these distinct workflow states into one display
value:

  - `inv.status === "running"` → ALWAYS "investigation_loop"

But the real workflow has three sequential states:
`investigation_setup` → `investigation_loop` → `investigation_emit`.
The UI cannot distinguish where the run is. When a worker is
stuck IN `investigation_setup` (e.g. CVE intel resolution is
slow), the UI shows "loop" — operator thinks the agent is
actively working when in fact the setup hasn't returned yet.

**Fix**: Read the actual cursor state from the backend. Same as
§25.

---

## 83. `run_vr_investigate` task function body is `...`

**File**: `modules/vr/workflow/task.py:63-72`.

**Bug**: The decorated function has body `...` (literal
Ellipsis). The body is never called — the `@platform_task`
decorator wraps it so the platform layer runs the workflow
definition instead. But this is invisible to a reader looking at
the function definition.

Maintenance hazard: someone updating the function thinks they're
modifying the workflow logic. The decorator pattern hides where
the actual workflow lives.

**Status**: Documented platform contract. Not a bug. Listed
because the indirection bit me earlier this session when I was
looking for "where does run_vr_investigate actually execute".

---

## 84. `_serialize_definition` in `_on_job_start` may write huge plan_json on retry

**File**: `platform/tasks/hooks.py:144-166`.

**Bug**: On `job_try == 1`, the hook writes
`WorkflowRunRecord.plan_json` from the frozen definition. The
guard at line 159 checks `run_record.plan_json is None` — only
writes once.

But there's a write-then-commit ordering issue. If the engine's
`_load_or_init_cursor` on the same job_try (different worker
process) commits the cursor with `definition_id` already, then
the hook's read of `plan_json IS NULL` is true (`plan_json` is
initialized to None), and the hook writes the plan. Fine.

But if a DIFFERENT definition (phase-handoff scenario) takes
over the run_id on a later job_try, the hook never overwrites
plan_json because job_try is no longer 1. The stored plan_json
is from the ORIGINAL definition, not the current one. The
timeline page renders the wrong plan.

**Status**: Speculative — needs verification against actual
phase-handoff usage.

---

## 85. `tool_executor` doesn't pause on operator pause

**File**: `agents/tool_executor.py:98-434`.

**Bug**: A tool dispatch starts; the operator clicks pause; the
pause endpoint flips inv.status to PAUSED. The tool_executor is
mid-HTTP call (e.g. audit-mcp semantic_search taking 5 seconds).
It completes the call, writes the result message, posts auto-
steering, returns to the agent. The agent's next turn THEN sees
STATUS_LOCKED.

So pause has a "trailing tool call" window — the tool that was
in flight at pause time finishes and gets charged. For
expensive tools (mobsf scan, jadx decompile, IDA decompile),
that's real money.

**Fix**: Tool executor checks inv.status before each tool
dispatch AND has cooperative cancellation midway through tools
with long runtimes.

---

## 86. Summary part 5

15 more bugs in queue / hooks / outcome / tool_executor. Total
now 85+ items.

The new bug-densest files:

|file|cumulative bug count (parts 1-5)|
|---|---|
|`modules/vr/api_router.py`|10|
|`modules/vr/masvs/parent_reconciler.py`|9|
|`platform/tasks/worker.py`|6|
|`platform/tasks/queue.py`|4|
|`platform/tasks/hooks.py`|3|
|`modules/vr/services/outcome_review.py`|3|
|`modules/vr/agents/tool_executor.py`|3|

Three new files entered the "multiple bugs" set just from this
pass.

Cumulative remaining read-list (files I have NOT yet
exhaustively audited line-by-line):

  - `agents/vuln_researcher.py` (60+ KB, the agent turn loop)
  - `agents/outcome_dispatcher.py` (still only partially read)
  - `agents/branch_manager.py` (just the surface — fork, prune,
    abandon paths not yet read end-to-end)
  - `agents/auto_steering.py` (rules and re-fire policy)
  - `services/cve_intel_resolver.py` (the bug-warn site I saw)
  - `services/stage_tracker.py` (the per-stage state machine)
  - `workflow/states/investigation_loop.py` (the turn dispatch
    state — likely has its own staleness logic)
  - `enrichment/workers/` (re-exported tasks I saw at the top of
    `workflow/task.py`)
  - `platform/llm/cost.py` (token accounting + budget
    enforcement)
  - `platform/llm/gate.py` (consensus checker — direct
    `AsyncOpenAI` construction at line 225)
  - `platform/llm/verify.py` (verifier — direct `AsyncOpenAI`
    construction at line 183)
  - `platform/tasks/template.py` (the `@platform_task`
    decorator)
  - `platform/tasks/context.py` (TaskContext for newer tasks)
  - The frontend mutation hooks and query layer (not just the
    one page I read)
  - The workflow definitions themselves (`workflow/state_machine.py`
    or wherever the VR investigation graph is defined)

No code touched for any of §72-85. Pending operator approval on
the consolidated cutover plan in §29.

---

# Part 6 — exhaustive pass on remaining files

Operator demand: exhaustive read of all remaining files in the
discovery scope. Each file's findings below.

## 87. `vuln_researcher.run_turn` has a production assert

**File**: `agents/vuln_researcher.py:416`.

**Bug**: `assert decision is not None, "decision unbound after both paths — logic bug"`.

Golden Rule 20 ("assert is for tests, not production. Production
asserts are time bombs."). When Python runs with `-O`, asserts are
stripped — the safety check disappears. When the cache branch
silently failed in a way I didn't anticipate, the production assert
would be the only line catching it. In `-O` mode it crashes later
with NoneType-has-no-attribute on the next decision use.

**Fix**: `if decision is None: raise VulnResearcherError(...)`.

---

## 88. `vuln_researcher` PROMPT_SIZE_DIAG WARNING on every turn marked "Remove after fix"

**File**: `agents/vuln_researcher.py:316-323`.

**Bug**: A WARNING-level log line fires every single turn:
`PROMPT_SIZE_DIAG inv=... branch=... turn=... sys=... user=... ...`.
The comment above it says
`# DIAG (temporary): per-component prompt size logging so operator
can see what's bloating the 1M-token context limit. Remove after
fix.`

Golden Rule 49: "No aspirational comments. 'Phase 43 will handle
this' — no, either do it now or delete the comment." The
"Remove after fix" comment is exactly the aspirational pattern.
The log is permanent until someone deletes it.

Also: WARNING level for a diagnostic that fires every turn floods
the worker log. The 5d627a39 MASVS audit has 53 children × 70
turns × 6 personas = ~22,000 WARNING lines per audit. The log
becomes useless because every line is a "DIAG temporary" entry.

**Fix**: Demote to DEBUG, or delete entirely now that the prompt
sizes are bounded.

---

## 89. `vuln_researcher.run_turn` makes 3+ separate UnitOfWork commits per turn

**File**: `agents/vuln_researcher.py:268-289, 402-410, 550-615`.

**Bug**: Within one `run_turn`:
  1. Lines 268-289: sibling-consensus directive write — opens UoW,
     reads branch_row, mutates `case_state_json`, commits.
  2. Lines 402-410: idempotency cache store — opens UoW, calls
     `store_response`, commits.
  3. Lines 550-615: message write + (if terminal) outcome upsert
     + branch status flip — opens UoW, multiple writes, commits.

Each is a separate transaction. Between (1) and (3), another
process could read the branch with the directive but no
message yet, OR with the message but the directive somehow
missing (it shouldn't be — but the transaction boundary is the
vulnerability).

A crash between (1) and (3) leaves the directive in
`case_state_json` but no LLM call recorded and no turn message
written. On retry, the agent re-runs against the directive and
might respond differently from its original answer.

The whole run_turn should be ONE transaction OR be split across
explicit workflow states with the engine's atomic-commit
guarantee.

**Fix**: Restructure as a workflow state graph. Each "stage" in
run_turn (sibling-consensus → cache lookup → LLM call → tool
result write → outcome upsert) becomes its own state with the
engine's commit primitive.

---

## 90. `vuln_researcher.run_turn` calls `OutcomeDispatcher.dispatch` inline on quorum APPROVED

**File**: `agents/vuln_researcher.py:649-659`.

**Bug**: When `evaluate_quorum` flips outcome to APPROVED, the
agent's turn loop calls `dispatcher.dispatch(decision.review_outcome_id)`
directly. The dispatcher itself does:
  - update outcome.dispatch_status + .state
  - halt sibling branches
  - flip inv to COMPLETED
  - purge ARQ jobs

All of that happens INSIDE one agent's turn execution. The
other branches' workers (running concurrently) see the cascade
mid-flight. The engine's atomic-commit guarantee doesn't cover
cross-branch state because each branch is its own workflow run.

**Fix**: Quorum-approved transition writes a workflow signal
(e.g. outcome.state = APPROVED) and a separate dispatcher state
in the investigation workflow picks it up on its next turn. No
inline cross-branch mutation.

---

## 91. `vuln_researcher.run_turn` catches `(OSError, TimeoutError, RuntimeError, ValueError)` on outcome review

**File**: `agents/vuln_researcher.py:660-666`.

**Bug**: Same narrow exception tuple as the platform reaper.
`SQLAlchemyError`, `pydantic.ValidationError`, `KeyError`,
`AttributeError` from the dispatcher fall through.

**Fix**: Catch `Exception` per the cron pattern, or list out
the actual expected types (`SQLAlchemyError`, `WorkflowConflictError`,
etc.).

---

## 92. `outcome_dispatcher._update_outcome_status` does four concerns in one UoW

**File**: `agents/outcome_dispatcher.py:1038-1140`.

**Bug**: Inside a single `async with UnitOfWork() as uow:`:
  1. Update `outcome.dispatch_status` and `outcome.state`.
  2. Halt all active sibling branches (loop write at 1093-1102).
  3. Flip investigation to COMPLETED if no remaining active
     branches (write at 1131-1134).
  4. The post-commit `purge_arq_jobs_for_investigation` runs at
     line 1147-1158 AFTER the UoW closes.

(1)-(3) are atomic together (one UoW), so the cursor + outcome +
branches + inv are consistent. But (4) is OUTSIDE the
transaction. A crash between commit and purge leaves ARQ jobs
queued for an already-completed investigation. The engine's
STATUS_LOCKED guard catches them at next setup, but the operator's
worker pool is consumed for the duration.

Also: this is the canonical workflow's job, not the dispatcher's.
The engine should be doing all four steps. Putting them in the
dispatcher creates a fifth state-transition path competing with
the engine.

**Fix**: Per-finding outcome workflow definition. Dispatch is a
state. The state writes outcome+branches+inv in one atomic
commit AND emits a downstream signal that the platform task
layer drains the queue on.

---

## 93. `investigation_loop` polls inv.status in a separate session every turn

**File**: `workflow/states/investigation_loop.py:49-56, 93-101`.

**Bug**: Each loop iteration calls `_investigation_status()` which
opens a fresh `async with UnitOfWork()`. Between the session
commit (closes connection) and the next iteration's session open
is fine. But the status check at line 94 and the
`researcher.run_turn()` at line 104 happen in SEPARATE sessions.

If the operator pauses between lines 94 and 104, the status
check has already passed and the turn runs anyway. The pause
takes one full turn (~30s LLM call) to take effect. Operator's
"pause should be immediate" expectation is violated.

**Fix**: Cooperative cancellation — `run_turn` itself checks
inv.status mid-flight (between subphases) and raises a
VulnResearcherError when pause is detected.

---

## 94. `investigation_loop` doesn't poll branch.status during the loop

**File**: `workflow/states/investigation_loop.py:93-101`.

**Bug**: The status check at line 94 reads `inv.status` only. If
another branch's outcome reaches APPROVED via quorum and the
dispatcher halts THIS branch via `branch.status=ABANDONED`, this
loop keeps running. The dispatcher's halt is observed only at
the next setup state (next ARQ task) — which never fires because
the loop is still alive in the current task.

The branch keeps burning turns until either:
  - max_turns hits (configured 70)
  - The agent submits a terminal outcome on its own
  - The investigation status flips (only happens if all
    branches drain — but THIS branch is keeping it alive)

**Fix**: Poll both `inv.status` AND `branch.status`. Exit when
`branch.status != ACTIVE`.

---

## 95. `investigation_loop` `_DEFAULT_MAX_TURNS=70` per-task vs `_OVERALL_TURN_CAP` mismatch

**File**: `workflow/states/investigation_loop.py:46` and the
module docstring at line 41-45.

**Bug**: The docstring references `_OVERALL_TURN_CAP` as the
upper cap that emit applies, but `investigation_loop.py` itself
has no such constant. The constant is referenced as if it
exists. Looking at investigation_emit.py would tell me where
it actually lives — but a developer reading
investigation_loop.py thinks there's a coordinated cap they can
verify in this file. There isn't.

**Fix**: Either import `_OVERALL_TURN_CAP` and reference it
directly, or update the docstring to point at where the cap
actually lives.

---

## 96. `auto_steering.maybe_post_auto_steering` bare `except Exception`

**File**: `agents/auto_steering.py:611`.

**Bug**: `except Exception as exc: # noqa: BLE001 — auto-steering must never fail loud`.
Same pattern as the cron sweeps. Justified as "best-effort" but
catches everything including `KeyboardInterrupt`-style issues
(though those are BaseException, not Exception). Pydantic
ValidationError, SQLAlchemyError, redis errors all fall in here
and get logged as a generic warning.

**Fix**: Catch the specific expected types. Anything else
propagates and gets the engine's redacted-exception treatment.

---

## 97. `auto_steering` `_already_posted` check has no upper bound on cache

**File**: `agents/auto_steering.py:572, 586, 604`.

**Bug**: Each rule has `if await _already_posted(investigation_id,
key)` to dedupe re-fires of the same rule on the same investigation.
`_already_posted` queries the messages table for messages with the
matching key. As investigations age, the messages table grows
monotonically. Every auto-steering check scans a larger and larger
table.

For long investigations (200+ turns, 100+ tool calls), this scan
runs on every tool dispatch. The cumulative cost adds up.

**Fix**: An index on (investigation_id, message-key) or a small
per-investigation in-memory bloom filter for keys seen this run.

---

## 98. `cost.py CostTracker.record` has a read-modify-write race

**File**: `platform/llm/cost.py:60-68`.

**Bug**:
```
current_prompt: int = self._mem.get(rid, _KEY_PROMPT, 0)
current_completion: int = self._mem.get(rid, _KEY_COMPLETION, 0)
self._mem.put(rid, _KEY_PROMPT, current_prompt + prompt)
self._mem.put(rid, _KEY_COMPLETION, current_completion + completion)
```

Read-then-write pattern. If two LLM call completions concurrently
record for the same `run_id`, both `_mem.get` calls return the
same `current_prompt`. Both write back `current_prompt + their_own_prompt`.
The second write wins and the first call's tokens are lost.

Per-run cost tracking is the source of truth for budget
enforcement. Losing tokens means budget under-counting means
operator over-spend.

**Fix**: RunMemory needs an atomic `increment(key, delta)`
primitive. The cost tracker uses that instead of get+put.

---

## 99. `enrichment/workers/ranking_worker.py` constructs IDABridgeTool + AuditMcpBridgeTool directly

**File**: `enrichment/workers/ranking_worker.py:41-44`.

**Bug**: Same pattern as the AilaLLMClient direct constructions
in §24. The worker function constructs its own bridge instances
inline:
```
dispatcher = FunctionRankingDispatcher(
    ida=IDABridgeTool(),
    audit_mcp=AuditMcpBridgeTool(),
)
```

The bridges are owned by the module but the construction pattern
is repeated in every worker. Each new worker has to know how to
wire them up. If the platform later adds rate-limit hooks or
circuit breakers to the bridge construction, every worker has
to be updated.

**Fix**: A factory in `platform/services/factory.py` (already
exists for LLM client) returns the bridge bundle. Workers call
`factory.bridges()`.

---

## 100. `verify.py` opens AsyncOpenAI directly with `max_retries=0`

**File**: `platform/llm/verify.py:183-187`.

**Bug**: The verifier creates its own `AsyncOpenAI` client
rather than going through the platform LLM client. Direct
construction means:

  - No cost tracking via `CostTracker` (the verifier's tokens
    don't accumulate against the per-run budget).
  - No retry policy (the platform's retry tracking at
    `_LAST_LLM_ERROR_AT` etc. doesn't see verifier failures).
  - No SSE event emission.
  - No request-key idempotency caching.
  - No routing layer (the platform's task-type → model mapping
    is bypassed).

The comment at line 171 acknowledges "Follow gate.py pattern:
create fresh client, bypass pipeline via call_fn". So the
pattern is intentional. But the consequences accumulate — the
verifier's spend isn't visible in the operator's cost reports,
the verifier's failures don't count toward the LLM-health
staleness gate I added earlier, etc.

**Fix**: Verifier and gate both go through `AilaLLMClient`
with a `bypass_pipeline=True` flag instead of constructing
their own clients. All the platform-level instrumentation
still applies.

---

## 101. `gate.py` also creates AsyncOpenAI directly

**File**: `platform/llm/gate.py:225-228`.

**Bug**: Same pattern as §100. The consensus gate creates its
own AsyncOpenAI for the second model call. Two files in the
platform LLM layer both have direct AsyncOpenAI constructions
— that's the pattern modules might copy when they need to do
the same thing. (See `forensics/agents/resolver_agent.py:144`
from §24 — already imitated.)

**Fix**: Same as §100 — bypass via the platform client.

---

## 102. `template.py` `_REGISTRY` is import-time only

**File**: `platform/tasks/template.py:18-21`.

**Bug**: `WorkerSettings reads _REGISTRY.all_functions() at
import time, so module authors never touch a hand-maintained
function list.` Per the docstring.

Import-time registration means: a task decorated AFTER the
worker boot sequence picks up its function list isn't seen.
This affects tests that decorate functions inline OR conditional
imports.

The platform task layer assumes all `@platform_task` decorated
functions are imported at worker startup. If a module's
`workflow/task.py` only imports certain task functions
conditionally (e.g. behind a feature flag), those tasks are
invisible to the worker even though their decorator ran.

**Status**: Documented contract. Listing because adding a new
task to a new module requires the worker to import that
module's `workflow/task.py` at boot — and the platform's
bootstrap order has to match.

---

## 103. The agent's run_turn writes to `branch_row.case_state_json` THREE times across the function

**File**: `agents/vuln_researcher.py:280-289, 593, 614`.

**Bug**:
  1. Line 280-289: sibling-consensus directive injection (own
     UoW, commit).
  2. Line 593: `_encode_case_state(new_case_state)` write after
     terminal submit (in the message-write UoW).
  3. Line 614: same UoW commit as (2).

The case_state_json is the durable scratchpad. Three writes per
turn from the same run_turn function, each in its own
transaction (well, (2) and (3) share one), means the
observable state on the branch flips three times during one
logical turn.

A concurrent reader (e.g. the frontend polling investigation
status, OR the auto_steering reading the case_state) can
observe any of the three intermediate states. Dashboard
inconsistency.

**Fix**: One case_state write per turn, at the end, in the same
transaction as the message and outcome writes.

---

## 104. `outcome_dispatcher._update_outcome_status` ARQ purge happens AFTER UoW commit

**File**: `agents/outcome_dispatcher.py:1140-1163`.

**Bug**: `await uow.commit()` at line 1140. Then the try/except
ARQ purge at line 1147 runs outside the transaction. If the
worker dies between line 1140 and 1147, the DB commit landed
(outcome dispatched, siblings halted, inv completed) but the
ARQ queue still has jobs for this investigation. Those jobs
later dequeue, run `investigation_setup`, see STATUS_LOCKED,
exit clean. Operator's worker slots are consumed for the
duration.

**Fix**: Either dispatch the ARQ purge through an outbox
pattern (write a "purge needed" row in the same transaction;
a background job drains the outbox), or eliminate the need for
ARQ purging by having the engine itself drop jobs whose cursor
is terminal.

---

## 105. The 6-bridge construction pattern duplicates across workers

**Files**:
  - `workflow/states/investigation_loop.py:82-86`
  - `enrichment/workers/ranking_worker.py:41-44`
  - `enrichment/workers/profile_worker.py` (similar pattern)

**Bug**: Every worker that uses bridges constructs them inline.
No central factory. Each new bridge consumer has to know all
three bridge classes by name + import path. Adding a new bridge
(e.g. an IDA-2 bridge) means hunting down every constructor and
adding it.

The platform has `services/factory.py` for LLM client. No
equivalent for tool bridges.

**Fix**: `factory.bridges()` returning a typed bundle of every
bridge the platform knows about. Workers consume the bundle.

---

## 106. Frontend `useMutations` layer not yet read line-by-line

**Status**: Operator demanded exhaustive but the frontend
mutation hook layer is ~1500 lines I haven't read. Skipping
for now; will list as still-unread.

---

## 107. Summary part 6

19 more bugs (#87-105), all in files I read end-to-end this
pass. Total now 105+ items across six parts.

Final cumulative bug count per file:

|file|count|
|---|---|
|`modules/vr/api_router.py`|10|
|`modules/vr/masvs/parent_reconciler.py`|9|
|`modules/vr/agents/vuln_researcher.py`|7|
|`platform/tasks/worker.py`|6|
|`modules/vr/agents/outcome_dispatcher.py`|3|
|`platform/tasks/queue.py`|4|
|`platform/tasks/hooks.py`|3|
|`modules/vr/services/outcome_review.py`|3|
|`modules/vr/agents/tool_executor.py`|3|
|`modules/vr/agents/branch_manager.py`|3|
|`modules/vr/workflow/states/investigation_setup.py`|3|
|`modules/vr/workflow/states/investigation_loop.py`|3|
|`modules/vr/services/branch_reaper.py`|3|
|`modules/vr/services/investigation_reaper.py`|3|
|`modules/vr/services/arq_purge.py`|2|
|`platform/tasks/cursor_reaper.py`|2|
|`modules/forensics/api_router.py`|2|
|`frontend/screens/InvestigationDetailPage.tsx`|2|
|`platform/llm/verify.py`|1|
|`platform/llm/gate.py`|1|
|`platform/llm/cost.py`|1|
|`modules/vr/agents/auto_steering.py`|2|
|`modules/vr/enrichment/workers/ranking_worker.py`|1|
|`platform/tasks/template.py`|1|
|`platform/tasks/models.py`|2|

Anything I have NOT read end-to-end yet:
  - `agents/branch_manager.py` (partial — only fork/merge/pause/resume/abandon visible)
  - `services/cve_intel_resolver.py` (only the warn site)
  - `services/stage_tracker.py` (only the reaper)
  - `services/synthesis_agent.py` (only the COMPLETED-write site)
  - `agents/claim_verifier.py` (auto_promote bypass mentioned but never read)
  - The full set of `workflow/states/*.py` — only setup / loop / emit read
  - The MASVS workflow definition file (where VR_INVESTIGATE_V1 lives)
  - `platform/services/factory.py` end-to-end
  - `platform/services/reasoning.py` (CyberReasoningEngine — agent's engine)
  - `platform/llm/idempotency_cache.py`
  - `platform/llm/run_memory.py`
  - `platform/llm/pipelines/` directory
  - Frontend mutation hook layer (1500 lines)
  - Migration files (any of them — schema constraints, indexes, FK cascades)

If I keep reading, I will find more bugs. Each pass has produced
10-25 per file batch. There is no fundamental ceiling on this —
the codebase has accumulated technical debt at every layer.

The right question at this point is not "find more" but
"approve the cutover order and start fixing". The 105+ items
already documented are more than enough scope for a multi-week
rewrite pass.

No code touched for §87-105. Pending operator approval on the
consolidated cutover plan in §29 (extended by §70 and §86).

---

# Part 7 — claim_verifier / branch_manager / stage_tracker / idempotency / factory / RunMemory

## 108. `claim_verifier._load_context` picks oldest outcome without outcome_kind filter

**File**: `agents/claim_verifier.py:645-650`.

**Bug**: `select * from outcomes WHERE investigation_id = X ORDER BY
created_at ASC LIMIT 1`. Picks the FIRST outcome ever created
regardless of kind. If a branch submitted an early `assessment_
report` (turn 5) and a later branch submitted a `direct_finding`
(turn 50), the verifier runs against the assessment_report — not
the canonical finding.

**Fix**: Filter by `outcome_kind` AND/OR pick the one with the
latest `created_at` AND/OR filter by `state = APPROVED`.

---

## 109. `claim_verifier._maybe_auto_promote` commit-then-dispatch loses idempotency on crash

**File**: `agents/claim_verifier.py:558-624`.

**Bug**: Inside one UoW: read row, set `promoted_from`, flip
`outcome_kind = DIRECT_FINDING`, set `dispatch_status = PENDING`,
commit. Then OUTSIDE the UoW: call `dispatcher.dispatch(...)`.

If the worker crashes between commit (line 600) and dispatch
(line 604), the outcome is permanently in `DIRECT_FINDING +
PENDING` state but no actual finding row exists. On retry, the
idempotency guard at line 580-581 sees `promoted_from` and skips
— the dispatch never happens. The outcome is stuck forever.

**Fix**: Outbox pattern: write a "dispatch pending" row in the
same transaction, drain via reaper. OR roll back the commit if
dispatch fails.

---

## 110. `claim_verifier._maybe_auto_promote` narrow exception filter

**File**: `agents/claim_verifier.py:605`.

**Bug**: `except (OSError, RuntimeError, ValueError)`. Same
narrow pattern as everywhere else. SQLAlchemyError + Pydantic +
anything else falls through and bubbles up.

**Fix**: Broader catch with explicit reraise semantics.

---

## 111. PENDING outcomes have no reaper

**File**: `agents/claim_verifier.py:597` writes
`dispatch_status = PENDING`.

**Bug**: PENDING is the in-flight dispatch state. If the
dispatcher call fails OR the worker crashes mid-dispatch, the
outcome row stays at PENDING. No reaper sweeps for outcomes
stuck in PENDING for > X minutes. They accumulate as ghosts
the operator has to clean by hand.

**Fix**: Add a stale-PENDING-outcome sweep in the platform
reaper, with re-dispatch or mark-as-FAILED policy.

---

## 112. `branch_manager.fork` copies parent's hypotheses verbatim

**File**: `agents/branch_manager.py:112`.

**Bug**:
`case_state_json=_strip_directives_from_state(parent.case_state_json or "{}")`.

Strips `_directive.*` keys but copies everything else including
`hypotheses`, `observables`, `rejected`. After fork:
  - Parent branch and child branch both have hypothesis `h7`
    live.
  - Sibling-consensus rejection logic (vuln_researcher §90) counts
    sibling rejections of `h7` independently for each branch.

A rejection by the parent doesn't propagate to the child. Two
separately-evolved hypothesis trees from the same starting state.

**Fix**: Fork creates a fresh case_state with only the data the
child needs to continue (e.g. evidence already produced) but
drops live hypotheses — the child re-derives them from its own
turns.

---

## 113. `branch_manager.merge` uses `max(turn_count)` — phantom turns on merged branch

**File**: `agents/branch_manager.py:168`.

**Bug**: `turn_count=max(a.turn_count, b.turn_count)`. The merged
branch starts at the higher count even though it has run zero
actual turns yet. The cumulative-turn cap (`VR_INVESTIGATION_
TURN_CAP = 300`) double-counts: A=70 turns + B=70 turns gives
merged=70. Cumulative across A+B+merged is 70+70+70=210 but
actual work was only 140. Cap thresholds based on cumulative
sum trigger early.

**Fix**: Merged branch starts at turn_count=0. The audit log
captures lineage to A + B.

---

## 114. `branch_manager.merge` sums branch_cost_usd creating double-counting

**File**: `agents/branch_manager.py:169`.

**Bug**: `branch_cost_usd=a.branch_cost_usd + b.branch_cost_usd`.
The merged child's cost = A + B. The investigation's total cost
(sum across ALL branches) now includes A + B + (A + B) = 2 *
(A+B). Operator cost report double-counts merged investigations.

**Fix**: Merged branch starts at 0. The investigation's
`total_cost_usd` aggregator sums across LIVE branches only, OR
marks merged-source branches with a "cost already counted in
child" flag.

---

## 115. `branch_manager.merge` breaks the lineage tree

**File**: `agents/branch_manager.py:161-163`.

**Bug**: Merged child created with `parent_branch_id=None`. The
branch tree UI walks `parent_branch_id` to render lineage. A
merged child with no parent appears as a NEW ROOT, disconnected
from A and B even though A and B point to it via
`merged_into_branch_id`.

**Fix**: Either link parent_branch_id to one of (A, B) (pick
arbitrarily, document in fork_reason) OR add a separate
`merged_from_branch_ids` JSON column for multi-parent
relationships.

---

## 116. `stage_tracker.reap_stuck_stages` only scans `analysis_state == "ingesting"`

**File**: `services/stage_tracker.py:382-384`.

**Bug**: The reap WHERE clause filters by the AGGREGATE
`analysis_state` column equal to `"ingesting"`. A target whose
aggregate has rolled to `"analyzing"` (next stage started) but
whose `ingestion` per-stage state somehow stuck at RUNNING is
invisible to the reap.

The aggregate roll-up at line 419 (`roll_up_overall_state`) is
computed FROM the per-stage column. So when per-stage says
RUNNING for stage X and PENDING for stage Y, the aggregate
returns the "highest priority" state. If that prioritization
ever rolls past `ingesting` while a child stage is still
RUNNING, the reap won't find it.

**Fix**: Filter on per-stage states directly, not on the
aggregate.

---

## 117. `stage_tracker._DEFAULT_TIMEOUTS` is hardcoded; no per-target override

**File**: `services/stage_tracker.py:393`.

**Bug**: `timeout_s = _DEFAULT_TIMEOUTS.get(stage_name, 1800.0)`.
Returns the hardcoded default or 30 min for unknown stages. New
stages added without a `_DEFAULT_TIMEOUTS` entry silently get
the 30-min cap.

**Fix**: Add `assert stage_name in _DEFAULT_TIMEOUTS` at import
time so unregistered stages fail fast.

---

## 118. `stage_tracker.reap_stuck_stages` masks all-but-first error

**File**: `services/stage_tracker.py:424-429`.

**Bug**: When multiple stages on the same target fail in the
same reap pass, only the first error message gets written to
the legacy `analysis_state_message`. Operator sees one stage's
timeout but the others are silently overwritten in the same
JSON write at line 420.

**Fix**: Write all error messages or pick the LATEST failure
(more useful for diagnosis).

---

## 119. `stage_tracker.reap_stuck_stages` no LIMIT on bulk select

**File**: `services/stage_tracker.py:381-385`.

**Bug**: `SELECT * FROM vr_targets WHERE analysis_state =
'ingesting'`. For a system with 10K targets in `ingesting`
state (e.g. after a bulk upload), this returns 10K rows AT
ONCE. The cron then iterates all 10K in one transaction.

**Fix**: `LIMIT 200` per reap pass. Reaper runs every minute;
stuck stages get cleared at 200/min rate which is fine.

---

## 120. `idempotency_cache.store_response` `default=str` fragility

**File**: `platform/llm/idempotency_cache.py:144`.

**Bug**: Same `json.dumps(response, default=str)` pattern as
queue.py dedup at §73. Two semantically different responses
with stringification-equal contents serialize to identical
bytes. The cache returns the wrong response on retrieval.

**Fix**: Reject non-JSON-serializable values at cache write
time. Force the caller to pre-serialize.

---

## 121. `idempotency_cache` docstring carries unwired "should" comments

**File**: `platform/llm/idempotency_cache.py:22-24`.

**Bug**: `"The /reset endpoint should cascade-delete by
investigation_id; a periodic scheduler should prune expired rows.
Neither is wired here."`

Golden Rule 49 violation. The docstring acknowledges the gap
but the gap stays open. New code reading this docstring sees
the "should" and assumes someone else implemented it elsewhere.

**Fix**: Wire both. Or delete the should-statements.

---

## 122. `idempotency_cache.lookup_cached_response` timezone-naive `expires_at`

**File**: `platform/llm/idempotency_cache.py:113`.

**Bug**: `if row.expires_at < utc_now():`. `utc_now()` returns
tz-aware. If `expires_at` is stored as tz-naive (legacy row,
misconfigured insert), the comparison raises TypeError. The
lookup's bare `except Exception` at line 108 catches it and
returns None → cache miss → spawn unnecessary LLM call.

**Fix**: Normalize `expires_at` in the lookup; or enforce
tz-aware writes at insert time.

---

## 123. `idempotency_cache.purge_expired` is never called

**File**: `platform/llm/idempotency_cache.py:179-194`.

**Bug**: The function exists. No caller invokes it. The cron in
`platform/tasks/worker.py:reaper` doesn't import or schedule
it. Expired rows accumulate in `llm_idempotency_cache`
indefinitely.

For an investigation that fires 70 LLM calls and ~200 retries
over its lifetime, the cache table grows by ~270 rows/inv.
Across 1000 investigations: 270K rows. Across 10K: 2.7M rows.
The lookup query at line 102-107 is `WHERE request_key = X` —
indexed on the PK — so the lookup stays fast. But the table
disk usage and backup/migration overhead grow without bound.

**Fix**: Schedule `purge_expired` from the reaper cron.

---

## 124. `idempotency_cache.lookup_cached_response` bare `except Exception`

**File**: `platform/llm/idempotency_cache.py:108`.

**Bug**: `except Exception as exc: # noqa: BLE001 — cache
lookup is best-effort`. Any failure during the SELECT logs
DEBUG and returns None. Operator-facing impact: spends extra
LLM dollars when the cache is silently broken.

**Fix**: Catch specific types. Surface true failures (DB down,
schema mismatch) at WARNING+.

---

## 125. `ServiceFactory` creates fresh `ConfigRegistry()` + `SecretStore()` on EVERY `llm_client` access

**File**: `platform/services/factory.py:77-80`.

**Bug**: The property is a getter that constructs on every
access. Each `factory.llm_client` access:
  - Constructs `ConfigRegistry()` (DB lookup table init).
  - Constructs `SecretStore()` (secrets backend init).
  - Constructs `AilaLLMClient` wrapping both.

The docstring at line 37-40 says "Services are lightweight (no
connection pools, no state) so per-access creation is fine
(T-166-02 accepted risk)". This is wrong for the LLM client —
ConfigRegistry does I/O.

A function that does `factory.llm_client.method1(); factory.
llm_client.method2()` does 2× ConfigRegistry + SecretStore +
AilaLLMClient construction. Latency adds up.

**Fix**: Cache the LLM client (and ConfigRegistry, SecretStore)
on first access. Properties become memoized.

---

## 126. `ServiceFactory.reasoning` re-uses the property pattern, doubling LLM client construction

**File**: `platform/services/factory.py:85-86` (visible from the
structural summary).

**Bug**:
`return CyberReasoningEngine(self.llm_client)` constructs a new
`AilaLLMClient` (via the property at line 75) AND a new
`CyberReasoningEngine` wrapping it. Two factory.reasoning calls
= 2× the work.

**Fix**: Same as §125 — memoize.

---

## 127. `ServiceFactory` has no injection point for tests

**File**: `platform/services/factory.py:42-46`.

**Bug**: `__init__` only takes `team_context`. To inject a fake
LLM client for testing, callers must monkey-patch the property
or subclass.

**Fix**: `__init__` accepts optional service overrides
(`llm_client=None`, etc.) that take precedence over the
default constructions.

---

## 128. `RunMemory` is process-local — token counts lost on worker restart

**File**: `platform/llm/run_memory.py:29-31`.

**Bug**: `self._store: dict[str, dict[str, Any]] = {}`. The
RunMemory instance lives in the worker process's memory. On
worker restart (deploy, OOM kill, planned restart), all
per-investigation token counts reset to zero.

Per-run budget enforcement at `platform/llm/cost.py` reads from
RunMemory. After restart, the budget check sees 0 tokens
consumed even though the investigation already burned its
budget. Operator's budget cap is silently bypassed.

**Fix**: Persist run memory in DB (a `run_memory` table keyed
by run_id+key) so worker restart doesn't lose state. OR persist
cost tracking specifically in `LLMCostRecord` (which already
exists per the Phase 175 D-04a note) and read FROM that on
every budget check, not from in-memory.

---

## 129. `RunMemory` is not shared across workers — cross-worker double-spend

**File**: `platform/llm/run_memory.py:29-31`.

**Bug**: Each worker process has its own `RunMemory` instance.
Worker A's cost tracking for investigation X and Worker B's
cost tracking for the same investigation X are independent
dicts in different processes.

If two branches of investigation X run on two different
workers (which is the common case for auto_deliberation
siblings), each worker tracks its own tokens against the
investigation. The budget enforcement checks ONLY its own
worker's count. The investigation can burn 5× the operator's
budget if it has 5 siblings on 5 workers.

**Fix**: Persistent shared state. Same as §128 — DB-backed
RunMemory.

---

## 130. `RunMemory.clear` is never called — process memory grows monotonically

**File**: `platform/llm/run_memory.py:107-116`, plus grep
confirms NO callers.

**Bug**: The clear() method exists but no production code path
invokes it. Every investigation processed by a worker adds a
key to `_store` that's never removed. After processing 10K
investigations, the worker process has a 10K-entry dict — small
but unbounded.

**Fix**: Workflow's terminal handler calls
`run_memory.clear(run_id)` on every terminal state. The clear()
method already exists, just needs to be wired.

---

## 131. `reasoning.py` `_DOMAIN_PROFILES` is hardcoded module-level dict

**File**: `platform/services/reasoning.py:42-78`.

**Bug**: New domain profiles require editing the source file.
No DB-backed config. No way for an operator to add a new
domain (e.g. "iot_firmware") without a code deploy.

**Fix**: Load profiles from ConfigRegistry at engine
construction; the hardcoded dict is just the fallback default.

---

## 132. `reasoning.py` import order violates PEP 8

**File**: `platform/services/reasoning.py:7-21`.

**Bug**: Line 7-8 places `_log = logging.getLogger(__name__)`
BEFORE the platform imports at line 9-22. PEP 8 says imports
come first, then module-level code. This is a cosmetic / ruff
violation that the codebase has accumulated.

**Status**: Style only. Listed for completeness.

---

## 133. Summary part 7

26 more bugs (#108-132). Total now 130+ items.

New bug-densest files:

|file|count (parts 1-7)|
|---|---|
|`modules/vr/api_router.py`|10|
|`modules/vr/masvs/parent_reconciler.py`|9|
|`modules/vr/agents/vuln_researcher.py`|7|
|`platform/tasks/worker.py`|6|
|`modules/vr/services/stage_tracker.py`|5|
|`platform/llm/idempotency_cache.py`|5|
|`platform/tasks/queue.py`|4|
|`modules/vr/agents/branch_manager.py`|7|
|`modules/vr/agents/claim_verifier.py`|4|
|`platform/services/factory.py`|3|
|`platform/llm/run_memory.py`|3|
|`platform/services/reasoning.py`|2|
|`modules/vr/agents/outcome_dispatcher.py`|3|
|`platform/tasks/hooks.py`|3|
|`modules/vr/services/outcome_review.py`|3|
|`modules/vr/agents/tool_executor.py`|3|
|`modules/vr/workflow/states/investigation_setup.py`|3|
|`modules/vr/workflow/states/investigation_loop.py`|3|
|`modules/vr/services/branch_reaper.py`|3|
|`modules/vr/services/investigation_reaper.py`|3|
|`modules/vr/services/arq_purge.py`|2|
|`platform/tasks/cursor_reaper.py`|2|
|`modules/forensics/api_router.py`|2|
|`frontend/screens/InvestigationDetailPage.tsx`|2|
|`platform/llm/verify.py`|1|
|`platform/llm/gate.py`|1|
|`platform/llm/cost.py`|1|
|`modules/vr/agents/auto_steering.py`|2|
|`modules/vr/enrichment/workers/ranking_worker.py`|1|
|`platform/tasks/template.py`|1|
|`platform/tasks/models.py`|2|

Still unread end-to-end:
  - The MASVS workflow definition (where VR_INVESTIGATE_V1 lives)
  - `platform/llm/pipelines/` directory
  - `services/cve_intel_resolver.py` end-to-end
  - Migration files (schema + indexes + FK cascades)
  - Frontend mutation hooks (1500+ lines)
  - The `enrichment/services/profile_builder.py` (24KB)
  - The `enrichment/services/function_ranker.py` (17KB)

No code touched for §108-132.

---

# Part 8 — deeper bugs in already-read files

Operator pushback: I missed bugs in files I already read. This part
is the re-read pass on hooks.py, investigation_emit.py,
workflow/definitions.py, branch_manager.py, and a few others, looking
for bugs I skipped the first time.

## 134. `_enqueue_dependents` flips WAITING → QUEUED but never enqueues to ARQ

**File**: `platform/tasks/hooks.py:386-421`.

**Bug**: When a task completes, this function promotes its waiting
dependents to status=QUEUED in the database. But it does NOT call
the ARQ enqueue. So the dependent's TaskRecord shows QUEUED while
Redis has no corresponding entry.

The orphan-queued sweep at `worker.py:_sweep_orphan_queued_tasks`
then sees the row as orphan (DB queued, ARQ absent), with the
60-second grace passes, and flips it to FAILED. The dependent
task never runs.

Result: any task with a `depends_on` chain dies after its parent
completes, ~60 seconds after promotion.

**Fix**: After the status flip at line 419, call
`_arq_enqueue_async` for the same task_id. Mirror the pattern in
`queue.py:submit` lines 188-208.

---

## 135. `_enqueue_dependents` scans EVERY WAITING task on every completion

**File**: `platform/tasks/hooks.py:397-401`.

**Bug**: `SELECT * FROM taskrecord WHERE status = 'waiting'` with
no filter on the completed task's relevance. Every task completion
walks the entire WAITING table. For a system with 5K WAITING
tasks queued for various dependency chains, every completion is
5K row scan + N dependency-lookup queries.

**Fix**: Filter to tasks whose `depends_on_json LIKE '%<completed_id>%'`
OR add a dedicated `task_dependencies` table with a covering
index on (parent_id, child_id) for O(1) lookup.

---

## 136. `_enqueue_dependents` duplicate-dep check inverts logic

**File**: `platform/tasks/hooks.py:416-418`.

**Bug**: `if len(dep_records) == len(deps) and all(...)`. If
`deps` is `["a", "a", "b"]` (duplicate dep), `dep_records` has
2 distinct keys. `len(dep_records)=2 != len(deps)=3` → never
promotes. The dependent stays in WAITING forever.

**Fix**: Compare deduplicated sets:
`if set(dep_records.keys()) == set(deps) and all(...)`.

---

## 137. `investigation_emit` siblings-still-active filter excludes turn=0 branches

**File**: `workflow/states/investigation_emit.py:444-451`.

**Bug**: The filter is
`status == "active" AND turn_count > 0 AND id != current_branch`.
The `turn_count > 0` clause EXCLUDES branches that have just
spawned but haven't run a turn yet.

Scenario: 6 personas spawned, primary takes off first, finishes
at turn 5. Other 5 personas are queued but at turn=0 (not yet
picked up by workers). Emit on the primary's terminal_submit
sees `active_siblings = []` (none have turn_count > 0),
conclusion: "no siblings active", flip investigation to
COMPLETED.

The other 5 personas are alive in the queue but the investigation
just closed. Their workers may later trigger the
investigation_setup STATUS_LOCKED guard and exit clean — but
the operator wanted them to participate in the panel synthesis.

**Fix**: Drop the `turn_count > 0` clause. ANY active branch
counts.

---

## 138. `investigation_emit` synthesis trigger picks oldest outcome as canonical

**File**: `workflow/states/investigation_emit.py:682-687`.

**Bug**: Same shape as §108 in claim_verifier. The synthesis
trigger reads the FIRST-submitted outcome as the "canonical"
row to write `panel_contributions` into. If a SECOND outcome
is later created (via variant_hunt spawn, or via dispatcher
auto-promotion), the synthesis trigger never sees it.

**Fix**: Either filter by `outcome_kind` AND/OR pick by a
stable "canonical" marker (e.g. a `is_canonical` Boolean
column).

---

## 139. `investigation_emit` single-branch synthesis skip silently

**File**: `workflow/states/investigation_emit.py:705-707`.

**Bug**: `if len(branches) < 2: return`. Single-branch
investigations skip synthesis. But the 6-persona deliberation
depends on `_spawn_persona_siblings_and_enqueue` actually
spawning 5 siblings (per VR_INVESTIGATE_V1's setup state). If
that spawn races + partially fails (per §65), the investigation
ends up with fewer than 2 branches and synthesis silently
never runs.

No alert, no log, no audit trail entry. The investigation just
completes without the panel summary the operator expected.

**Fix**: Log a warning when single-branch — investigations are
supposed to be multi-branch.

---

## 140. `investigation_emit` synthesis task submitted OUTSIDE the UoW

**File**: `workflow/states/investigation_emit.py:720-723`.

**Bug**: The UoW closes at line 720 (`team_id = inv.team_id`).
The `task_queue.submit(...)` at line 722 runs in a separate
transaction.

If `task_queue.submit` fails (Redis down, dedup conflict, ARQ
queue full), the synthesis task is never created. No retry.
The investigation row's `primary_outcome_id` stays at the
first-submitted outcome (not the synthesised panel summary).

Operator-visible: investigation appears completed but the
expected synthesis output never materialised.

**Fix**: Outbox pattern. OR retry with bounded backoff inside
`_maybe_trigger_synthesis`.

---

## 141. `VR_NDAY_V1.research` has `max_retries=1` but no `retriable_on`

**File**: `workflow/definitions.py:84-89`.

**Bug**: The state spec declares `max_retries=1` but no
`retriable_on`. Without `retriable_on`, the engine retries on
ANY exception (the default tuple is empty). So ANY exception
from `state_research` triggers a retry — including LLM
budget exhaustion, Pydantic validation errors, NotFound errors,
permission errors.

The docstring at lines 21-23 says "research and advisory are not
retried — they own their own LLM-error handling". But
`max_retries=1` IS retry. The code contradicts the documented
intent.

If the comment is correct, `max_retries=0`. If `max_retries=1`
is correct, the comment is wrong AND `retriable_on=(LLMError,
TimeoutError, ...)` should be set to bound which exceptions
retry.

**Fix**: Decide which is correct. Either remove the retry or
constrain the retryable types.

---

## 142. `VR_INVESTIGATE_V1.investigation_setup` lacks `retriable_on`

**File**: `workflow/definitions.py:117-122`.

**Bug**: `max_retries=1` but no `retriable_on`. Same shape as
§141. The setup state opens a DB session, does CVE intel
resolution (network call), spawns sibling branches. A transient
OperationalError or TimeoutError would benefit from a retry —
but a Pydantic ValidationError or PermissionError SHOULDN'T
retry.

Without `retriable_on`, every exception is retried once. The
second attempt on a fixed-cause exception (e.g. malformed input
kwargs) just wastes worker time.

**Fix**: `retriable_on=(OperationalError, TimeoutError, ConnectionError)`
matching VR_NDAY's `_TRANSPORT_TRANSIENT`.

---

## 143. `VR_INVESTIGATE_V1.investigation_loop` `timeout_s=7200` cap vs operator turn budget

**File**: `workflow/definitions.py:123-130`.

**Bug**: 7200s = 2 hours. The loop runs up to `_DEFAULT_MAX_TURNS=70`
turns. At 30s per LLM call → 35 min normal case. But:

  - LLM calls can take 60-90s on cold start or under contention
    → 70 * 90 = 6300s + overhead = potential 2h+ exceed
  - Tool calls add latency on top of LLM (audit_mcp semantic_search
    can take 5-10s, ida decompile 30s+)
  - If the cap is hit mid-call, the handler is cancelled and the
    cursor sits at `investigation_loop` for the retry path. But
    `max_retries=0` so no retry. Investigation goes to FAILED
    via `_handle_failure`.

Operator-visible: a slow audit (high-quality, deep) gets force-
failed at 2h regardless of actual progress.

**Fix**: Increase `timeout_s` OR reduce per-task max_turns so
the 70-turn budget fits in 2h.

---

## 144. `investigation_emit.py:287` crashes if both `started_at` and `created_at` are None

**File**: `workflow/states/investigation_emit.py:287-288`.

**Bug**: `clock_start = inv.started_at or inv.created_at`
followed by `clock_start.tzinfo is None`. If both are None
(theoretically possible from a malformed row or test fixture),
`clock_start.tzinfo` raises AttributeError on a None object.

The cap-check then crashes the entire `state_investigation_emit`
handler. The engine's `_handle_failure` routes to __crashed__.
The investigation enters terminal state with no helpful message.

**Fix**: Defensive None check; default to a far-past timestamp
OR skip the wall-clock check entirely.

---

## 145. `investigation_emit.py` env defaults inconsistent with comments

**File**: `workflow/states/investigation_emit.py:63-65`.

**Bug**: `_INVESTIGATION_WALL_CLOCK_HOURS = float(os.environ.get(
"VR_INVESTIGATION_WALL_CLOCK_HOURS", "6"))`. Default 6 hours.

But the comment at lines 320-322 references the e1a9e13c
incident with a 24h cap and discusses "25.9h/24h cap killed 7
branches". The 24h figure was the operator's env override but
the code default is 6h. The discrepancy means a fresh installation
caps at 6h while the running production used 24h.

Operator-visible: a new deployment hits the cap 4× faster than
the documented behavior.

**Fix**: Align the default with what's actually in production
OR update the comment to reference the default.

---

## 146. `_pop_outcome` at `hooks.py:96-117` has no concurrency protection

**File**: `platform/tasks/hooks.py:96-117` (around the stash
access).

**Bug**: The outcome stash is a module-level dict. Concurrent
`pop` operations can race — but since ARQ runs one job at a
time per worker process, and `on_job_end` runs after `on_job_start`,
within a single process this is safe. Across processes the
stash isn't shared anyway.

The race is within a single ARQ event loop turn: two coroutines
both call `_pop_outcome` for different (job_id, job_try) pairs.
Since they're on different keys, no actual collision. OK.

**Status**: Not a bug; listing because I initially thought it
was. Documenting to save the next pass from re-examining.

---

## 147. `_serialize_definition` doesn't capture `retriable_on` types

**File**: `platform/tasks/hooks.py:346-368`.

**Bug**: The serializer captures `terminal`, `max_retries`,
`timeout_s` per state. Does NOT capture `retriable_on` (the
tuple of exception types). The timeline UI rendering plan_json
can't show "this state retries on TransportError but not on
ValidationError" — that info is lost.

Per Golden Rule "no aspirational comments": the docstring at
line 350-355 says "Handler identities are intentionally omitted
so the timeline page cannot leak internal module paths to the
frontend". OK that's the explicit choice. But `retriable_on` is
just a list of class names — no security concern. Could include
them for operator observability.

**Status**: Design choice, not a bug. Listing for the cutover
plan if operator wants better timeline detail.

---

## 148. `evaluate_quorum` siblings count includes branches with no votes

**File**: `services/outcome_review.py:256-266` (re-reading).

**Bug**: `siblings = ALL branches != proposing_branch`. Then
`non_proposing_active_count = len([b for b in branches if status==ACTIVE])`.
The quorum_k computation uses this count.

If a sibling branch was ABANDONED with reason="stale_no_progress"
before voting (per stale-branch detector), it's NOT in
`non_proposing_active`. Quorum_k is computed against the
remaining active siblings — which could be 1 or 0. Quorum
threshold passes with 1 approve vote.

An outcome can be APPROVED by a single vote when 4 siblings
got stale-abandoned. Operator-visible: low-confidence approvals
slip through under stale conditions.

**Fix**: Either count ALL non-proposing branches (active + closed)
for the quorum baseline, OR require a minimum quorum_k floor
regardless of remaining actives.

---

## 149. `branch_manager.fork` doesn't increment any per-investigation branch counter

**File**: `agents/branch_manager.py:88-127`.

**Bug**: A fork creates a new branch row with no upper bound.
An investigation can have 6, 60, or 600 branches forked. Each
fork triggers an ARQ task. Resource consumption is unbounded.

The operator has no signal that "this investigation has too
many branches and is spiralling". The fork operation doesn't
check the parent investigation's existing branch count.

**Fix**: Configurable per-investigation branch cap
(`VR_INVESTIGATION_BRANCH_CAP=20` or similar). Fork raises
`BranchManagerError("branch cap exceeded")` when above the cap.

---

## 150. `investigation_emit` `final_status` resolution doesn't distinguish auto-completed from operator-completed

**File**: `workflow/states/investigation_emit.py:438-464`.

**Bug**: The block at 438-461 flips status to COMPLETED when
all siblings done. The block at 462-464 flips status when
`final_status is not None` (e.g. from `_resolve_final_status`
on `terminal_submit`).

No marker on the `inv` row distinguishes:
  - Operator manually marked the investigation completed (from
    a hypothetical /complete endpoint)
  - Workflow auto-completed because all sibling branches done
  - Cap-exceeded close (forced terminal)
  - Reopen → re-completed

The audit trail conflates all four reasons under `status=COMPLETED`.
`pause_reason` is set on PAUSED, but there's no analogous
`completed_reason` column.

**Fix**: Add a `completed_reason` enum/text column carrying the
terminal reason. Updated by every code path that writes
`status=COMPLETED`.

---

## 151. `_enqueue_dependents` runs under `terminal_branch=='success'` but doesn't tag the dependent task with the successful parent's result

**File**: `platform/tasks/hooks.py:313-314`.

**Bug**: The dependent's `kwargs_json` was set at queue-time. It
contains no link to the completed parent's output. If a dependent
task needs to read its parent's `result_path` (e.g. consume the
APK ingestion's output dir), the dependent has no way to access
it post-promotion.

The TaskRecord row has `result_path` but only on the COMPLETED
task. The dependent must query its `depends_on_json` IDs and
lookup each parent's result_path.

**Status**: Documented limitation. The dependency framework
only signals "run after X done", not "feed X's output into Y".
Listed because the limit isn't obvious to new task authors.

---

## 152. Summary part 8

19 more bugs (#134-151). Total now 149+ items across parts
1-8.

File density updates:

|file|count (parts 1-7 + new)|
|---|---|
|`modules/vr/api_router.py`|10|
|`modules/vr/masvs/parent_reconciler.py`|9|
|`modules/vr/agents/vuln_researcher.py`|7|
|`modules/vr/agents/branch_manager.py`|7 + 1 (§149) = 8|
|`platform/tasks/worker.py`|6|
|`modules/vr/services/stage_tracker.py`|5|
|`platform/llm/idempotency_cache.py`|5|
|`workflow/states/investigation_emit.py`|1 + 6 (§137-140, §144, §145, §150) = 7|
|`platform/tasks/hooks.py`|3 + 4 (§134-136, §147) = 7|
|`workflow/definitions.py`|2 (§141, §142, §143)|
|`platform/tasks/queue.py`|4|
|`modules/vr/agents/claim_verifier.py`|4|
|`platform/services/factory.py`|3|
|`platform/llm/run_memory.py`|3|
|`platform/services/reasoning.py`|2|
|`modules/vr/agents/outcome_dispatcher.py`|3|
|`modules/vr/services/outcome_review.py`|3 + 1 (§148) = 4|
|`modules/vr/agents/tool_executor.py`|3|
|`modules/vr/workflow/states/investigation_setup.py`|3|
|`modules/vr/workflow/states/investigation_loop.py`|3|
|`modules/vr/services/branch_reaper.py`|3|
|`modules/vr/services/investigation_reaper.py`|3|

No code touched for §134-151.

---

# Part 9 — sanitize / pipeline / synthesis / sbd_nfr / supplemental

## 153. `sanitize.py` injection patterns are case-sensitive

**File**: `platform/llm/sanitize.py:50-73`.

**Bug**: Every `register_injection_pattern` call uses bare regex
with no `re.IGNORECASE`. The compile call inside `InjectionPattern`
(per the dataclass at line 23-28) doesn't add flags either.

So `Ignore Previous Instructions` (Title Case) and `IGNORE PREVIOUS
INSTRUCTIONS` (uppercase) PASS THROUGH unchanged. The pattern
`(?:ignore\s+(?:all\s+)?previous\s+instructions|you\s+are\s+now)`
matches only the exact lowercase form.

Same for `Assistant:`, `USER:`, `\[INST\]` — all case-sensitive.

**Fix**: Add `re.IGNORECASE` (or `(?i)` prefix) to every pattern.

---

## 154. `sanitize_input` has no protection against unicode/whitespace tricks

**File**: `platform/llm/sanitize.py:80-89`.

**Bug**: Patterns use ASCII `\s` and ASCII letters. Injection
variants using:
  - Zero-width space (`\u200b`): "ignore\u200bprevious\u200binstructions"
  - Full-width characters: "ＩＧＮＯＲＥ ＰＲＥＶＩＯＵＳ"
  - Right-to-left override (U+202E): visible "snoitcurtsni"
  - Mixed-script: "ignor​e all previous"
  - HTML entities: "ignore&nbsp;previous"

all pass the sanitizer untouched. The output rendering with
ASCII-only patterns gives a false sense of protection.

**Fix**: Either NFKD-normalize input + strip zero-width chars
before pattern match, OR use a more sophisticated detector
(LLM-based, regex-with-unicode-classes).

---

## 155. `register_injection_pattern` doesn't dedupe by name

**File**: `platform/llm/sanitize.py:35-43`.

**Bug**: Each call appends to the module-level `_INJECTION_PATTERNS`
list. Calling with the same name twice (test fixture, hot-reload)
adds a SECOND entry. `sanitize_input` then applies the substitution
twice. Idempotency holds for `regex.sub` on a string already
stripped, but the second pass is wasted work AND the list grows
unbounded across hot-reloads in dev.

**Fix**: Look up by name; replace existing entry if name matches.

---

## 156. `PipelineRunner.run` swallows step failures by default

**File**: `platform/llm/pipeline.py:115-126`.

**Bug**: `_run_step` reads `fail_mode` from config. On exception:
  - `fail_mode == "closed"` → raise as LLMError
  - else (default) → log warning + continue

Default is "fail-open" — a sanitization or validation failure
silently logs and continues. The LLM call proceeds unsanitized.
The agent gets the raw response back; the operator never sees
the failure unless they grep logs.

For security-critical steps (sanitize, validate, gate),
`fail_mode="open"` is a vulnerability — a regex compile error
disables sanitization for every subsequent call without alerting
the operator.

**Fix**: Default to `fail_mode="closed"` for steps tagged
security-critical. Make the per-step default explicit in the
config provider rather than defaulting silently.

---

## 157. `PipelineRunner` step order is hardcoded in module-level constants

**File**: `platform/llm/pipeline.py:27-28`.

**Bug**: `PRE_CALL_STEPS = ("classify",)` and
`POST_CALL_STEPS = ("validate", "gate", "verify", "seal")` are
module constants. Adding a new step (e.g. "redact-pii") requires
a source-file edit + redeploy. There's no plugin/registration
model for new steps.

The `register()` method at line 38-50 attaches a step FUNCTION
to an EXISTING slot name. A new slot name silently has no slot —
the step is registered to a name nothing iterates over.

**Fix**: Slot order is config-driven (per ConfigRegistry) so
new steps can land without a redeploy.

---

## 158. `synthesis_agent.run` catches only `RuntimeError`

**File**: `agents/synthesis_agent.py:125-130`.

**Bug**: `except RuntimeError as exc`. The LLM client's exception
hierarchy is `LLMError` (RuntimeError subclass) — usually caught.
But:
  - `pydantic.ValidationError` (ValueError subclass)
  - `httpx.HTTPError` / `httpx.NetworkError`
  - `openai.OpenAIError`
  - `TimeoutError`

None of these are `RuntimeError`. A network failure crashes
the synthesis task instead of being logged as a clean failure.
The investigation's primary_outcome stays at the first-submitted
outcome forever.

**Fix**: Broader `except Exception` with explicit re-raise of
SystemExit/KeyboardInterrupt.

---

## 159. `synthesis_agent.run` uses `services.llm_client.chat` not `chat_structured`

**File**: `agents/synthesis_agent.py:117-124`.

**Bug**: `services.llm_client.chat(task_type=..., messages=...)`
returns free-text. Synthesis output goes directly into
`payload['panel_summary']['narrative']` without schema validation.

A malformed LLM response (empty string, prompt-injection
leakage, off-topic) gets stored verbatim and rendered on the
report PDF + frontend. Operator sees garbage in the synthesis
section.

**Fix**: Use `chat_structured` with a Pydantic schema (mirrors
the report-writer agent I built and then reverted in §1).

---

## 160. `synthesis_agent.run` opens TWO UnitOfWorks bracketing the LLM call

**File**: `agents/synthesis_agent.py:61-186`.

**Bug**: First UoW at line 61-115 reads inv + canonical and
extracts the panel. The LLM call runs at line 117-124 with no
session. Second UoW at line 140-186 commits the synthesis.

Between the two UoWs, another process can:
  - Add a new outcome to the investigation
  - Mutate the canonical row's payload
  - Flip inv.status to PAUSED / FAILED / ABANDONED

The second UoW reads the canonical row again (line 141-147) and
writes panel_summary. But it does NOT re-read inv to check if
the status changed. So a paused investigation gets synthesis
committed anyway — the inv_row.status write at line 182 then
flips it to COMPLETED unconditionally, overriding the operator's
pause.

**Fix**: Re-load inv in the second UoW and verify status is
still RUNNING before committing the synthesis.

---

## 161. `synthesis_agent._synthesis_confidence` recognises "weak" but enum doesn't have it

**File**: `agents/synthesis_agent.py:212`.

**Bug**: `conf_rank = {"strong": 1, "exact": 0, "medium": 2,
"caveated": 3, "weak": 3, "unknown": 4}`. Includes `"weak"`
but `OutcomeConfidence` enum has no WEAK value (only EXACT,
STRONG, MEDIUM, CAVEATED, UNKNOWN).

Any panel contribution claiming `confidence="weak"` (typo,
legacy data) gets mapped to rank 3 — equivalent to CAVEATED.
The mapping doesn't fail loud — it silently treats the typo
as a valid value.

**Fix**: Drop the `"weak"` entry. Or add it to the enum if it's
a real concept.

---

## 162. `synthesis_agent.run` flips inv status to COMPLETED — direct workflow-engine bypass

**File**: `agents/synthesis_agent.py:181-185`.

**Bug**: `inv_row.status = InvestigationStatus.COMPLETED.value`.
The synthesis agent writes the investigation's terminal status
directly. Same anti-pattern as §22 — agent code writing the
investigation's terminal state outside the workflow engine.

**Fix**: Synthesis is a workflow state. Its handler returns
`StateResult(next_state=__succeeded__, output=panel_summary)`
and the engine commits the cursor + the inv status in one
transaction.

---

## 163. `sbd_nfr/api_router.py:smart_search` constructs LLM client directly

**File**: `modules/sbd_nfr/api_router.py:834-843`.

**Bug**: Already noted at §24 generally. Per-instance: this
request handler builds `PlatformSettings`, `ConfigRegistry`,
`SecretStore`, `AilaLLMClient` on EVERY request. Each builds
sub-objects that touch env + DB.

No factory injection. No caching. Every smart_search request
is N times slower than a similarly-shaped operation that
receives the LLM client from a FastAPI dependency.

**Fix**: FastAPI `Depends(get_llm_client)` factory.

---

## 164. `sbd_nfr/api_router.py:smart_search` doesn't pass `auth.team_id` to the LLM client

**File**: `modules/sbd_nfr/api_router.py:843-850`.

**Bug**: `AilaLLMClient` constructed without team context. The
per-team cost budget enforcement reads from a team-scoped
ConfigRegistry. A request handler that doesn't propagate team_id
through the client construction can't enforce per-team budget.

The user_id IS passed to `search_service.smart_search`, so
downstream code has identity. But the LLM client itself doesn't
know which team's budget to charge.

**Fix**: ConfigRegistry construction with `team_id=auth.team_id`
OR a per-team factory.

---

## 165. `synthesis_agent._render_panel` doesn't sanitize panel content

**File**: `agents/synthesis_agent.py:222-263`.

**Bug**: Panel contributions contain agent free-text (`narrative`,
`answer`, persona content). The `_render_panel` function
interpolates them into the user_prompt for the LLM. No
sanitization step is applied.

If a previous agent's output included a prompt-injection payload
(legitimately written by an upstream component OR injected via a
tool result), it gets baked into the synthesis prompt. The
synthesis LLM follows the injection instead of summarising.

**Fix**: Apply `sanitize_input` (the sanitize.py public API) to
every panel contribution's text fields before rendering.

---

## 166. Summary part 9

13 more bugs (#153-165). Total now 162+ items.

File density additions:

|file|count|
|---|---|
|`platform/llm/sanitize.py`|3 (§153-155)|
|`platform/llm/pipeline.py`|2 (§156, §157)|
|`modules/vr/agents/synthesis_agent.py`|5 (§158-162, §165)|
|`modules/sbd_nfr/api_router.py`|1 + 2 (§163, §164) = 3|

No code touched for §153-165.

---

# Part 10 — outcome-editing data loss (operator-flagged)

Operator question: are agents allowed to extend/refine a drafted
outcome? If they don't ship their input, is there data loss?

Answer: agents CAN add via subsequent `terminal_submit` which calls
`_upsert_canonical_outcome`. But the merge is lossy in concrete
ways, AND the `suggested_edits` review workflow is purely
decorative — proposed edits never reach the outcome payload.

## 166. `_upsert_canonical_outcome` overwrites `answer` field on merge

**File**: `agents/vuln_researcher.py:2717-2724`.

**Bug**: When a sibling submits and their `answer` is ≥20%
longer than the existing canonical answer (or comes from a
more-specific kind), the existing answer is REPLACED in
`payload['answer']`. The prior agent's analysis text is gone
from the load-bearing field.

Backup: line 2636 captures a copy of each contribution's answer
in `panel_contributions[i]['answer_brief']`, but TRUNCATED to
4000 chars. A 7000-char detailed analysis loses the last 3000
chars in the panel record. And the REPLACED text from
`payload['answer']` itself is not stored elsewhere.

Real loss: maddie writes a 3000-char analysis with specific
code locations. renzo writes a 4000-char analysis (33% longer).
Renzo's REPLACES maddie's in `payload['answer']`. Maddie's
`answer_brief` survives in panel_contributions (3000 < 4000 cap)
so technically recoverable — but the canonical's primary
`answer` field shows only renzo's text. Report PDF + frontend
render only the canonical `answer`. Maddie's specific evidence
is hidden in a JSON sub-field.

**Fix**: Append a `prior_answers` array preserving every
REPLACED answer with its provenance (persona, at_turn,
submitted_at). Or render `panel_contributions[].answer_brief`
alongside the canonical answer in the report.

---

## 167. `_upsert_canonical_outcome` ignores second `poc_code` submission

**File**: `agents/vuln_researcher.py:2700-2703`.

**Bug**: `if new_payload.get("poc_code") and not old_payload.get("poc_code")`.
The new poc_code is taken ONLY when the old is empty. If a
second branch submits a more complete or correct poc, it's
silently dropped.

`panel_contributions` does NOT store `poc_code` (line 2629-2637
shows only persona, branch_id, at_turn, outcome_kind, confidence,
answer_brief). The dropped poc is genuinely lost — not even in
the audit trail.

**Fix**: Carry every contribution's `poc_code` in
`panel_contributions[i].poc_code`. Render all options in the
report; operator picks which to ship.

---

## 168. `_upsert_canonical_outcome` race: concurrent terminal_submits create duplicate canonical rows

**File**: `agents/vuln_researcher.py:2620-2662`.

**Bug**: The function reads "existing canonical" via
`SELECT ... ORDER BY created_at ASC LIMIT 1`. If no row exists,
it INSERTs a new one (lines 2643-2651). No row-level lock, no
UNIQUE constraint on (investigation_id) within
`vr_investigation_outcomes`.

Two branches whose workers finish terminal_submit at the same
moment:
  - Branch A's UoW reads existing=None at T=0
  - Branch B's UoW reads existing=None at T=0.5
  - Branch A INSERTs at T=1
  - Branch B INSERTs at T=1.5
  - Two canonical rows exist for the same investigation.

Downstream paths read "the canonical" as the OLDEST row (per
`investigation_emit._maybe_trigger_synthesis` line 682-687,
`claim_verifier._load_context` line 645-650, every other reader).
The SECOND canonical's contents — including its
panel_contributions, affected_components, answer, etc. — are
stranded. The synthesis agent reads ONLY the first.

Operator-visible data loss: a branch that submits 50ms late has
its entire submission written to a dangling outcome row that
no production code reads.

**Fix**: Schema-level UNIQUE constraint on (investigation_id)
with a `canonical` Boolean partial index, OR INSERT with
`ON CONFLICT DO NOTHING` + re-read pattern, OR application-level
row lock via `SELECT ... FOR UPDATE`.

---

## 169. `_upsert_canonical_outcome` reads OLDEST row when picking the canonical

**File**: `agents/vuln_researcher.py:2622-2625`.

**Bug**: Same shape as §168. The "existing canonical" is just
the OLDEST outcome row. If the first row was created as a
synthesis output (via SynthesisAgent — kind=synthesis) and a
later branch submits, the merge logic still picks the synthesis
row as canonical. The branch's submission gets MERGED INTO the
synthesis output, overwriting it.

Same in `synthesis_agent.run` and `claim_verifier._load_context`.
Every reader uses created_at ASC and assumes the oldest is the
canonical. That's fragile.

**Fix**: An explicit `canonical: Boolean` column on
`vr_investigation_outcomes`. The first writer claims canonical;
others append their contributions and explicitly target it by ID.

---

## 170. `suggested_edits_json` is stored but NEVER applied to outcomes

**Files**:
  - `services/outcome_review.py:198` (write)
  - `db_models/outcome_review.py:65` (schema)
  - `api_router.py:5147, 5196` (read for display only)
  - Migration `062_vr_outcome_review.py:22-23` (docstring
    acknowledging "application is operator-initiated, not
    automatic")

**Bug**: An agent voting `request_edit` with a `suggested_edits`
payload (e.g. `{"confidence": "weak"}`, `{"answer": "corrected
text"}`) writes the suggestion to the review row. Zero downstream
code applies these suggestions to the underlying outcome's
payload.

There's also NO operator-facing endpoint to apply them. The
frontend `Reviews` panel shows the suggestion text for human
reading; no Apply button exists.

Pure data loss: every `vote=request_edit` action takes an LLM
round-trip to produce the suggestion, the suggestion goes to
DB, and nobody reads it. The agent's effort is wasted; the
correction never happens.

The operator-noted symptom: "agents draft outcomes, others
partially nod or want to refine, but only one outcome exists".
The `suggested_edits` workflow was designed to address this and
is non-functional.

**Fix**: Either wire an operator-Apply path AND/OR have the
synthesis agent read all reviews' suggested_edits and incorporate
them into the panel_summary. Latter is automatic + agent-driven.

---

## 171. `_upsert_canonical_outcome` truncates `answer_brief` to 4000 chars

**File**: `agents/vuln_researcher.py:2636`.

**Bug**: `"answer_brief": (new_payload.get("answer") or "")[:4000]`.
The panel-contribution snapshot of each persona's answer is
truncated. Anyone's submission > 4000 chars loses the tail in
the audit record.

The full answer survives ONLY in `payload['answer']` — which
is itself REPLACED on subsequent merges per §166. So the
full-text record of an early persona's analysis can be lost
completely if a later persona's answer (which replaces) is
itself replaced by an even later one.

**Fix**: Either drop the truncation, OR keep a separate
`prior_answers` array that preserves every full-length submission.

---

## 172. `_upsert_canonical_outcome` panel_contributions deduplication is missing

**File**: `agents/vuln_researcher.py:2726-2728`.

**Bug**: `contributions.append(contribution)`. No check for
duplicate (branch_id, at_turn) pairs. A retry of the same
terminal_submit (re-enqueue + same turn) appends a duplicate
entry. The audit trail counts the same submission twice.

Subsequent counters that read `len(panel_contributions)`
(e.g. synthesis quorum check at investigation_emit line 712)
see N+1 instead of N. The thresholds are off by the number
of duplicate retries.

**Fix**: Dedupe by (branch_id, at_turn).

---

## 173. The merge logic only fires inside `vuln_researcher.run_turn` terminal-submit path

**File**: `agents/vuln_researcher.py:577-615`.

**Bug**: `_upsert_canonical_outcome` is called ONLY on
terminal_submit. A branch that wants to add to an existing
canonical without terminating itself has NO path to do so.

Operator scenario: maddie submits a finding (terminal). Renzo
is still investigating, sees the canonical, wants to add an
`affected_components` entry without terminating his own branch.
There's no `add_to_canonical` action; only terminal_submit
merges.

So renzo has to either:
  - Terminate (lose the rest of his investigation budget)
  - Wait until his own terminal_submit to add (and hope his
    answer doesn't get REPLACED per §166)

**Fix**: A non-terminal `submit_canonical_addition` action that
lets a branch contribute components/orders without closing.
The merge logic supports this — only the action-routing in
`run_turn` doesn't.

---

## 174. `_upsert_canonical_outcome` only reads OLDEST canonical — second canonical's `panel_contributions` stranded

**File**: `agents/vuln_researcher.py:2620-2625` (combined with §168).

**Bug**: When the race in §168 creates two canonical rows, the
merge logic in subsequent calls reads only the OLDEST. The
SECOND canonical has its own `panel_contributions=[contribution_B]`
from its initial creation. That second row's contributions are
never merged into anything — they exist in the DB, the row's
UI element shows them, but synthesis + dispatch ignore them.

Both branches' contributions ARE in the `vr_investigation_outcomes`
table but only one is rendered through the official pipeline.

**Fix**: Same as §168 — UNIQUE constraint + ON CONFLICT.

---

## 175. `panel_contributions` doesn't link to the corresponding outcome row OR the branch's other artifacts

**File**: `agents/vuln_researcher.py:2629-2637` (the contribution
dataclass).

**Bug**: Each `panel_contributions` entry has `persona`,
`branch_id`, `at_turn`, `submitted_at`, `outcome_kind`,
`confidence`, `answer_brief`. Missing:

  - `evidence_refs` (the agent's cited file:line evidence)
  - `poc_code` (per §167)
  - `affected_components` (per-persona view of what they thought
    was affected, separate from the merged set)
  - `variant_hunt_orders` (which variants they proposed)
  - `confidence_breakdown` (their per-claim confidence)

So the per-persona record only shows the answer text + metadata.
If maddie cited 5 files in `affected_components` and renzo cited
3 different ones, the merged components list has all 8 — but
the reader can't tell which persona cited which.

**Fix**: Store the full per-persona payload in each
`panel_contributions[i].full_payload` field. Increases storage
by ~3-5KB per contribution but preserves per-persona attribution.

---

## 176. Summary part 10

10 more bugs (#166-175). Total now 175+ items.

Direct answer to operator's question:

  - Yes, agents CAN extend a drafted outcome. The path is
    `terminal_submit` → `_upsert_canonical_outcome` → merge.
  - NO, agents CANNOT extend WITHOUT terminating their own branch
    (per §173).
  - YES, there is data loss:
    * `answer` text replaced not concatenated (§166)
    * `poc_code` second-and-later submissions dropped (§167)
    * `answer_brief` truncated to 4000 chars (§171)
    * Concurrent submits create duplicate canonical rows, second
      row's contents stranded (§168, §174)
    * `suggested_edits` from `request_edit` votes are stored but
      never applied to any outcome (§170)
    * Per-persona affected_components / variant_hunt_orders /
      evidence_refs are merged WITHOUT attribution — reader
      can't see which persona cited which (§175)

File density additions:

|file|count|
|---|---|
|`agents/vuln_researcher.py`|7 + 6 (§166-169, §171-173) = 13|
|`services/outcome_review.py`|4 + 1 (§170) = 5|

No code touched for §166-175.

---

# Part 11 — the "unnamed branch named as 'branch'" bug + related

Operator-flagged: somewhere in the UI an unnamed branch is rendered
as the literal string `"branch"`. Found it.

## 176. Frontend renders literal `"branch"` when persona_voice is null

**Files**:
  - `frontend/src/queries.ts:736-737`
  - `frontend/src/screens/BranchTreePage.tsx:115`
  - `frontend/src/screens/EvidenceGraphPage.tsx:81`

**Bug**: All three sites fall back to literal `"branch"` when
`persona_voice` is null:

```ts
const persona = hit.persona_voice ? `${hit.persona_voice}` : "branch";
// or
{b.persona_voice ?? "branch"}
```

Operator sees a branch whose displayed name IS the word "branch".
Confusing because every other branch displays "halvar", "maddie",
"noor", etc.

**Fix**: Render something distinguishable — `(no persona)`,
`merged`, the branch's `fork_reason`, or just the first 8 chars of
the branch id. Each option carries more signal than the bare word.

---

## 177. `branch_manager.merge` always creates merged branch with `persona_voice=None`

**File**: `agents/branch_manager.py:161-170`.

**Bug**: `merged = VRInvestigationBranchRecord(... persona_voice=None, ...)`.
The merged branch is born with no persona. Combined with §176,
every merge produces a branch that renders as literal "branch"
in the UI.

The fork_reason at line 166 IS set to `"merge: <reason>"` so the
branch's lineage IS recorded — just not in the display field the
frontend reads first.

**Fix**: Set `persona_voice = "merge_result"` (a new PersonaVoice
enum value) OR have the frontend prefer `fork_reason` when
`persona_voice` is null.

---

## 178. `branch_manager.fork` allows null persona_voice with no validation

**File**: `agents/branch_manager.py:88-127`.

**Bug**: `persona_voice: str | None = None`. Callers that forget
to pass a persona create a null-persona branch. Combined with
§176, the UI shows "branch".

`_spawn_persona_siblings_and_enqueue` at line 462-468 passes
`persona_voice=persona.value` correctly. But other callers
(operator-initiated forks via the api_router at line 5549) may
pass None if the operator didn't pick one in the UI.

**Fix**: Make persona_voice required at the fork API, OR default
to a marker value the frontend renders correctly.

---

## 179. `investigation_setup` primary-persona fallback runs AFTER branch creation

**File**: `workflow/states/investigation_setup.py:279-282`.

**Bug**: Loads the existing primary branch and, IF its
persona_voice is null, sets it to `_PRIMARY_PERSONA.value`. The
branch was already created earlier (line 219-232 or via the
dispatcher) with a possibly-null persona. Between creation and
the fallback, any reader sees null → frontend renders "branch".

The window is the duration of one workflow state transition
(typically <1s in fast paths but seconds when CVE intel
resolution runs).

**Fix**: Set the persona at CREATION time, not fallback in
setup.

---

## 180. The `persona_voice` column has no DB-level NOT NULL constraint on rows that should be persona-bound

**File**: `db_models/branch.py:55`.

**Bug**: `persona_voice: str | None = Field(default=None, max_length=32)`.
The column is nullable in the schema. Operationally, every branch
SHOULD have a persona (primary, halvar, maddie, etc.) OR a
structural marker (merge_result, operator_spawn). Nullable is too
permissive.

**Fix**: Either NOT NULL with a sensible default + CHECK constraint
enforcing it's in the PersonaVoice enum OR a known marker, OR
keep it nullable but add a `display_label` column that's always
populated.

---

## 181. Even when persona_voice is set, the frontend doesn't always render it consistently

**Files**:
  - `frontend/screens/InvestigationDetailPage.tsx` — uses persona-key in filters
  - `frontend/screens/BranchTreePage.tsx:115` — renders `persona_voice ?? "branch"`
  - `frontend/screens/EvidenceGraphPage.tsx:81` — same shape
  - `frontend/queries.ts:737` — `${hit.persona_voice}` falls through to "branch"

**Bug**: Four different code paths each have their own fallback
string. A future operator who changes one display site
(e.g. to render "(no persona)") has to update the other three.
The drift is silent.

**Fix**: Single helper `formatBranchDisplayName(branch)` consumed
by every renderer. Encapsulate the fallback logic.

---

## 182. Summary part 11

6 more bugs (#176-181). Total now 181+ items across 11 parts.

The operator-flagged "unnamed branch named as 'branch'" bug is
§176 with three concrete sources (§177, §178, §179). The schema
gap is §180. The duplicate-fallback drift is §181.

File density additions:

|file|count|
|---|---|
|`frontend/src/queries.ts`|1|
|`frontend/screens/BranchTreePage.tsx`|1|
|`frontend/screens/EvidenceGraphPage.tsx`|1|
|`agents/branch_manager.py`|8 + 2 (§177, §178) = 10|
|`workflow/states/investigation_setup.py`|3 + 1 (§179) = 4|
|`db_models/branch.py`|1|

No code touched for §176-181.

---

# Part 12 — outcome_dispatcher / cve_intel / pattern_extractor

VR deep-read pass on `agents/outcome_dispatcher.py:dispatch()` main
entry, `services/cve_intel_resolver.py` end-to-end, and
`agents/pattern_extractor.py`.

## 182. `outcome_dispatcher.dispatch` treats NULL state as "already dispatched"

**File**: `agents/outcome_dispatcher.py:178`.

**Bug**: `state = outcome.state or OUTCOME_STATE_DISPATCHED`. The
comment at line 178 says "legacy NULL". But:

  - A synthesized outcome (from `_synthesize_no_finding_outcomes`)
    inserts with `state='approved'` — fine.
  - A direct-INSERT path that forgets to set state inserts NULL
    — silently treated as "already dispatched" and skipped.

The synth code paths I've reviewed do set state. But the fallback
masks any future code path that forgets. A typo bug where state
isn't set looks identical to "already shipped" in the dispatch
log — operator sees no real shipping happen but no error either.

**Fix**: Treat NULL as a hard error. Raise `ValueError("outcome
missing state — schema invariant violated")`.

---

## 183. `outcome_dispatcher.dispatch` SKIPS unknown state values

**File**: `agents/outcome_dispatcher.py:221-232`.

**Bug**: `if state != OUTCOME_STATE_APPROVED` (after the three
known-states branches) returns SKIPPED with reason
`"unknown_state:{state}"`. The dispatcher emits a warning and
returns.

An outcome that has been written with state="approve" (typo) or
state="approving" (future enum) is silently skipped. No human
attention required. The outcome sits unshipped indefinitely.

**Fix**: Raise an error, OR explicitly log at ERROR level so
operator-facing alerting picks it up.

---

## 184. `outcome_dispatcher.dispatch` narrow exception filter causes UnboundLocalError on the wider catch path

**File**: `agents/outcome_dispatcher.py:274-287`.

**Bug**: The dispatch branch select at lines 233-273 sets the
`result` variable in each branch. The except at line 274 catches
only `(OSError, TimeoutError, RuntimeError, ValueError)`. If an
SQLAlchemyError or pydantic ValidationError raises in (say)
`_dispatch_direct_finding`, the exception bubbles past line 274,
`result` is never assigned, and line 287 `await self._update_outcome_status(result)`
raises UnboundLocalError.

The dispatcher crashes the whole investigation_emit state with a
confusing UnboundLocalError instead of the original exception.
The operator-facing log shows the wrong root cause.

**Fix**: Either broaden the except to `Exception`, OR initialize
`result` to a default before the try block.

---

## 185. `outcome_dispatcher._update_outcome_status` runs even on SKIPPED unknown-state

**File**: `agents/outcome_dispatcher.py:226-287`.

**Bug**: When state is unknown (line 221-232 branch), `result`
is a SKIPPED with reason `unknown_state:...`. Then line 287
calls `_update_outcome_status(result)` which writes
`dispatch_status=SKIPPED` onto the outcome row.

So an outcome with garbage `state` gets a clean
`dispatch_status=skipped` audit entry. Operator sees a row that
looks normally-processed but its state field is junk. Diagnosing
the underlying schema corruption is harder because the
dispatch_status update masks it.

**Fix**: Don't touch dispatch_status when state was unknown.
Leave the audit trail clean.

---

## 186. `outcome_dispatcher.dispatch` has no transactional rollback on partial dispatch failure

**File**: `agents/outcome_dispatcher.py:233-285`.

**Bug**: `_dispatch_direct_finding`, `_dispatch_audit_memo`,
`_dispatch_variant_hunt_order` each can do multi-step work
(create row, update parent inv, halt siblings). If the second
step fails after the first commits, the outcome's
`dispatch_status` writes to FAILED via the catch path — but the
row created in the first step stays.

Operator-visible: a finding row exists in `vr_findings` but the
outcome shows `dispatch_status=failed`. The finding is orphaned;
the outcome looks unshipped; operator has to manually reconcile.

**Fix**: Wrap the whole dispatch + cascade side-effects in a
single UoW. The outbox pattern (write side-effects as queued
actions in the same transaction; drain via a separate worker)
is the durable answer.

---

## 187. `cve_intel_resolver._CVE_RE` doesn't match 8+ digit serials

**File**: `services/cve_intel_resolver.py:44`.

**Bug**: `re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)`.
Matches serials of 4-7 digits. Modern CVE format allows arbitrary
serial length:
  - CVE-2014-1 (1-digit minimum) — historically valid, NOT matched
  - CVE-2026-12345678 (8 digits) — increasingly common in 2024+,
    NOT matched

An investigation prompt mentioning "CVE-2026-100000000" would
have that CVE id silently dropped by the resolver; the agent
thinks no CVE was mentioned and proceeds without intel context.

**Fix**: `r"\bCVE-\d{4}-\d+\b"` (1+ digit serials, any length).
The IntelService backend will return not_found for invalid ids.

---

## 188. `cve_intel_resolver` classifies 404 via text-match on exception string

**File**: `services/cve_intel_resolver.py:192-205`.

**Bug**: `if "404" in text or "Not Found" in text` is used to
distinguish NOT_FOUND from generic error. Two failure modes:
  - A genuine 404 returns "HTTPError 404: Not Found" — matches → NOT_FOUND ✓
  - A network error with stack trace text containing "Not Found" (typo
    in error message, code reference) — false NOT_FOUND
  - A generic exception whose repr happens to contain "404" — false NOT_FOUND

The fix should classify by the exception TYPE (httpx.HTTPStatusError
with .response.status_code == 404), not by text match.

**Fix**: Catch the typed exception, inspect .response.status_code.
Or have IntelService raise a typed `IntelNotFoundError`.

---

## 189. `cve_intel_resolver` conflates "definitely not found" with "couldn't reach NVD"

**File**: `services/cve_intel_resolver.py:213-221`.

**Bug**: When IntelService returns `knowledge is None`, the
resolver writes `status="not_found"`. But IntelService's None
return value can mean:
  - Cache miss + NVD lookup returned no record (true not_found)
  - Cache miss + NVD transient error masked as None (different
    semantic — should retry)
  - Cache hit but the cached value is None (legitimately
    NOT_FOUND or stale negative cache)

Conflating these means the agent's prompt says "NVD has no
record for this CVE id" when reality is "NVD is down". Agent
treats the CVE as bogus and proceeds without it.

**Fix**: IntelService should return a discriminated union
(`NotFound`, `TransportError`, `Found(...)`). The resolver maps
each to the right status.

---

## 190. `cve_intel_resolver` silently degrades when vulnerability module unregistered

**File**: `services/cve_intel_resolver.py:174-186`.

**Bug**: When `_get_intel_service` returns None (vulnerability
module not registered), the resolver builds an error-status entry
for each cve_id and returns. The investigation proceeds with
broken CVE intel.

`investigation_setup` consumes the resolver's output and writes
`cve_intel` into the workflow state input. The agent's prompt
reads cve_intel section, sees all entries with status=error,
and the user message says "IntelService unavailable — vulnerability
module not registered".

The agent now reasons against the error message text. In
practice that means the agent either:
  - Confabulates ("the operator must have a reason to ask about
    this CVE")
  - Or asks the operator for context (acceptable but slow)

No operator-side alerting fires when an entire MASVS audit run
sees CVE intel "unavailable". The condition is logged at
WARNING per line 142, 147 but cron-driven audits never get the
log to a human eye.

**Fix**: When the vulnerability module is mandatorily required
for VR module operation, refuse to start the worker without it.
OR raise an OperatorAlertingEvent so a paging service catches.

---

## 191. `pattern_extractor.extract` LLM-call exception filter is `(OSError, TimeoutError, RuntimeError)`

**File**: `agents/pattern_extractor.py:147-150`.

**Bug**: Same narrow tuple as everywhere. ValueError,
pydantic.ValidationError, json.JSONDecodeError (line 162-166
IS caught separately, so that one's fine), httpx errors,
openai.OpenAIError — none of those are `RuntimeError` subclass
in general.

A non-caught exception in the LLM call bubbles up to the caller
(`investigation_emit`) which catches `(OSError, TimeoutError,
RuntimeError, ValueError)` per the calling site at line 572-578
— same narrow tuple. Then THAT catch re-raises into the engine's
`_handle_failure`. The investigation goes to FAILED state on a
pattern-extraction failure rather than just skipping pattern
extraction.

**Fix**: Broaden the catch. Pattern extraction is supplementary;
a failure should NEVER fail the parent state.

---

## 192. `pattern_extractor.extract` `disabled=True` skip is invisible to operator

**File**: `agents/pattern_extractor.py:152-159`.

**Bug**: When the LLM is disabled (kill-switch), extraction
returns `skipped_reason="llm_disabled"` and `extracted_count=0`.
Operator-facing surface: the investigation closes normally, the
pattern store has no new entries, and only a tail-search of the
log shows the kill-switch was active.

For an audit that's supposed to produce reusable patterns, this
silent-skip is a hidden gap. The operator's pattern review queue
never gets the patterns they expected.

**Fix**: Log at INFO level prominently and emit an operator-
visible event so the dashboard shows "patterns not extracted
because LLM was disabled".

---

## 193. `pattern_extractor._load_transcript` reads ALL messages with no LIMIT

**File**: `agents/pattern_extractor.py:258-265`.

**Bug**: `SELECT * FROM vr_investigation_messages WHERE
investigation_id = X ORDER BY created_at ASC`. No LIMIT clause.
For a 70-turn × 6-branch investigation with ~5 messages per
turn, that's 2100 rows fetched into Python memory. Each row's
`payload_json` can be 10-50KB. Total memory load: 20-100MB
per extraction.

Then line 274-280 truncates the joined string to last 30000
chars. The full payload is materialized BEFORE truncation —
memory cost paid for data that gets discarded.

**Fix**: SELECT with LIMIT + DESC + flip the list in Python.
Or stream the transcript and stop once 30K chars are accumulated.

---

## 194. `pattern_extractor._load_transcript` keeps the LAST 30K chars — drops the seed

**File**: `agents/pattern_extractor.py:274-280`.

**Bug**: Truncation takes `full[-_MAX_TRANSCRIPT_CHARS:]`. The
last 30K chars are the agent's recent turns — likely the
terminal_submit + nearby tool calls.

But the FIRST few messages contain the seed prompt (the
question + control context) and the initial setup turns. For
pattern extraction, the seed context tells the extractor WHY
the investigation ran. Dropping the seed means the LLM extracts
patterns from the conclusion alone, missing the setup context
that would inform pattern scope.

**Fix**: Keep first 5000 chars + last 25000 chars, with a
`[...transcript continues...]` marker in the middle. The model
sees both the question AND the answer.

---

## 195. `pattern_extractor._load_transcript` returns the transcript even when there's no terminal outcome

**File**: `agents/pattern_extractor.py:250-280`.

**Bug**: The function reads all messages regardless of whether
the investigation actually closed. For a mid-investigation
abandonment (per the stale-branch detector), the transcript
ends mid-turn. The extractor prompts the LLM with truncated
reasoning, asks "extract patterns", gets garbage back.

The caller at `investigation_emit` line 563-578 guards against
running extraction on non-completed investigations:
`if outcome_id and final_status == COMPLETED.value`. So
extraction only fires on completion. But:

  - If the investigation is "completed" via synthesis (per §162),
    the canonical outcome may differ from the transcript's
    terminal_submit point — the synthesis added a `panel_summary`
    AFTER the transcript's last message.
  - The transcript's last 30K chars don't include the synthesis
    output.

So the pattern extractor sees the per-persona reasoning but NOT
the synthesised summary. The extracted patterns reflect the
per-persona views, not the panel verdict.

**Fix**: Include the synthesis output (`payload['panel_summary']`)
as a separate prompt section, not just rely on transcript tail.

---

## 196. Summary part 12

15 more bugs (#182-195). Total now 196+ items across 12 parts.

File density updates:

|file|count|
|---|---|
|`agents/outcome_dispatcher.py`|3 + 5 (§182-186) = 8|
|`services/cve_intel_resolver.py`|4 (§187-190)|
|`agents/pattern_extractor.py`|5 (§191-195)|

No code touched for §182-195.

---

# Part 13 — tool_executor / pattern_store / audit_mcp_bridge deeper

## 197. `tool_executor.execute` bridge-call exception filter misses common LLM-call errors

**File**: `agents/tool_executor.py:211-221`.

**Bug**: `except (OSError, TimeoutError, RuntimeError)` around
`bridge.forward(...)`. The bridge can raise:
  - `httpx.HTTPStatusError` (not RuntimeError subclass)
  - `pydantic.ValidationError` (ValueError subclass)
  - `json.JSONDecodeError` (ValueError subclass)

These aren't caught. They bubble up through investigation_loop's
own `(OSError, TimeoutError, RuntimeError, ValueError)` filter
— which DOES catch ValueError descendants but NOT httpx errors.
The investigation crashes on httpx errors that should have been
a clean tool-error message back to the agent.

**Fix**: Broaden to `except Exception` for the bridge call. The
tool-error path is supposed to be graceful regardless of error
class.

---

## 198. `tool_executor.execute` hardcodes audit-mcp URL for auto-steering

**File**: `agents/tool_executor.py:408`.

**Bug**: `bridge_base_url = "http://127.0.0.1:18822"`. Hardcoded
constant. The audit-mcp bridge has its own resolution
(`_resolve_base_url` at audit_mcp_bridge.py:286-300) that reads
env + ConfigRegistry. The tool_executor's auto-steering call
passes the hardcoded URL.

An operator who moved audit-mcp behind a reverse proxy (port
18822 → 443) or to a different host has the auto-steering
silently hitting localhost:18822 — which is either dead OR (worse)
a different service on the same port. The auto-steering response
may then be garbage that's posted as operator-steering to the
investigation.

**Fix**: Read the same env/registry chain as
`audit_mcp_bridge._resolve_base_url`. Or inject the bridge
instance and reuse its resolved URL.

---

## 199. `tool_executor` `_directive.pivot` overwrites previous pivot on every survey

**File**: `agents/tool_executor.py:374-377`.

**Bug**: When the survey-streak heuristic fires, the directive
is set via `observables_delta["_directive.pivot"] = pivot_hint`.
The agent's case_state then carries the directive into next
turn's prompt.

But every subsequent survey REPLACES the directive text (same
key, new value). The agent may have responded to the previous
pivot directive on turn N with a complex reasoning chain across
turn N+1, N+2... if the agent surveys again on N+3, the OLD
directive text is lost and replaced. The audit trail shows
only the latest pivot, not the history of when the agent was
nudged.

**Fix**: Either timestamp every pivot fire (append to a
`_directive.pivot_history` array), OR don't overwrite an
existing pivot directive — only set when none exists.

---

## 200. `tool_executor` `_READ_TOOLS` set is hardcoded

**File**: `agents/tool_executor.py:385-389` (and the
`_READ_TOOLS` class attribute defined elsewhere).

**Bug**: The set of "real read tools that clear the pivot
directive" is a class-level frozenset. New read tools added later
(e.g. a new `ida_headless.decompile_pseudocode`) won't be
recognized as read tools until someone updates the set. The
pivot directive then stays set even after the agent does a
legitimate read with the new tool.

**Fix**: A registration decorator on the adapter / tool spec
that flags it as a read tool. The set is computed from registered
adapters.

---

## 201. `tool_executor` malformed-command count uses `_count_consecutive_malformed`

**File**: `agents/tool_executor.py:127-129`.

**Bug**: `malformed_count >= 1` triggers the STOP message at
line 130 (so on the SECOND consecutive malformed). The count
looks at recent messages. A non-malformed tool result between
two malformed tool runs RESETS the count.

Pattern: empty → good → empty → good → empty → good — count
is always 0 because each empty is followed by a good. The STOP
never fires. Agent keeps producing empty commands indefinitely.

**Fix**: Use total-malformed-count for this branch, not
consecutive. Once an agent has produced 5 malformed commands
(of any sequence) the STOP fires.

---

## 202. `tool_executor.execute` checks `raw.get("status") == "error"` — misses other failure flags

**File**: `agents/tool_executor.py:223`.

**Bug**: Only checks the literal string `"error"`. A bridge that
returns `{"status": "failed", ...}` or `{"status": "timeout"}`
falls through to the success path. The adapter then runs against
a "failed" response as if it succeeded.

The bridge's own forward function probably returns "error" but
downstream MCPs (android_mcp, ida_headless) may pass through
their own status strings. The check is fragile.

**Fix**: Treat ANY non-"ok" / non-"success" status as failure.
Whitelist success values rather than blacklist error values.

---

## 203. `tool_executor._write_result_message` + `_merge_observables` in two separate UoWs

**File**: `agents/tool_executor.py:391-397`.

**Bug**: `_write_result_message` opens its own UoW (line 444),
commits. Then `_merge_observables` opens another UoW
(presumably) for the case_state write. Two separate transactions.

A concurrent reader (auto_steering, frontend polling, sibling
branch's investigation_loop reading the case_state) can observe
the message without the observables OR vice versa. The
inconsistency window is small (~10ms) but non-zero.

**Fix**: One UoW for both writes.

---

## 204. `pattern_store.create` is NOT atomic — 3 transactions for one create

**File**: `services/pattern_store.py:139-189`.

**Bug**: UoW #1 INSERTs the pattern row, commits at line 154.
No UoW: knowledge.store call at line 161-174 opens its own
session, writes the mirror, commits. UoW #2 (line 177-188)
UPDATEs the pattern with knowledge_entry_id.

Failure modes:
  - Crash between (1) and (2): pattern row exists with
    `knowledge_entry_id=None`. Semantic search by pattern id
    can't find the mirror.
  - Crash between (2) and (3): knowledge mirror exists; pattern
    row points to None. The mirror is orphaned (no pattern
    reference back).

No reaper sweeps for these conditions. The orphaned rows live
forever.

**Fix**: Single UoW that creates both AND writes the link in one
transaction. The KnowledgeService.store needs an in-transaction
variant.

---

## 205. `pattern_store.create` dedup_key truncates summary to 200 chars

**File**: `services/pattern_store.py:137`.

**Bug**: `dedup_key = f"{body.workspace_id}|{body.kind.value}|{body.summary[:200]}"`.
Two patterns with the same first-200-chars-of-summary but
different bodies hash to the same dedup key. KnowledgeService
treats them as the same entry, skipping the second.

Lost pattern data — second pattern's body never gets a mirror,
so it's invisible to semantic search.

**Fix**: Include a hash of the body in the dedup key, OR drop
the truncation (let dedup use the full summary).

---

## 206. `pattern_store.create` doesn't error when KnowledgeService returns no entry_id

**File**: `services/pattern_store.py:175-189`.

**Bug**: `entry_id = store_result.get("entry_id")`. If
KnowledgeService returns no entry_id (because the mirror didn't
actually get persisted, or the dedup logic returned an existing
entry's id without surfacing it), the conditional at line 185
`if isinstance(entry_id, int) and entry_id != row.knowledge_entry_id`
is False. The pattern row's `knowledge_entry_id` stays NULL.
The pattern is created but un-mirrored.

No error raised. The caller (`PatternExtractor` at line 195-201)
treats this as success and counts the pattern as persisted —
per §192 it's invisible to semantic search.

**Fix**: Raise `PatternStoreError("mirror not persisted")` when
entry_id is None.

---

## 207. `audit_mcp_bridge._warmed_indexes` class-level set leaks across instances

**File**: `tools/audit_mcp_bridge.py:281-282`.

**Bug**: `_warmed_indexes: set[str] = set()` and
`_warm_locks: dict[str, Any] = {}` are CLASS attributes. Every
`AuditMcpBridgeTool` instance shares the same set and dict.

Side effects:
  - Test setUp creates a fresh bridge but the set is still
    populated from a previous test — warmup behavior changes
    based on test order.
  - In a long-running worker, the dict grows monotonically as
    new investigations spawn new indexes. Each index_id is a
    string key in the dict; locks are never garbage-collected.
    Memory leak across ~100K investigations per worker.

**Fix**: Move to instance attributes initialized in `__init__`.
Worker-process shared state belongs in a dedicated singleton, not
a class attribute.

---

## 208. `audit_mcp_bridge._resolve_base_url` constructs ConfigRegistry per call

**File**: `tools/audit_mcp_bridge.py:293-300`.

**Bug**: `cfg_value = await ConfigRegistry().get(...)`.
ConfigRegistry construction does DB lookups (per §125). Every
`_resolve_base_url` call (every forward call to audit_mcp) does
a fresh ConfigRegistry.

For a typical investigation that runs 70 tool calls, 70 fresh
ConfigRegistry constructions × O(N) DB reads each = significant
overhead.

**Fix**: Cache the resolved URL on the bridge instance for the
lifetime of the bridge. The URL doesn't change during an
investigation.

---

## 209. `audit_mcp_bridge._resolve_base_url` narrow exception filter

**File**: `tools/audit_mcp_bridge.py:298`.

**Bug**: `except (ValueError, RuntimeError, ImportError)`. A
SQLAlchemy `OperationalError` (DB unavailable), `ConfigKeyError`
(missing config), or any other exception from `ConfigRegistry().get`
propagates up and crashes the bridge call.

The tool dispatcher above (`tool_executor.execute`) catches
`(OSError, TimeoutError, RuntimeError)` — doesn't include
SQLAlchemy errors either. So a DB hiccup during URL resolution
crashes the entire turn, not just the tool call.

**Fix**: Broader catch with INFO-level log. Bridge URL resolution
is a config lookup — fail-safe to the default.

---

## 210. Summary part 13

13 more bugs (#197-209). Total now 209+ items.

File density updates:

|file|count|
|---|---|
|`agents/tool_executor.py`|3 + 7 (§197-203) = 10|
|`services/pattern_store.py`|3 (§204-206)|
|`tools/audit_mcp_bridge.py`|3 (§207-209)|

No code touched for §197-209.

---

# Part 14 — bridges / verdict mapper / seed / enrichment / dispatcher per-kind

## 211. `ida_bridge._SPEC_CACHE` / `_AUTO_ALIAS_MAP` class-level mutable defaults

**File**: `tools/ida_bridge.py:237, 156`.

Same pattern as audit_mcp_bridge §207. Class-level mutable cache
— survives across instances but is lost on worker restart. If
the IDA MCP server hot-reloads with a new tool catalog, AILA's
bridge keeps using the stale cache. Cold restart required.

The alias map is also class-level — switching from IDA Free to
IDA Pro with different tool names mid-session leaves the alias
map pointed at the wrong canonicals.

**Fix**: Instance-level caches OR explicit invalidation endpoint
the operator can call when the upstream MCP catalog changes.

---

## 212. `ida_bridge._resolve_base_url` narrow exception filter

**File**: `tools/ida_bridge.py:113`.

`except (ValueError, RuntimeError, ImportError)`. Same as
audit_mcp_bridge §209: SQLAlchemy errors during ConfigRegistry
lookup crash the bridge call instead of falling back to the
default URL.

---

## 213. `ida_bridge._upload_binary` reads ENTIRE binary into memory

**File**: `tools/ida_bridge.py:313`.

`file_bytes = await asyncio.to_thread(target.read_bytes)`. A
4GB binary upload requires 4GB resident memory in the worker
process before posting. AILA workers run on machines with
limited RAM (typically 8-16GB). A single large binary upload
can OOM the worker, killing all in-flight investigations.

The previous version (per comment line 308-312) was worse — it
held the file open through the synchronous chunked POST — but
streaming via `httpx`'s multipart-with-async-generator is
strictly better than both.

**Fix**: Stream via `httpx.stream` + `AsyncIterator[bytes]` reading
chunks from disk. Cap memory at ~64MB regardless of binary size.

---

## 214. `ida_bridge.forward` status normalization fallthrough

**File**: `tools/ida_bridge.py:222-228`.

```python
if payload_status in ("ready", "pending", "error"):
    ctx["status"] = payload_status
elif resp.status_code < 400:
    ctx["status"] = "ready"
```

If the MCP returns `{"status": "queued"}` with HTTP 200, the
elif falls through and marks status as `"ready"`. The
tool_executor (§202) then treats it as a successful result,
writes it to the agent's case_state, agent moves on — when in
fact the work is still queued upstream. This is the D-294
failure shape: "No worker detected. Request queued" with
HTTP 200 was the literal bug.

**Fix**: Whitelist success values explicitly. Anything not in
`("ready", "completed", "ok")` and not in the known async
states (`pending`, `queued`, `running`) maps to `"error"`.

---

## 215. `android_mcp_bridge.forward` accepts unknown status as `"ready"`

**File**: `tools/android_mcp_bridge.py:315-328`.

Lines 315-323 honor explicit `payload.status == "error"`. After
that, line 325 unconditionally sets `ctx["status"] = "ready"`.
But the bridge handler doesn't validate the payload SHAPE.

If android-mcp returns `{"status": "partial_failure", "errors": [...]}`,
the dict has no `"error"` key, so `_log.warning` doesn't fire.
`ctx["status"] = "ready"` overwrites the real failure state.
The caller writes "ready" into the call log and the agent gets
the partial-failure payload as if it were success.

**Fix**: Same whitelist as §214 — only `"ready" / "completed" / "ok"`
map to success; everything else is at minimum a warning.

---

## 216. `android_mcp_bridge.forward` upload not parallelizable

**File**: `tools/android_mcp_bridge.py:251-252`.

The forward wraps every call in `httpx.AsyncClient(timeout=...)`
— constructs a new client per call. Each construction opens a
fresh connection pool. For an investigation that makes 70
android-mcp tool calls, that's 70 connection pools created and
torn down.

**Fix**: Module-level shared `AsyncClient` with connection
pooling. The audit_mcp_bridge has the same shape — would be
a 2x latency improvement on hot tool surfaces.

---

## 217. `verdict_mapper._extract_evidence_locations` silently caps at 32

**File**: `masvs/verdict_mapper.py:394, 397-444`.

`_EVIDENCE_LOCATION_CAP: int = 32`. The agent emits 50 affected
components — the 33rd through 50th are dropped silently. No
"and N more" hint in the verdict. The PDF reader doesn't know
the data was truncated.

**Fix**: Add `evidence_locations_total` field on
MasvsControlVerdict carrying the true count. PDF renderer
shows "32 of 50 components shown — see investigation page for
full list".

---

## 218. `verdict_mapper` Branch 3 misses "confirmed + low-conf"

**File**: `masvs/verdict_mapper.py:152-184`.

Branch 3 handles DIRECT_FINDING:
  - `verifier_verdict == "inconclusive"` → INCONCLUSIVE
  - `numeric_conf >= 0.6` → FINDING
  - else → INCONCLUSIVE

Missing: `verifier_verdict == "confirmed"` with `numeric_conf < 0.6`.
Falls into the "else" branch → INCONCLUSIVE. The verifier
explicitly said "confirmed" but the mapper downgrades it
because confidence is below the auto-promote floor. This is
wrong — the verifier's verdict is the canonical signal; the
confidence is for AUTO-PROMOTE only.

**Fix**: When verifier_verdict == "confirmed", FINDING
regardless of confidence (use the verifier's confidence as
the reported number).

---

## 219. `verdict_mapper._ENUM_CONFIDENCE` defaults to 0.0 on unknown

**File**: `masvs/verdict_mapper.py:117`.

`numeric_conf = _ENUM_CONFIDENCE.get(outcome.confidence, 0.0)`.
If a new OutcomeConfidence enum value is added later (e.g.
CERTAIN, MAYBE), the dict lookup defaults to 0.0 → all
findings of the new enum value land at INCONCLUSIVE because
they fail the 0.6 floor.

Silent verdict downgrade across the entire MASVS run when the
enum grows.

**Fix**: Either raise on unknown enum value (fail loud) or
map UNKNOWN to MEDIUM (≥ floor) so new enum values default
to "treat as a finding pending operator review".

---

## 220. `verdict_mapper._has_not_applicable_tag` preserves agent confidence

**File**: `masvs/verdict_mapper.py:124-134`.

NOT_APPLICABLE branch sets `confidence=numeric_conf` — the
agent's claimed confidence on the not_applicable claim. But
not_applicable is a binary, deterministic statement (control
does/doesn't apply to this APK). The confidence field is
meaningless here.

The PDF then renders "N/A (confidence 0.6)" — operator-confusing
display.

**Fix**: Set `confidence=1.0` for NOT_APPLICABLE verdicts.

---

## 221. `seed._PROMPT_TEMPLATE` injects local filesystem path

**File**: `masvs/seed.py:84, 145-165`.

The `decompiled_dir` value (line 84) is a local filesystem path
from `apk_overview.decompiled_dir`. Injected raw into the
prompt at template line 148 (visible to the agent indirectly
via the audit_mcp index id, but exposed via decompiled_dir
isn't shown to the agent in current template — let me re-read).

Wait — the current template at lines 145-165 doesn't include
`{decompiled_dir}` in the output. So it's loaded into the
function but never used. Dead variable.

**Fix**: Drop `decompiled_dir` from `MasvsSeedBuilder.build`
— it's loaded but never injected.

---

## 222. `seed.MasvsSeedBuilder.build` empty `verification_steps` silently empty section

**File**: `masvs/seed.py:87-90, 154-156`.

`steps_block = "\n".join(...)`. When `control.verification_steps`
is empty, `steps_block = ""`. The template then emits:

```
## Verification steps


## Evidence hints (...)
```

An empty Verification steps section with no fallback message.
Unlike `hints_block` (line 91-94) which has `"  - (none catalogued)"`
fallback, steps has no fallback. The agent's prompt has
structural inconsistency — they see "verify these steps" then
nothing then "evidence hints".

**Fix**: Same fallback as hints_block: `"(none catalogued — use evidence hints below)"`.

---

## 223. `seed.MasvsSeedBuilder.build` no isinstance check on `static_summary`

**File**: `masvs/seed.py:73-76`.

```python
static_summary: Mapping[str, Any] = (
    overview.get("static_summary") or {}
)
```

If `static_summary` is a non-dict (e.g. corrupted JSON, agent
wrote a string by mistake), the `static_summary.get(...)` calls
at lines 78-80 raise AttributeError. The seed builder crashes
→ MASVS audit dispatcher fails → operator sees "internal error"
with no useful context.

**Fix**: `if not isinstance(static_summary, Mapping): static_summary = {}`.

---

## 224. `profile_builder.build` returns "complete" profile even when ALL signals fail

**File**: `enrichment/services/profile_builder.py:315-395`.

Both `_gather_source_signals` and `_gather_binary_signals` use
`if resp.get("status") == "ready"` to gate signal population.
If every MCP call returns `{"status": "error"}`, the signals
dict ends up empty (or only carries the index_id check). The
function then proceeds to `_compose_profile` with empty
signals.

Result: profile with `primary_language=""`, empty
`applicable_fuzzing_engines`, default disclosure tracks.
Stage marked DONE. Operator sees a "complete" profile that
contains zero information from the binary.

**Fix**: Track signals_collected. Raise
ProfileBuilderError("all MCP signals failed") when < N of M
gathers returned ready.

---

## 225. `profile_builder._gather_binary_signals` is SEQUENTIAL — 7 calls

**File**: `enrichment/services/profile_builder.py:352-393`.

Seven sequential `self._ida.forward()` calls:
  - binary_survey
  - checksec
  - classify_behavior
  - verify_capabilities
  - capa_scan
  - imports
  - exports

Each ~30s. Total ~3.5 min for stage. With `asyncio.gather`
the wall-clock collapses to ~30s — the slowest call.

**Fix**: `asyncio.gather(*[forward(...) for action in ACTIONS])`.

---

## 226. `profile_builder._compose_profile` `(kind, "")` falls through to empty engines

**File**: `enrichment/services/profile_builder.py:419-422`.

`engines_key = (target_row.kind, primary_language.lower())`.
When language detection failed (primary_language is ""), key
is `(kind, "")`. The `_APPLICABLE_FUZZING_ENGINES` dict has no
such key → default `[]`.

No `(kind, "*")` wildcard for fuzzing engines (unlike
`_DEFAULT_REASONING_STRATEGY` at line 426). Target with unknown
language gets zero fuzzing engines — silent gap.

**Fix**: Add `(kind, "*")` defaults to `_APPLICABLE_FUZZING_ENGINES`
for the unknown-language case.

---

## 227. `profile_builder.build` preserved_keys list will rot

**File**: `enrichment/services/profile_builder.py:286-290`.

```python
preserved_keys = ("function_ranking", "enrichment_errors", "overrides")
preserved = {k: existing[k] for k in preserved_keys if k in existing}
merged = profile.model_dump(mode="json")
merged.update(preserved)
```

If a future version adds `function_ranking` as a proper field
on `TargetCapabilityProfile`, the new profile will write a
fresh `function_ranking` into `merged`. Then `merged.update(preserved)`
SILENTLY OVERWRITES that fresh value with the stale one from
`existing`. The new profile is degraded by the "preservation"
logic.

**Fix**: Either move these out of capability_profile_json into
a separate column, OR only preserve keys NOT in the new model
(check `model_fields` before overwriting).

---

## 228. `function_ranker.rank` references `TargetKind.APK` (does not exist)

**File**: `enrichment/services/function_ranker.py:135`.

`elif target_row.kind in { ..., TargetKind.APK.value, ... }`.
But TargetKind enum has `ANDROID_APK`, not `APK`. If `APK` was
removed in a refactor, this line fails at import-time with
AttributeError. If `APK` is still defined as a synonym, kind
matching may miss android_apk targets that report
kind="android_apk" string.

**Action**: Confirm enum membership — `grep -n "APK" contracts/target.py`.
If `APK` is gone, the dispatcher crashes; if `ANDROID_APK`
is the canonical, targets with kind="android_apk" wouldn't
match `TargetKind.APK.value`.

---

## 229. `function_ranker._rank_source` poll timeout is 15min vs StageTracker 30min

**File**: `enrichment/services/function_ranker.py:198-202`.

`if poll_attempts > 180: raise FunctionRankerError("still pending after ~15min")`.

But the StageTracker for FUNCTION_RANKING is 30min per the
docstring. The dispatcher gives up at 15min — half the stage
budget. Operator waiting longer would have gotten a real
result (audit-mcp's heavy ranking is documented as ~25-30 min
for monorepo-scale).

**Fix**: Read the stage timeout from `tracker.deadline` and
poll until it's near (with 30s safety margin) rather than
hardcoded 180.

---

## 230. `function_ranker._rank_binary` is SEQUENTIAL on parser sinks

**File**: `enrichment/services/function_ranker.py:231-244`.

Sequential `for api in _PARSER_SINK_APIS` loop. Each
`find_api_call_sites` call is ~30s. With 5+ APIs that's 2.5+
min sequential vs ~30s parallel.

Then lines 259-276: sequential `for addr in deep_addresses`
— up to 10 `assess_exploitability` calls each ~30s = 5min
sequential.

Total binary ranking budget: ~7.5 min sequential vs ~1 min
parallel.

**Fix**: `asyncio.gather`.

---

## 231. `function_ranker._rank_binary` hardcoded `sink_argument_index=0` is wrong for most sinks

**File**: `enrichment/services/function_ranker.py:271`.

`sink_argument_index=2 if sink in {"memcpy", "memmove"} else 0`.

But the tainted argument for most sinks is NOT at index 0:
  - `strcpy(dst, src)` — src is index 1.
  - `sprintf(buf, fmt, ...)` — fmt is index 1.
  - `system(cmd)` — cmd is index 0 ✓.
  - `execve(path, argv, envp)` — path is index 0 ✓ but
    user-controlled often comes via argv (index 1).
  - `gets(buf)` — index 0 is dst, no tainted source (gets reads
    stdin internally).
  - `strcat(dst, src)` — src is index 1.

Hardcoded 0 is correct for ~30% of common sinks. For the rest,
`assess_exploitability` is run against the wrong argument
slot, producing wrong/missing verdicts. The output is
miscategorized as "no exploit path" when there clearly is one.

**Fix**: A per-sink table of canonical taint-arg indices.

---

## 232. `function_ranker._rank_binary` score normalization compresses

**File**: `enrichment/services/function_ranker.py:280, 287`.

`normalized = row["hits"] / max_hits if max_hits else 0.0`.

If max_hits is 1 (single highest-ranked function with 1
callsite), every function in the top-K has `normalized = 1.0 / 1.0 = 1.0`
or less. The score lost all discriminative power.

The `min(1.0, normalized)` at line 287 then caps at 1.0 — but
the cap is irrelevant because normalized is already in [0, 1].

**Fix**: Log-scale or use raw `hits` as the score (callers can
normalize as needed).

---

## 233. `outcome_dispatcher._dispatch_variant_hunt_order` does NOT enqueue child

**File**: `agents/outcome_dispatcher.py:534-604`.

**CRITICAL BUG**.

The canonical VARIANT_HUNT_ORDER outcome path creates a
VRInvestigationRecord (status=CREATED) plus a primary
VRInvestigationBranchRecord. Returns DISPATCHED.

Does NOT submit the `run_vr_investigate` task. The child
investigation sits at CREATED forever, never executed. No
reaper drives CREATED → RUNNING for variant_hunt children.

Compare to `_spawn_variant_child` at line 606-691 which DOES
enqueue at lines 674-690. Those bundled variant orders
(inside a DIRECT_FINDING payload) execute correctly. Standalone
VARIANT_HUNT_ORDER outcomes produce zombie investigations.

**Fix**: Add the same `task_queue.submit(track="vr", fn=run_vr_investigate, ...)`
block at line 596 (after `child_id = child.id`).

---

## 234. `outcome_dispatcher._dispatch_variant_hunt_order` parent.cost_budget_usd=None crashes

**File**: `agents/outcome_dispatcher.py:568-570`.

`child_budget = float(payload.get("cost_budget_usd") or (parent.cost_budget_usd * 0.5))`.

If `parent.cost_budget_usd` is None and payload doesn't carry
`cost_budget_usd`, `None * 0.5` raises TypeError. Dispatch
aborts. The dispatcher's `except (OSError, TimeoutError, RuntimeError, ValueError)`
filter doesn't catch TypeError → dispatch failure propagates,
outcome stuck DISPATCHED state never reached.

**Fix**: Default to a hardcoded floor (e.g. $5) when parent
budget is None. Validate at fork time.

---

## 235. `outcome_dispatcher._dispatch_direct_finding` two commits in one UoW

**File**: `agents/outcome_dispatcher.py:438-476`.

Pattern:
  1. UoW opens
  2. INSERT finding, `commit()` at line 460
  3. SELECT investigation, UPDATE `linked_finding_ids_json`,
     `commit()` at line 476

If the second commit fails (DB transient error, FK problem
on linked_finding_ids_json), the finding exists but the
investigation row doesn't reference it. Orphan finding,
investigation appears to have no findings.

**Fix**: One UoW, one commit. Add the finding + update the
investigation in the same transaction.

---

## 236. `outcome_dispatcher._dispatch_direct_finding` variant spawn loop has no rollback

**File**: `agents/outcome_dispatcher.py:487-499`.

```python
for raw in variants:
    try:
        child_id = await self._spawn_variant_child(...)
        spawned_children.append(child_id)
    except (ValueError, RuntimeError) as exc:
        spawn_errors.append(...)
```

If the loop spawns children 1-5 successfully and child 6 fails,
children 1-5 are alive. The dispatch result reports
`variant_errors=...` but children 1-5 already enqueued and
started consuming budget. Operator who sees the partial
failure may try to re-dispatch — duplicates children 1-5.

**Fix**: Either spawn all in a single transaction with full
rollback on any failure, OR record the spawned child ids in
the outcome payload so re-dispatch knows which to skip.

---

## 237. `outcome_dispatcher._dispatch_direct_finding` recursive variant budget halves to 0

**File**: `agents/outcome_dispatcher.py:641` (via `_spawn_variant_child`).

`child_budget = float(payload.get("cost_budget_usd") or (parent.cost_budget_usd * 0.5))`.

At generation 10: $100 → $50 → $25 → $12.50 → $6.25 → $3.13 →
$1.56 → $0.78 → $0.39 → $0.20. After 10 generations the
variant has $0.20 — below the cost of a single LLM turn. The
investigation immediately hits cost cap and is FAILED.

No floor. Variant chains terminate at a depth determined by
the parent's initial budget, not by an explicit depth limit.

**Fix**: Explicit `MAX_VARIANT_DEPTH = 5` enforced at fork
time AND a floor at the budget (e.g. $5 minimum). Refuse
to spawn beyond either.

---

## 238. `outcome_dispatcher._dispatch_direct_finding` variant orders dict-shape silently dropped

**File**: `agents/outcome_dispatcher.py:486-490`.

```python
variants = payload.get("variant_hunt_orders")
if isinstance(variants, list):
    for raw in variants:
        if not isinstance(raw, dict):
            continue
```

If the agent supplies `variant_hunt_orders` as a single dict
(common LLM mistake — "one order vs list of orders"), the
outer isinstance check fails. The variant orders are silently
dropped. No warning, no `variant_hunt_advisory` flag.

Same for the inner loop: if a raw entry is a string (e.g. agent
wrote `[{...}, "second order as string"]`), the string is
silently skipped. Partial data loss.

**Fix**: Coerce dict → `[dict]` before the loop. Log when an
inner entry is dropped.

---

## 239. `outcome_dispatcher._dispatch_direct_finding` advisory branch only fires for variant_hunt

**File**: `agents/outcome_dispatcher.py:395-429`.

The `variant_hunt_advisory` flag only stamps the payload for
`inv.kind == "variant_hunt"`. For an AUDIT or NDAY child that
also submits an empty `variant_hunt_orders` list, the advisory
is never written. Operator review of an AUDIT outcome can't
see whether the agent explicitly declared exhaustion vs
silently produced an empty list.

**Fix**: Apply the advisory uniformly — any DIRECT_FINDING
with empty `variant_hunt_orders` and a confident verdict gets
stamped.

---

## 240. `target_analysis._analyze_android_apk` is fully sequential — 5 stages

**File**: `services/target_analysis.py:398-412`.

Five stages in a chain: APK_DECODE → JADX_DECOMPILE →
INDEX_DECOMPILED → STATIC_SUMMARY → MOBSF_SCAN. All sequential.

Dependency analysis:
  - APK_DECODE (apktool): independent, ~30s.
  - JADX_DECOMPILE: independent (takes APK directly), ~5-15min.
  - INDEX_DECOMPILED: depends on JADX (needs decompiled tree).
  - STATIC_SUMMARY (androguard): independent, ~30s.
  - MOBSF_SCAN: independent, ~5-30min.

Parallelizable groups:
  - [APK_DECODE, JADX_DECOMPILE, STATIC_SUMMARY, MOBSF_SCAN]
    can run concurrently.
  - INDEX_DECOMPILED runs after JADX_DECOMPILE.

Current wall-clock ~50min worst case; could be ~30min with
parallel groups.

**Fix**: `asyncio.gather` for the independent group, then
await INDEX_DECOMPILED after JADX completes.

---

## 241. `target_analysis` hardcoded 4-hour poll timeout

**File**: `services/target_analysis.py:59`.

`_POLL_TIMEOUT_SECONDS = 14400.0`. Module constant. For very
large source repos (e.g. Linux kernel mainline ~5GB,
chromium ~50GB) 4 hours may be insufficient. The bound is
silent — no env override, no per-stage configuration.

**Fix**: Read `VR_INGESTION_POLL_TIMEOUT_S` env var; default
to 14400 but allow operator extension.

---

## 242. `target_analysis.analyze` android exceptions bypass operator-resume path

**File**: `services/target_analysis.py:263-265`.

The android path returns early at line 264-265, OUTSIDE the
`try/except StageAlreadyDoneError/StageInFlightError` block
at line 268-328. If `_analyze_android_apk` raises (e.g.
intermediate stage failed with non-StageInFlightError), the
exception propagates uncaught into the ARQ task.

The legacy path (line 268-328) catches the two stage-state
exceptions and returns silently. Android path doesn't — the
ARQ task sees the raw exception, logs at ERROR level, marks
the task failed. Operator must dig through worker logs to
understand what happened.

**Fix**: Wrap `_analyze_android_apk` call in the same
try/except.

---

## 243. Summary part 14

33 more bugs (#211-242). Total now 242+ items.

File density updates after parts 13-14:

|file|count|
|---|---|
|`agents/vuln_researcher.py`|13|
|`agents/outcome_dispatcher.py`|8 + 8 = 16|
|`agents/tool_executor.py`|10|
|`agents/branch_manager.py`|10|
|`api_router.py` (vr)|10|
|`parent_reconciler.py`|9|
|`tools/ida_bridge.py`|4|
|`tools/audit_mcp_bridge.py`|3|
|`tools/android_mcp_bridge.py`|2|
|`masvs/verdict_mapper.py`|4|
|`masvs/seed.py`|3|
|`enrichment/profile_builder.py`|4|
|`enrichment/function_ranker.py`|5|
|`services/target_analysis.py`|3|

No code touched for §211-242.

---

# Part 15 — mcp_adapters / outcome_review / tool_executor helpers / dispatcher per-kind / android stages

## 244. `mcp_adapters.registry.get_adapter` returns None for unknown tools — silent drift

**File**: `agents/mcp_adapters/registry.py:129-142`.

Returns `None` when a tool is unknown. Caller (tool_executor)
surfaces "no such tool" to the agent. But this design relies on
`KNOWN_TOOLS` staying in sync with the actual upstream MCP
catalogs. If a developer adds a new MCP tool to the bridge but
forgets to extend `known_tools.KNOWN_TOOLS`, the bridge can
handle the call (forward works) but the adapter resolution
returns None.

The result: agents can call the tool but its result message
never gets written. Silent feature drop until someone notices.

**Fix**: Have the bridges auto-populate `KNOWN_TOOLS` at startup
via their `/tools` catalog endpoints. Stop maintaining a manual
list.

---

## 245. `audit_mcp.adapt_search_functions` re-binding at module load

**File**: `agents/mcp_adapters/audit_mcp.py:928, 1008`.

Line 928: `adapt_search_functions = _adapt_search("search_functions")`
(factory output).
Line 1008: `adapt_search_functions = _adapt_search_functions_specialized`
(overrides).

The factory-bound version at line 928 is dead. Future devs may
rely on line 928's behavior without realizing line 1008
overrides it. Refactor risk: deleting either line silently
changes behavior.

**Fix**: Delete line 928. Only line 1008 (specialized version)
should exist.

---

## 246. `audit_mcp._render_chunks_dense` silently drops non-dict results

**File**: `agents/mcp_adapters/audit_mcp.py:1042-1043`.

`if not isinstance(r, dict): continue`. If an MCP returns
results as strings (some adapters might for simple results),
they're silently dropped. The agent sees fewer chunks than
actually returned, with no warning.

**Fix**: Coerce non-dict results to `{"content": str(r)}` so
they still appear (with no metadata) instead of vanishing.

---

## 247. `audit_mcp._render_chunks_dense` per-block size unbounded

**File**: `agents/mcp_adapters/audit_mcp.py:1056-1060`.

The size check is `if total_chars + len(block) > _MAX_OBS_CHUNKS: continue`.

But there's no per-block cap. A single chunk with 200MB body
would individually exceed the budget — it gets dropped (line
1057: `dropped += 1; continue`), then subsequent normal blocks
can be added. But the rendering loses the big chunk's content
entirely.

`_MAX_OBS_CHUNKS = 100_000_000` (100MB) — in practice this
drop probably never fires. But the logic is fragile.

**Fix**: Truncate the offending block at the per-block cap
rather than dropping it. Surface "truncated" marker.

---

## 248. `outcome_review.post_draft_review_request` LIKE-on-payload_json idempotency check

**File**: `services/outcome_review.py:425-437`.

```python
_select(VRInvestigationMessageRecord)
.where(...investigation_id == investigation_id)
.where(...payload_json.contains(auto_steering_key))
.limit(1)
```

Two issues:

  1. **Substring match across the JSON text column**. If another
     message contains the literal `auto_steering_key` string in
     unrelated context (e.g. an agent's tool result quoted it),
     the check sees a "match" and SKIPS posting. Critical
     review-request never reaches siblings.

  2. **No FOR UPDATE or unique constraint**. Two concurrent
     calls both see "no existing" → both INSERT. Duplicate
     review-request messages.

**Fix**: Use a dedicated indexed column (e.g. `dedup_key TEXT`
with unique constraint) on the message table. SELECT ... FOR
UPDATE on it. Insert under unique violation handler.

---

## 249. `outcome_review.post_draft_review_request` only attaches message to proposing branch

**File**: `services/outcome_review.py:441-454`.

`branch_id=proposing_branch_id`. The message is attached to
the PROPOSING branch only. If the prompt builder reads messages
by branch_id (not investigation_id), sibling branches never
see the review request.

The docstring at line 378-379 says "Lands at OPERATOR position
on the next prompt for every branch". For that to work, the
prompt builder MUST query by investigation_id AND surface
OPERATOR messages across all branches. Without reading the
prompt builder, this attachment is suspicious — and is the
kind of bug that would explain why siblings don't review.

**Action**: Verify the prompt builder queries by
`investigation_id` for OPERATOR-sender messages. If it scopes
by `branch_id`, siblings literally never see review requests.

---

## 250. `outcome_review.post_draft_review_request` SenderKind.OPERATOR for system-authored message

**File**: `services/outcome_review.py:443`.

`sender_kind=SenderKind.OPERATOR.value`. The message is marked
as OPERATOR-sent. But the function name says "system-authored".
Operators can also send messages — distinguishing system steering
from actual human steering becomes impossible from `sender_kind`
alone.

`sender_id="outcome_review"` (line 445) is the only way to
tell them apart. UI filtering by sender_kind would lump
system-steering with human-steering.

**Fix**: Either add a `SenderKind.SYSTEM` enum value, or expose
the `sender_id` discriminator prominently in UI filters.

---

## 251. `outcome_review.post_draft_review_request` uses `uow.commit()` not `uow.session.commit()`

**File**: `services/outcome_review.py:456`.

`await uow.commit()`. Other call sites use `await uow.session.commit()`
(e.g. pattern_store.py:188, outcome_dispatcher.py:460,
target_analysis.py inline). Inconsistent commit pattern across
codebase — `uow.commit()` is a wrapper method on UnitOfWork,
while `uow.session.commit()` calls the session directly.

Different commit semantics? Unclear without reading
`platform/uow.py`. The inconsistency itself is a code-smell.

**Fix**: Pick one canonical commit pattern and enforce
(grep + lint rule). My guess from the code: `uow.commit()`
is the convenience wrapper that also handles auto-flush; both
should work but the codebase should pick one.

---

## 252. `tool_executor._resolve_index_id` cache is unbounded

**File**: `agents/tool_executor.py:502-545`.

`self._inv_index_id_cache[investigation_id] = resolved`. The
dict grows monotonically over the worker lifetime — every
investigation processed has an entry. For a worker handling
100K+ investigations, this dict holds 100K entries.

No TTL. If the target's `audit_mcp_index_id` ever changes
(re-ingestion, target switch, audit-mcp restart with new
index ids), the cache returns stale value. Investigation
tool calls go to wrong index → "no results" forever.

**Fix**: TTL-based eviction (e.g. functools.lru_cache(maxsize=2048)
pattern). OR invalidate on a known event (target row updated
after a certain timestamp).

---

## 253. `tool_executor._resolve_index_id` narrow exception filter

**File**: `agents/tool_executor.py:544`.

`except (OSError, RuntimeError, ImportError, AttributeError)`.
SQLAlchemy errors (DB transient failures) not caught — they
propagate up and crash the tool dispatch. The auto-correct
for `index_id` placeholders should NEVER block the underlying
tool call.

**Fix**: `except Exception` with INFO log. The auto-correct
is a best-effort optimization; failure should silently use
the agent-supplied args.

---

## 254. `tool_executor._count_consecutive_malformed` string-literal match

**File**: `agents/tool_executor.py:587`.

`"Malformed tool_run" in str(payload.get("text", ""))`.
Literal substring match. If a future refactor changes the
error wording (e.g. "Invalid tool_run" or "Bad tool command"),
the detector silently returns 0 and the STOP threshold never
fires.

**Fix**: Constant for the marker string at top of file,
referenced by both the writer (when emitting the error
message) and this reader.

---

## 255. `tool_executor._count_prior_failures` O(N²) walk

**File**: `agents/tool_executor.py:632-636`.

For each error in the last 50 messages, calls `_messages_before`
which does another DB query for 3 prior messages. 50 errors ×
1 prior-call query each = 50 nested queries per circuit-breaker
check.

The circuit breaker runs on EVERY tool error. For a branch with
many tool errors, this becomes a significant fraction of tool
dispatch latency.

**Fix**: Single query that fetches messages with their
positional rank (window function: `LAG()`). Or precompute the
(tool_call, tool_result) pairs in one query and walk in
memory.

---

## 256. `tool_executor._count_consecutive_malformed` uses string literal `sender_kind == "engine"`

**File**: `agents/tool_executor.py:575`.

Filter `VRInvestigationMessageRecord.sender_kind == "engine"`.
Hardcoded string instead of `SenderKind.ENGINE.value`. If the
enum value renames, this query silently returns no rows —
malformed count is always 0, STOP never fires.

**Fix**: Use the enum value, not the literal.

---

## 257. `tool_executor._survey_streak_hint` partition on `.` breaks multi-segment tool names

**File**: `agents/tool_executor.py:783`.

`tool_id = (cmd.get("tool") or "").partition(".")`. Splits on
FIRST `.`:

  - `"audit_mcp.semantic_search"` → `("audit_mcp", ".", "semantic_search")` ✓
  - `"audit_mcp.utils.read_lines"` → `("audit_mcp", ".", "utils.read_lines")` ✗

If a future tool has a multi-segment name (e.g.
`audit_mcp.utils.X`), the key check at line 785 fails:
`("audit_mcp", "utils.read_lines")` not in `_SURVEY_TOOLS`.
The survey streak detection silently misses surveys on
multi-segment-named tools.

**Fix**: `rsplit(".", 1)` to get `(server, tool)` correctly
even with multi-segment paths. OR ban multi-segment tool
names at the bridge level.

---

## 258. `tool_executor._merge_observables` JSONDecodeError-only catch

**File**: `agents/tool_executor.py:884-886`.

`try: case_state = json.loads(...); except json.JSONDecodeError`.
If `branch.case_state_json` is somehow None (column NULL), the
`or "{}"` fallback at line 884 prevents it. But if it's bytes
(stored binary by mistake), `json.loads(bytes)` works in Python
3.6+ — wait, actually it does. So this is probably fine.

The actual risk: if `branch.case_state_json` returns a numeric
type (corrupted column), `json.loads()` raises `TypeError`,
not `JSONDecodeError`. Uncaught.

**Fix**: `except (json.JSONDecodeError, TypeError)`.

---

## 259. `tool_executor._merge_observables` eviction reorders directives in dict

**File**: `agents/tool_executor.py:895-906`.

On eviction, `observables = {**kept, **directives}` puts
directives AFTER kept non-directives. Dict insertion order
is preserved in Python 3.7+. The prompt builder reads
observables in insertion order → after first eviction, the
directive ordering shifts.

If the prompt is sensitive to observable ordering (e.g. older
state first), the eviction silently changes prompt shape.

**Fix**: Preserve original key insertion order. Reconstruct
`observables` as `{k: v for k, v in original_items if k in kept or k in directives}`.

---

## 260. `tool_executor._parse_command` treats `args=null` as malformed

**File**: `agents/tool_executor.py:914-938`.

`args = decoded.get("args", {})`. If agent passes
`"args": null` explicitly (LLMs do this), `decoded.get("args", {})`
returns `None` (key exists with None value), NOT the default `{}`.

Then `isinstance(args, dict)` is False → returns None →
executor treats as malformed → STOP threshold counts toward
force-stop.

This is actually a valid call: no args needed (e.g. `list_indexes`).

**Fix**: `args = decoded.get("args") or {}` to coerce None to {}.

---

## 261. `tool_executor._parse_command` no length cap on raw input

**File**: `agents/tool_executor.py:914-938`.

`json.loads(raw)` with no length check. An agent that produces
a 10MB malformed string blocks the worker on parse attempt +
memory allocation. No DoS guard.

**Fix**: `if len(raw) > _MAX_TOOL_CMD_BYTES: return None` with
early reject. 64KB cap is plenty for any legitimate tool call.

---

## 262. `outcome_dispatcher._dispatch_campaign_launch` superseded race

**File**: `agents/outcome_dispatcher.py:776-842`.

UoW opens at line 776. Old PENDING proposals marked
`status="superseded"` at line 798. New proposal INSERT at line
802. Commit at line 842.

Two concurrent CAMPAIGN_LAUNCH dispatches on the same
`(investigation_id, target_id, descriptor_key)`:

  - Both read SAME set of old PENDING rows.
  - Both mark them superseded (write conflict resolved by DB
    isolation but values agree).
  - Both INSERT a new proposal.
  - Result: TWO new pending proposals, both with the same
    descriptor_key. The supersede-old logic only handled the
    OLD pending; nothing prevents the NEW twin from existing.

**Fix**: SELECT FOR UPDATE on pending rows for that
(target_id, descriptor_key) pair. OR add a partial unique
constraint at DB level.

---

## 263. `outcome_dispatcher._dispatch_campaign_launch` 3-key descriptor fallback creates duplicates

**File**: `agents/outcome_dispatcher.py:769-774`.

`descriptor_key = harness OR function OR function_name OR ""`.

If agent A's payload uses `function`, agent B's uses
`function_name` (same actual function), the keys differ →
supersede logic misses → both proposals coexist.

**Fix**: Canonicalize on a single field at write time. The
agent should use ONE name; the dispatcher normalizes the
others to the canonical.

---

## 264. `outcome_dispatcher._dispatch_profile_spec_draft` dedup_key loses spec content

**File**: `agents/outcome_dispatcher.py:909`.

`dedup_key=f"{workspace_id}|{profile_kind}|{profile_name}"`.

Two drafts with the same profile_name but DIFFERENT spec
content collide on dedup. KnowledgeService treats them as
duplicates → second silently replaces (or skips). Data loss.

**Fix**: Hash the spec content into the dedup_key.

---

## 265. `outcome_dispatcher._dispatch_patch_assessment_report` doesn't validate patch_descriptor keys

**File**: `agents/outcome_dispatcher.py:970-983`.

`if isinstance(patch_descriptor, dict) and patch_descriptor`.
Only checks truthiness — not whether required keys
(`vulnerable_ref`, `patched_ref`, `repo_url`) are present.

If agent supplies `{"foo": "bar"}`, `enqueue_vr_nday` is
called with garbage descriptor → nday task crashes downstream
with no clear error. Operator sees "nday_error: ValueError"
with cryptic detail.

**Fix**: Required-key validation BEFORE enqueue.

---

## 266. `outcome_dispatcher._dispatch_patch_assessment_report` variant spawn no rollback

**File**: `agents/outcome_dispatcher.py:951-963`.

Same pattern as DIRECT_FINDING (§236): partial children
survive partial failure. No transactional all-or-nothing.

---

## 267. `target_analysis._android_apk_decode` `force=True` but `jadx_decompile` no force

**File**: `services/target_analysis.py:472, 503-505`.

`apktool_decode` uses `force=True` so retries overwrite
leftover output (line 471-472 comment explains this).

`jadx_decompile` (line 503-505) does NOT pass force. If jadx
also fails on "destination exists" without force, the JADX
stage perma-fails on retry — same failure mode the apktool
comment describes.

**Fix**: Mirror — pass `force=True` (or equivalent flag in
android-mcp's jadx_decompile contract) for consistent retry
behavior.

---

## 268. `target_analysis._android_static_summary` inlines full androguard response

**File**: `services/target_analysis.py:622`.

`current_handles["android_mcp_static_summary"] = resp`. The
full androguard summary (manifest XML, all permissions, all
exported components) embedded inline in `mcp_handles_json` —
single column, single row.

For complex APKs the response can be 100KB-2MB. Every target
row read (e.g. analyze, target detail page, profile build)
pays full bandwidth.

**Fix**: Store the summary in a separate `target_static_summaries`
table OR an artifact (file path + content addressed). Keep
`mcp_handles_json` slim.

---

## 269. `target_analysis._android_mobsf_scan` inlines full MobSF response

**File**: `services/target_analysis.py:666`.

`current_handles["android_mcp_mobsf_scan"] = resp`. MobSF scan
output for a complex APK can be 5-10 MB. Same inline storage
problem as §268 — every target row read carries the MB-scale
blob.

Also: storing MobSF output where it can reach prompts is per
D-100 / per the bridge's PIPELINE_ONLY_TOOLS comment (line 90
of android_mcp_bridge.py) PROHIBITED. The bridge explicitly
says "mobsf output must never reach prompts per operator".

If a downstream consumer reads `target.mcp_handles_json` and
forwards the `android_mcp_mobsf_scan` field to a prompt
(prompt builder, agent reasoning, etc.), the policy is
silently violated.

**Fix**: Store MobSF in a separate column or artifact with an
explicit "do not include in prompts" annotation. Verify no
prompt-building code path reads `android_mcp_mobsf_scan`.

---

## 270. `target_analysis._android_index_decompiled` inline await of 4-hour audit-mcp poll

**File**: `services/target_analysis.py:593`.

`await self._poll_audit_mcp(index_id)`. The poll respects
`_POLL_TIMEOUT_SECONDS = 14400` (4 hours per §241).

Inline await inside the stage worker. The ARQ worker is
blocked for up to 4 hours waiting on audit-mcp's
`index_codebase` call. During that window, the worker can't
pick up other tasks. For a worker pool of 4 + 4 simultaneous
APK ingests in different investigations, the entire pool
stalls.

**Fix**: Yield the wait — schedule a continuation task that
checks index readiness, rather than holding the worker slot.
OR ensure the worker pool size is sized for the inline-wait
ceiling.

---

## 271. Summary part 15

28 more bugs (#244-270). Total now 270+ items.

File density updates after part 15:

|file|count|
|---|---|
|`agents/outcome_dispatcher.py`|**20**|
|`agents/vuln_researcher.py`|13|
|`agents/tool_executor.py`|**18**|
|`agents/branch_manager.py`|10|
|`api_router.py` (vr)|10|
|`parent_reconciler.py`|9|
|`enrichment/function_ranker.py`|5|
|`enrichment/profile_builder.py`|4|
|`tools/ida_bridge.py`|4|
|`masvs/verdict_mapper.py`|4|
|`agents/mcp_adapters/audit_mcp.py`|3|
|`services/outcome_review.py`|4|
|`services/target_analysis.py`|7|
|`agents/mcp_adapters/registry.py`|1|
|`tools/audit_mcp_bridge.py`|3|
|`tools/android_mcp_bridge.py`|2|
|`masvs/seed.py`|3|

No code touched for §244-270.

---

# Part 16 — adapter shared / ida_headless adapter / workflow states

## 271. `_shared.MAX_OBS_DUMP_CHARS` comment-vs-value drift

**File**: `agents/mcp_adapters/_shared.py:29-36`.

The block comment narrates `2000 → 15000`, but the actual
value is `100_000_000` (100MB). The comment is stale by 6700x.
The constant is conceptually a per-observation budget; with
100MB defaults, the "bounded preview" pattern the docstring
describes is effectively unbounded.

**Fix**: Either restore the small cap and let specialized
adapters explicitly override (per the docstring contract), OR
drop the rationale block since it no longer reflects code
behavior.

---

## 272. `_shared.bounded_dump` `indent=2` triples JSON size before cap

**File**: `agents/mcp_adapters/_shared.py:103`.

`text = json.dumps(value, indent=2, default=str)`. Pretty-
printed JSON bloats the byte count by ~3x over compact form.
The cap at line 36 is applied AFTER indentation, so the
effective semantic budget is ~33MB of actual data (rest is
whitespace).

**Fix**: Either drop `indent=2` (rendering quality concern,
but compact text saves 3x cap budget) or cap on
`json.dumps(value)` length BEFORE pretty-printing.

---

## 273. `_shared._args_fingerprint` truncation collapses multi-arg discrimination

**File**: `agents/mcp_adapters/_shared.py:91-92`.

`if len(joined) > 120: joined = joined[:117] + "..."`.

One arg with a 1000-char value dominates `joined`. The
fingerprint then truncates at 117 chars — first arg only
visible, other args completely cut off. The fingerprint
loses discriminative power: two calls with the same first
arg but different second args produce IDENTICAL fingerprints.

The observable key then collides; second call's observation
overwrites first. Agent loses context.

**Fix**: Truncate per-arg-value before joining (e.g. 30 chars
per value), then truncate the full join at 120.

---

## 274. `_shared._args_fingerprint` noise set is hardcoded

**File**: `agents/mcp_adapters/_shared.py:82`.

`noise = {"index_id", "binary_id", "limit", "offset"}`.

Other pagination knobs (`page`, `cursor`, `next_token`,
`page_size`, `from`, `to`) aren't filtered. They contribute
to the fingerprint → consecutive paginated calls produce
DIFFERENT fingerprints → observables don't de-dupe → agent
sees redundant observation entries for the same conceptual
question with different page numbers.

**Fix**: Pagination keys belong to a curated set; or extract
a `_PAGINATION_NOISE_KEYS` constant that tooling owners
contribute to.

---

## 275. `_shared.obs_key_for` collides for no-arg tool calls

**File**: `agents/mcp_adapters/_shared.py:62-68`.

When neither `suffix` nor `args` produce a fingerprint
(no-arg tool like `audit_mcp.list_indexes`), the observable
key is just `"server.tool"`. Two consecutive `list_indexes`
calls write to the same key → second observation overwrites
first. The agent's record of what they previously saw is
lost.

**Fix**: Append a sequence number (e.g. `at_turn` from ctx)
when no other discriminator exists. Better: include `call_id`
suffix as fallback.

---

## 276. `generic._summarize_raw` includes `error=...` but doesn't propagate error state

**File**: `agents/mcp_adapters/generic.py:74-75`.

`if "error" in raw: bits.append(f"error={raw['error']!r}")`.
The summary string includes the error, but the
`AdapterResult.payload_kind` is still `TEXT` — the executor
upstream sees this as a normal-success path. The error
condition is only visible to the agent via the summary line.

`tool_executor.execute` checks `raw.get("status") == "error"`
separately (§202). When status="ok" but `error` is in the
raw response (some MCPs do this), the executor treats it as
success and the agent sees an "ok"-marked tool result with
error text embedded.

**Fix**: When `error` key is present, AdapterResult should
include a discriminator (e.g. `is_error: True` in payload)
that the executor surfaces upstream.

---

## 277. `generic.adapt_generic` 100MB observable cap per call

**File**: `agents/mcp_adapters/generic.py:31, 43`.

`preview = bounded_dump(raw)` caps at `_shared.MAX_OBS_DUMP_CHARS`
(100MB per §271). For a single tool call with a 50MB raw
response, 100MB of indented JSON lands in observables.

Multiple observations accumulate: 5 × 100MB = 500MB in
`case_state_json` (single PG column). The branch row read
pays full bandwidth on every read of the case_state — agent
turn, prompt build, parent_reconciler scan, frontend display.

**Fix**: Lower the cap to a sane value (e.g. 30KB) for the
generic path. Specialized adapters with their own renderers
can override.

---

## 278. `ida_headless._MAX_OBS_PSEUDOCODE` / `_MAX_OBS_DISASM` comment-vs-value drift

**File**: `agents/mcp_adapters/ida_headless.py:53-61`.

Comment narrates `3000/2500 → 50000 chars covers ~600 lines
of pseudocode`. Actual constants are `100_000_000` (100MB
each). 2000x bigger than the "50000" the comment celebrates.
The "bounded slice" rationale no longer applies.

**Fix**: Restore the small cap with explicit override knob,
OR delete the rationale block.

---

## 279. `ida_headless._MAX_OBS_CALLSITES = 25` inconsistent with `_shared.MAX_LIST_PREVIEW = 20`

**File**: `agents/mcp_adapters/ida_headless.py:62`,
`agents/mcp_adapters/_shared.py:39`.

Two list-preview caps with different values for similar
concepts. The IDA adapter previews 25 callsites; the shared
helper previews 20 list items. Operators reading the prompt
see inconsistent truncation behavior across tools.

**Fix**: Use the same constant across all adapters. If a
specific tool needs a different cap, document why.

---

## 280. `ida_headless` adapters don't validate `binary_id` consistency

**File**: `agents/mcp_adapters/ida_headless.py` (all adapters).

No adapter cross-checks the response's `binary_id` field
against `ctx.args["binary_id"]`. If the IDA MCP server has
a bug that returns wrong binary's data (e.g. cache mismatch,
wrong handle resolution), the adapter happily surfaces it.
The agent's branch is wired to one binary but observes data
from another. Silent cross-binary contamination.

**Fix**: Assert `raw.get("binary_id") == ctx.args["binary_id"]`
at adapter entry. Mismatch = error result, log loudly.

---

## 281. `investigation_emit` caps read at module load via `__import__("os")`

**File**: `workflow/states/investigation_emit.py:56-65`.

`_OVERALL_TURN_CAP = int(__import__("os").environ.get(...))`.
Four caps read at module import time. Changing env after
AILA started has NO effect — restart required. The
`__import__("os")` pattern obscures the actual import (os is
already imported in many other files).

Operator who tries to bump `VR_INVESTIGATION_TURN_CAP` from
300 to 500 sees no change; debugging is hard because the
env var IS set, but the constant is frozen.

**Fix**: Read env on each call via a thin getter; cache via
`functools.lru_cache(maxsize=1)` if perf is a concern. OR
at minimum document that these are import-time constants.

---

## 282. `investigation_emit` cap cascade hides multiple breaches

**File**: `workflow/states/investigation_emit.py:295-305`.

`if total_turns >= cap: breach = ...; elif total_messages >= cap: ...; elif age_hours >= cap: ...`.

If turn cap AND message cap are both breached, only turn is
reported. Operator can't tell whether the investigation is
over on a single axis or all three. The exit reason becomes
misleading for post-mortem analysis.

**Fix**: Collect ALL breaches into a list; report the comma-
separated reason. Most informative for forensics.

---

## 283. `investigation_emit` latest_act_row tuple/scalar dance

**File**: `workflow/states/investigation_emit.py:339-344`.

```python
latest_act = (
    latest_act_row
    if not hasattr(latest_act_row, "__getitem__")
    else latest_act_row[0]
)
```

SQLAlchemy's `_select(func.max(...))` returns either a scalar
or a `Row` depending on `.first()` semantics + driver version.
The `hasattr(__getitem__)` check is fragile — a future driver
upgrade could break it silently (scalar with `__getitem__`
is rare but datetime has indexing for `(year, month, day)`
via tuple unpacking).

**Fix**: Use `.scalar()` instead of `.first()` for single-
aggregate queries. Eliminates the ambiguity.

---

## 284. `investigation_emit` cap commit `uow.commit()` (consistency)

**File**: `workflow/states/investigation_emit.py:389`.

Same `uow.commit()` vs `uow.session.commit()` inconsistency
as §251 / §287.

---

## 285. `investigation_emit` ARQ purge runs AFTER commit

**File**: `workflow/states/investigation_emit.py:391-407`.

Pattern: commit cap-exceeded state → purge ARQ jobs. If purge
fails (Redis down, connection error), the transaction already
committed (branches abandoned, status COMPLETED) but ARQ
jobs are still alive.

Those alive ARQ jobs eventually run `run_vr_investigate`,
find the investigation COMPLETED (status_locked check at
investigation_setup line 132 fires), exit clean. So no
actual damage — but wasted worker time + log noise per
missed-purge job.

Worse: if ARQ purge raises an exception caught by the
narrow except, the operator never knows the cap exceeded.

**Fix**: Purge ARQ jobs BEFORE the commit; or use a
two-phase commit with the ARQ as compensating action.

---

## 286. `investigation_loop` constructs fresh engine + executor + researcher per task

**File**: `workflow/states/investigation_loop.py:74-86`.

Per task invocation (per state run), three heavy objects
constructed:
  - `CyberReasoningEngine(services.llm_client)`
  - `HonestVulnResearcher(...)`
  - `ToolExecutor(IDABridgeTool(), AuditMcpBridgeTool(), AndroidMcpBridgeTool())`

`ToolExecutor._inv_index_id_cache` (§252) is fresh — cache
miss on every task boundary. Re-resolve index_id every task,
wasting one DB roundtrip per task.

The bridges each construct their own httpx clients (per §216).
Per-task pool teardown + construction.

**Fix**: Construct once at worker boot; pass through
`services` (which is the natural DI seam).

---

## 287. `investigation_loop` polls inv.status with FRESH UoW every turn

**File**: `workflow/states/investigation_loop.py:49-56, 94`.

`_investigation_status(investigation_id)` opens a UoW just
to read `inv.status`. Called every iteration of the loop
(once per turn). For a 70-turn investigation, 70 UoW
transactions opened just for status polling.

Each UoW is a fresh DB connection acquisition (or pool
checkout) + commit cycle. ~5ms per poll × 70 turns = 350ms
pure overhead.

**Fix**: Pass status through input/output state OR observe
inv.status via an in-loop refresh of an existing cached
object via a service.

---

## 288. `investigation_loop` doesn't poll branch.status

**File**: `workflow/states/investigation_loop.py:94-101`.

Already in §97 / §289. The poll checks ONLY
`InvestigationStatus`. An operator who pauses a specific
branch (not the whole investigation) — the loop doesn't
see it. Branch keeps running until investigation-level
pause / cap.

---

## 289. `investigation_loop` `or []` swallows literal `False`

**File**: `workflow/states/investigation_loop.py:79-80`.

`cve_intel=input.get("cve_intel") or []`. If
`input["cve_intel"]` is literal `False` (corrupted state),
`False or []` returns `[]`. Silent acceptance of bad input.

**Fix**: `isinstance(input.get("cve_intel"), list)`
validation. Refuse non-list values loudly.

---

## 290. `investigation_setup._STATUS_LOCKED` exits with `cve_intel=[]` lose context

**File**: `workflow/states/investigation_setup.py:140-155`.

When `inv.status in _STATUS_LOCKED` (paused, completed,
failed), the function returns early with `cve_intel=[]` (line
149). But the resume path may have been MID-WAY through a
CVE-intensive investigation. On resume, the `cve_intel` will
be recomputed from `inv.initial_question` (line 312) — fine.

But: if the investigation was paused, the resume path goes
through setup → loop → ... and the cve_intel comes back. If
the investigation was FAILED but the operator hits /reopen,
the new task starts setup which re-resolves CVE intel. OK.

Edge case: if CVE intel was relevant context for the
investigation but is removed from the question after
/reopen (operator edit), the new task loses it silently.

---

## 291. `investigation_setup` orphan abandon + new primary in SAME UoW — no partial rollback

**File**: `workflow/states/investigation_setup.py:225-282`.

Pattern: INSERT new primary branch → flush → SELECT orphans
→ UPDATE orphans status → commit at line 290.

If the orphans UPDATE fails (unlikely but possible — FK
constraint, DB transient), the primary branch insert ALSO
rolls back. Investigation has NO primary branch → next
poll sees no live branch → tries to create one → cycle.

OR: if the COMMIT at 290 partial-fails (rare but PG
supports partial-commit semantics under savepoints), the
inconsistent state persists.

**Fix**: Acceptable as-is (atomic UoW commit). Document the
all-or-nothing contract loudly.

---

## 292. `investigation_setup._spawn_persona_siblings_and_enqueue` not transactional

**File**: `workflow/states/investigation_setup.py:295-300`.

The function spawns 5 sibling branches + enqueues 5 ARQ
tasks (per `_DELIBERATION_SIBLINGS`). The spawn-each is a
loop; partial completion is possible if any branch INSERT
or ARQ submit raises mid-loop.

Result: 3 of 6 personas alive, 2 unspawned. The investigation
runs with a deficient panel. No reaper detects this and
spawns the missing ones.

**Fix**: Two-phase: phase 1 INSERT all 5 branches in one UoW
(transactional). Phase 2 enqueue all 5 ARQ tasks (best-effort
with per-task retry). If a task enqueue fails, the branch
exists and a reaper can submit it later.

---

## 293. `investigation_setup` bare except on CVE + pattern lookup

**File**: `workflow/states/investigation_setup.py:318, 357`.

Two `except Exception as exc: # noqa: BLE001` blocks. Both
log at WARNING and continue. Comment justifies "never block
setup on intel/pattern failure".

But: if the pattern store is BROKEN GLOBALLY (DB schema
drift, KnowledgeService down), every new investigation runs
without patterns and the operator sees no alert. The fleet
silently degrades to no-pattern reasoning.

**Fix**: Per-call swallow is fine; add a counter / sentinel
that detects "5 consecutive pattern lookups failed" → fires
an operations alert. Same for CVE intel.

---

## 294. `investigation_setup` SELECT target row OUTSIDE the UoW it uses

**File**: `workflow/states/investigation_setup.py:339-356`.

Pattern: open UoW, SELECT target, exit UoW. Then ACCESS
`target.workspace_id`, `target.kind`, `target.primary_language`
OUTSIDE the UoW.

`target` is a SQLAlchemy model instance — detached after
UoW close. Column attributes are still accessible (they're
stored on the instance), but any relationship traversal
would fail (`DetachedInstanceError`). Fragile pattern: a
future refactor adding `target.workspace` (relationship)
would silently break.

**Fix**: Either keep all access INSIDE the UoW, OR `.refresh()`
+ explicit fetch of all needed columns before exit.

---

## 295. `investigation_setup` `_AUTO_DELIBERATION` flag read at module load

**File**: `workflow/states/investigation_setup.py:31`.

`_AUTO_DELIBERATION = os.environ.get(...) == "1"`. Module-
load constant. Operator who toggles this mid-session sees
no effect.

---

## 296. `investigation_setup` unconditional `inv.status = RUNNING`

**File**: `workflow/states/investigation_setup.py:285`.

After all the early-exits for `_STATUS_LOCKED`, the function
unconditionally flips `inv.status = RUNNING`. But what if
the investigation is in a non-locked but non-RUNNING state
(e.g. CREATED)? The flip is correct — CREATED → RUNNING is
the intended transition.

But the test `if inv.status in _STATUS_LOCKED` at line 132
covers PAUSED / COMPLETED / FAILED. Anything else (CREATED,
future ABANDONED if added) silently transitions to RUNNING.

**Fix**: Whitelist: only allow RUNNING flip when current
status is one of `{CREATED, RUNNING}` (idempotent).

---

## 297. `investigation_setup` `del services` discards DI seam

**File**: `workflow/states/investigation_setup.py:108`.

`del services`. The state's `services` arg is the natural
dependency-injection seam — it carries the LLM client,
task queue factory, knowledge service, etc.

By discarding services, the state then constructs its own
`UnitOfWork`, `PatternStore`, `KnowledgeService` etc. inline
(line 333-347). Tests can't inject fakes.

Same pattern in `investigation_emit` (§283), `investigation_loop`.

**Fix**: Use services. Inject `pattern_store`, `cve_resolver`,
`task_queue_factory` through the services container.

---

## 298. Summary part 16

27 more bugs (#271-297). Total now 297+ items.

File density updates after part 16:

|file|count|
|---|---|
|`agents/outcome_dispatcher.py`|20|
|`agents/tool_executor.py`|18|
|`agents/vuln_researcher.py`|13|
|`workflow/states/investigation_emit.py`|**12**|
|`workflow/states/investigation_setup.py`|**8**|
|`agents/branch_manager.py`|10|
|`api_router.py` (vr)|10|
|`parent_reconciler.py`|9|
|`services/target_analysis.py`|7|
|`agents/mcp_adapters/_shared.py`|5|
|`enrichment/function_ranker.py`|5|
|`workflow/states/investigation_loop.py`|4|
|`services/outcome_review.py`|4|
|`enrichment/profile_builder.py`|4|
|`tools/ida_bridge.py`|4|
|`masvs/verdict_mapper.py`|4|
|`agents/mcp_adapters/ida_headless.py`|3|
|`agents/mcp_adapters/audit_mcp.py`|3|
|`agents/mcp_adapters/generic.py`|2|
|`agents/mcp_adapters/registry.py`|1|
|`tools/audit_mcp_bridge.py`|3|
|`tools/android_mcp_bridge.py`|2|
|`masvs/seed.py`|3|
|`services/pattern_store.py`|3|

No code touched for §271-297.

---

# Part 17 — workflow states (setup/poc) / parent_reconciler synthesis / branch+investigation reapers / stage_tracker / synthesis_agent

## 298. `state_setup._upload_and_wait` 60s budget vs realistic upload+analysis times

**File**: `workflow/states/setup.py:50, 154-170`.

`_POLL_BUDGET_S = 60.0`. After 60 seconds, the loop exits with
WARNING but proceeds. Downstream code assumes the binary is
ready and calls IDA tools → fails with "not ready" errors.
The agent then sees confusing errors. Silent degradation.

For large binaries (firefox, chromium binaries pulled fresh)
IDA's auto-analysis runs ~5-10 min. The 60s budget fires
long before.

**Fix**: Increase to `_POLL_BUDGET_S = 600` (10 min) OR
raise an explicit error rather than proceeding.

---

## 299. `state_setup._upload_and_wait` wait time counts polls only

**File**: `workflow/states/setup.py:154-165`.

`waited += _POLL_INTERVAL_S` (2s). But the `await ida_bridge.forward(...)`
may take 10s itself. Wall-clock can be 5-10x the recorded
`waited`. The 60s budget translates to 5-10 minutes of real
time before exit. The WARNING message claims "60s" but the
actual wait was much longer.

**Fix**: Track wall-clock via `time.monotonic()` instead of
counting poll intervals.

---

## 300. `state_setup._upload_and_wait` original-upload state-check fragility

**File**: `workflow/states/setup.py:153-156`.

`last: dict[str, Any] = upload` then `if upload.get("analysis_ready")`
(NOT `last`). The check uses the ORIGINAL upload response,
not the polled one. Subsequent polls update `last` and the
inner check at line 162 uses `last` — so the first iteration
returns based on `upload` and later iterations on `last`.

Confusing variable scoping. A future refactor that doesn't
understand the dual-variable pattern would break.

**Fix**: One variable. Check after the first poll uniformly.

---

## 301. `poc_development._llm_poc` finds JSON via brace counting

**File**: `workflow/states/poc_development.py:102-105`.

`start = raw.find("{"); end = raw.rfind("}")`. If the LLM
wraps response in markdown code fences with curly braces in
the code (Python dict literal in the PoC, C struct
definitions), the first `{` may be inside the code block.
`json.loads(raw[start:end+1])` then fails because the slice
is invalid JSON.

**Fix**: Use `chat_structured` with a schema, OR detect
code-fence boundaries explicitly via regex.

---

## 302. `poc_development._llm_poc` doesn't use `chat_structured`

**File**: `workflow/states/poc_development.py:91-96`.

Calls `services.llm_client.chat(...)` with no schema. The
LLM can return anything; the code parses by find-first-brace.
`chat_structured` with a Pydantic schema would enforce
structure + catch malformed returns at the LLM layer.

Same issue as §155 (synthesis_agent).

---

## 303. `poc_development._llm_poc` `response.disabled` raises generic RuntimeError

**File**: `workflow/states/poc_development.py:99-100`.

`if response.disabled: raise RuntimeError("LLM disabled by operator")`.

The outer try/except at line 174 catches RuntimeError and
treats it as "llm_error", appending to history. The operator's
intentional pause becomes indistinguishable from a network
outage — the loop keeps retrying.

**Fix**: Define `LLMDisabledByOperatorError` subclass.
Caller breaks on disabled, continues on transient.

---

## 304. `poc_development` retry loop no upper $$$ cap

**File**: `workflow/states/poc_development.py:168-228`.

`max_attempts = max(1, int(services.config.poc_max_attempts))`.
Operator-configurable. Setting `poc_max_attempts=1000`
launches a $500+ PoC development session — no cost gate.

**Fix**: Cap at `min(operator_cap, 25)` OR enforce per-call
cost budget via the LLM client.

---

## 305. `poc_development` retry no exponential backoff

**File**: `workflow/states/poc_development.py:169-228`.

Failed compile or no-crash immediately retries the next
attempt. For an LLM that takes 60s per call, 10 attempts
means 600s of compute spend with no backoff window. If the
failure is "MCP transient" (e.g. SSH dropped), 10 immediate
retries pile up on the same dead connection.

**Fix**: Exponential backoff with jitter between attempts.

---

## 306. `poc_development` `run_result.get("crash_detected")` no type coerce

**File**: `workflow/states/poc_development.py:211`.

`if run_result.get("crash_detected"):`. If `crash_detected` is
the string `"false"` (LLM accidentally string-serialised a
bool, or upstream MCP returned text), `if "false"` is truthy
in Python → false crash detected → break out of attempt loop.

**Fix**: `if run_result.get("crash_detected") is True:` or
explicit bool coerce.

---

## 307. `poc_development` task_type hardcoded

**File**: `workflow/states/poc_development.py:92`.

`task_type="vulnerability_research"`. The platform may
route this to a specific (slow/expensive) model. Multiple
PoC iterations all pay max cost. No cheaper alternative for
early iterations.

**Fix**: First iteration uses cheaper model
(`vulnerability_research.poc_draft`), later iterations
(after compile failures) escalate to more capable model.

---

## 308. `poc_development._untested_payload` language fallback wrong

**File**: `workflow/states/poc_development.py:230-240`.

If no crash but attempt loop exhausted, returns "no crash
within attempt budget" with `last_code` + `last_language`.
But `last_language` is the LAST iteration's language, not
the BEST. If iteration 1 was python (compile succeeded but
no crash), iteration 5 was C (compile succeeded but no
crash), the payload reports `language="c"` and `code=<C
code>`. Operator review sees C code but the python attempt
may have been closer to working.

**Fix**: Track best-attempt by some heuristic (closest to
a target crash) and surface that.

---

## 309. `poc_development._llm_poc` no token budget

**File**: `workflow/states/poc_development.py:91-98`.

No `max_output_tokens` on the chat call. LLM can produce
arbitrarily long output. A misbehaving LLM that emits 100K
tokens of explanation costs ~$3 just for one attempt.

**Fix**: `max_output_tokens=2048` cap with explicit budget.

---

## 310. `parent_reconciler._synthesize_no_finding_outcomes` raw SQL INSERT

**File**: `masvs/parent_reconciler.py:832-860`.

Bypasses ORM via `text("INSERT INTO vr_investigation_outcomes ...")`.
Schema hardcoded as SQL string. If table schema changes
(column added/removed/renamed), this INSERT silently fails
with a constraint violation — caught by the bare except at
line 873 → logged as WARNING → loop continues without
synthesizing.

Comment justifies "13 columns; constructing via SQL avoids
importing the model". But the model import is cheap at
runtime (caches in sys.modules). The SQL is fragile for an
optimization that doesn't exist.

**Fix**: Use the ORM model. Standard pattern across codebase.

---

## 311. `parent_reconciler._synthesize_no_finding_outcomes` `accepted_by_operator=false` field lies

**File**: `masvs/parent_reconciler.py:838`.

The synthesized outcome carries `accepted_by_operator=false`.
But this outcome was AUTO-approved by the reconciler — no
operator was involved. The field name (`accepted_by_operator`)
lies about the state.

Operator dashboards filtering by `accepted_by_operator=true`
to find human-vetted outcomes would not see this auto-approval.
Dashboards filtering by `state='approved'` AND
`accepted_by_operator=false` would see auto-approvals and
true human-rejected approvals mixed together.

**Fix**: Add explicit `auto_approved` boolean field or
repurpose `accepted_by_operator` with sentinel value
("auto_reconciler" string instead of bool).

---

## 312. `parent_reconciler._synthesize_no_finding_outcomes` "just flip" path no FK check

**File**: `masvs/parent_reconciler.py:759-781`.

If `existing_outcome_row` is non-null (some other path created
an outcome but the inv stayed RUNNING), the "just flip" branch
UPDATEs the inv to COMPLETED. But it does NOT verify that the
`existing_outcome` UUID actually points to a valid outcome row.

If the existing_outcome UUID is stale (the outcome was deleted
manually, or a migration cleared it), the inv is flipped to
COMPLETED with a dangling `primary_outcome_id`. Frontend
tries to load it → 404 → operator confusion.

**Fix**: SELECT to confirm `existing_outcome` row exists
before the flip. If gone, fall through to synthesize.

---

## 313. `parent_reconciler._synthesize_no_finding_outcomes` total_turns sum inflates

**File**: `masvs/parent_reconciler.py:805`.

`total_turns = sum(r[2] for r in unwrapped)`. Sums turn
counts across ALL branches. Per §141 (branch_manager.merge),
a merged branch's `turn_count` is `max(parent, child)`, NOT
the sum. So summing across branches:

  - 3 branches with turn_count 10 each → sum = 30
  - But if 2 of them are forks/merges from the same root,
    the actual unique work is closer to 15.

The "consumed X turns" payload narrative is misleadingly
inflated.

**Fix**: Either compute unique-work-turns via a graph
traversal, OR change wording to "branch-turn-units" (clearer
about double-counting).

---

## 314. `parent_reconciler._synthesize` ON CONFLICT missing

**File**: `masvs/parent_reconciler.py:832-848`.

The INSERT has no `ON CONFLICT DO NOTHING`. If a concurrent
reconciler tick races on the same orphan investigation
(unlikely but possible with cron jitter), the second tick's
INSERT raises a unique constraint violation. Caught by the
bare except → orphan stays orphan.

**Fix**: Append `ON CONFLICT (id) DO NOTHING` OR
`ON CONFLICT (investigation_id, branch_id, outcome_kind)
WHERE state='approved' DO NOTHING`.

---

## 315. `parent_reconciler._synthesize` bare except on failure → orphan stays orphan

**File**: `masvs/parent_reconciler.py:873-876`.

On any error during synthesis, log + continue. The orphan
investigation stays at RUNNING with no outcome. Next sweep
tick re-encounters it. If the underlying cause is persistent
(corrupted JSON, deleted FK), the orphan stays orphan
forever — operator never sees it close.

**Fix**: Retry counter on the orphan; after 3 failed
synthesis attempts, force-flip to FAILED with explicit
error message.

---

## 316. `branch_reaper.sweep_orphan_active_branches` updated_at staleness reaps mid-LLM

**File**: `services/branch_reaper.py:124`.

`BR.updated_at < branch_touch_cutoff` (2 min). If a tool
call (semantic_search with rerank, large taint analysis)
takes 5+ min, `updated_at` is stale for that duration.
After 2 min idle the reaper sees the branch as orphaned and
abandons it.

But: the branch is alive — there's an in-flight LLM call.
The abandon then interrupts work that was about to commit.

The investigation_reaper has the same 15-min idle grace per
`VR_WALL_CLOCK_IDLE_GRACE_S`; the branch_reaper has a
stricter 2-min cap. Inconsistency.

**Fix**: Unify the idle grace window across both reapers.
`VR_BRANCH_TOUCH_GRACE_S` env var with the same 15-min
default as wall_clock.

---

## 317. `branch_reaper.sweep` case() string concat uses `+` (PG vs SQLAlchemy)

**File**: `services/branch_reaper.py:96-102`.

```python
new_reason = case(
    (or_(...), "investigation_terminal:" + INV.status),
    else_=BR.closed_reason + "; investigation_terminal:" + INV.status,
)
```

`+` on SQLAlchemy String columns generates SQL `||` (concat).
OK in PG. But: if `BR.closed_reason` is NULL, `NULL ||
'...'` evaluates to NULL in PG. The else_ branch then
writes NULL closed_reason. The next reaper invocation
treats this row's closed_reason as "empty" again — but
since the row is now ABANDONED, the reap-WHERE excludes it.

Minor: a NULL closed_reason on an abandoned row is just
ugly UI text, not corruption.

**Fix**: `COALESCE(BR.closed_reason, '') || '; ...'` to
avoid NULL propagation.

---

## 318. `investigation_reaper.sweep` UPDATE without `.returning()`

**File**: `services/investigation_reaper.py:183-206`.

Two `update().values()` (branches + inv) without
`.returning(...)`. Already per §57 / D-300. The
`completed_ids.append(inv_id)` at line 207 runs regardless
of whether the UPDATE actually modified a row.

If the inv row was concurrently flipped from RUNNING to
something else (operator pause, another reaper tick won
the race), the inv UPDATE affects 0 rows due to the WHERE
guard at line 199. But `completed_ids` still includes the
id — ARQ purge runs on a row we didn't actually transition.

**Fix**: `.returning(INV.id)` + only append IDs that the
UPDATE confirmed.

---

## 319. `investigation_reaper.sweep` outer `except ImportError: pass`

**File**: `services/investigation_reaper.py:235`.

The `from .arq_purge import ...` is inside try; on
ImportError the entire purge step is silently skipped.
If the arq_purge module is missing or has a circular
import, the function still returns `completed_ids` count
— operator has no idea jobs are NOT being purged. Silent
degradation.

**Fix**: Import at module top. If circular import is the
concern, fix the circular dependency.

---

## 320. `stage_tracker.__aenter__` SELECT-then-WRITE race

**File**: `services/stage_tracker.py:253-301`.

Pattern: `load_target_stages(...)` (SELECT) → check state
→ `save_target_stages(...)` (WRITE RUNNING). No FOR UPDATE.

Two concurrent workers both entering the same stage:
  - Worker A: SELECT, sees PENDING.
  - Worker B: SELECT, sees PENDING.
  - Worker A: WRITE RUNNING.
  - Worker B: WRITE RUNNING (over-writes A's started_at).
Both proceed. Both run the stage in parallel. Both __aexit__
commit DONE. Whichever commits LAST wins on record_output.

The `StageInFlightError` guard at line 262-279 only catches
the race where B's SELECT happens AFTER A's WRITE — the
narrow window between A's SELECT and A's WRITE is
unprotected.

**Fix**: SELECT FOR UPDATE on the target row in the
context-enter, releasing only after the RUNNING WRITE commits.

---

## 321. `stage_tracker.__aexit__` SELECT-then-WRITE race vs reaper

**File**: `services/stage_tracker.py:303-349`.

Same SELECT-then-WRITE pattern in __aexit__. If the reaper
concurrently flipped the stage to FAILED:timeout (per `reap_stuck_stages`),
the __aexit__ WRITE overwrites the reaper's FAILED with our
DONE. The reaper's effect is silently overridden.

Visible symptom: stage appears DONE but its work was
aborted at the reaper's timeout. Operator sees "done" but
downstream stages fail.

**Fix**: In __aexit__, refuse to write DONE if current
state is FAILED with an `error` containing "reaper:" prefix.

---

## 322. `stage_tracker.__aexit__` swallows commit failure

**File**: `services/stage_tracker.py:337-345`.

`except Exception as save_exc: # noqa: BLE001 ... log + don't re-raise`.

If the commit fails, in-memory `stages` shows DONE/FAILED
but DB still shows RUNNING. Next worker enters and sees
stuck RUNNING (within timeout window) → StageInFlightError
→ blocks until timeout window expires (30 min default).

The comment justifies "don't mask the original work
exception". But the work was successful — the commit failed.
The state inconsistency is hidden by the swallow.

**Fix**: If exc is None (work succeeded), re-raise the
save_exc — the work needs to be retried because its state
wasn't persisted.

---

## 323. `stage_tracker.reap_stuck_stages` SELECT-then-WRITE race

**File**: `services/stage_tracker.py:371-434`.

Same SELECT-then-WRITE pattern. Reaper SELECTs RUNNING
rows → iterates → WRITEs FAILED. Between SELECT and WRITE,
another worker may legitimately complete the stage (__aexit__
DONE). The reaper's WRITE then overwrites the legitimate
DONE with FAILED:timeout. Work is lost.

**Fix**: WHERE clause on the WRITE to confirm state is
still RUNNING with same started_at as the SELECT saw.

---

## 324. `stage_tracker.reap_stuck_stages` analysis_state hardcoded string

**File**: `services/stage_tracker.py:383`.

`VRTargetRecord.analysis_state == "ingesting"`. Hardcoded
string. If enum value renames, the reaper silently misses
all rows.

**Fix**: `AnalysisState.INGESTING.value` reference.

---

## 325. `stage_tracker.reap_stuck_stages` deferred commit blast radius

**File**: `services/stage_tracker.py:415-433`.

Commit deferred until all rows processed. If row #50 of 100
raises during iteration (corrupted JSON, validation error),
the loop crashes via the bare except elsewhere? No — the
except is only on parse_stages. A raise from `roll_up_overall_state`
or `serialize_stages` would crash the loop AND lose all
staged mutations (uow.session.add() calls without commit).

**Fix**: Commit per row OR wrap the whole loop in try/except
with a rollback path.

---

## 326. `synthesis_agent._synthesis_confidence` EXACT silently downgraded to STRONG

**File**: `agents/synthesis_agent.py:205-212`.

`conf_rank = {"strong": 1, "exact": 0, "medium": 2, "caveated": 3, "weak": 3, "unknown": 4}`.
`rank_to_conf = {0: OutcomeConfidence.STRONG, 1: STRONG, 2: MEDIUM, 3: CAVEATED, 4: UNKNOWN}`.

EXACT (rank 0) reverse-maps to STRONG, NOT EXACT. The
synthesized confidence silently downgrades EXACT to STRONG.

There's no `OutcomeConfidence.EXACT` in `rank_to_conf` —
looks like the reverse map is missing an entry.

**Fix**: `rank_to_conf[0] = OutcomeConfidence.EXACT`.

---

## 327. `synthesis_agent._synthesis_confidence` disagreement penalty is one-notch always

**File**: `agents/synthesis_agent.py:215-218`.

`if len(kinds) > 1: median = min(median + 1, 4)`. Downgrades
by ONE notch on ANY kind mismatch.

But: critic-says-DIRECT_FINDING + researcher-says-DIRECT_FINDING +
implementer-says-PATCH_PRESENT is real disagreement on whether
a bug exists. Two-DIRECT_FINDING + one-AUDIT_MEMO (no_finding)
is FUNDAMENTAL disagreement on whether anything was found.

Same single-notch penalty for both. Doesn't differentiate
severity of disagreement.

**Fix**: Compute a disagreement score (entropy of the kind
distribution); penalty proportional to score.

---

## 328. `synthesis_agent.run` per-persona affected_components copies canonical's list

**File**: `agents/synthesis_agent.py:109-110`.

```python
panel.append({...
    "affected_components": canonical_payload.get("affected_components") or [],
    "variant_hunt_orders": canonical_payload.get("variant_hunt_orders") or [],
})
```

For EVERY persona, copies the canonical payload's lists.
The synthesis prompt sees identical lists per persona.
Per-persona attribution is lost — the synthesiser can't
tell which persona contributed which component.

Already adjacent to §174 (per-persona attribution loss).

**Fix**: Read per-persona lists from the contribution
itself (`c.get("affected_components")`), not from canonical.

---

## 329. `synthesis_agent._render_panel` synthesis instruction hardcoded inline

**File**: `agents/synthesis_agent.py:246-262`.

The synthesis instruction (5-point rubric) is hardcoded as a
Python string at the bottom of `_render_panel`. Updating
the rubric requires a code change.

Compare: `prompts/` directory has `system_audit.md`,
`persona_*.md`, etc. The synthesis prompt is the only one
not in a file.

**Fix**: Move to `prompts/synthesis_instruction.md` so
operators can edit without deploying.

---

## 330. `synthesis_agent.run` two UoWs around LLM call → state can shift

**File**: `agents/synthesis_agent.py:61, 116, 140`.

UoW 1 (line 61-113) reads canonical + panel.
LLM call (line 117-135) — operator could pause/cancel
during the call.
UoW 2 (line 140-186) writes panel_summary + flips status.

Already cataloged §156. Worth re-emphasizing: UoW 2 does
NOT re-check `inv.status == RUNNING`. If the operator
paused mid-synthesis, the second UoW silently overrides
the pause and writes COMPLETED.

**Fix**: SELECT inv at top of UoW 2 with FOR UPDATE; if
status != RUNNING, abort synthesis with "operator interrupt".

---

## 331. Summary part 17

34 more bugs (#298-330). Total now 330+ items.

File density updates after part 17:

|file|count|
|---|---|
|`agents/outcome_dispatcher.py`|20|
|`agents/tool_executor.py`|18|
|`agents/vuln_researcher.py`|13|
|`workflow/states/investigation_emit.py`|12|
|`workflow/states/poc_development.py`|**9**|
|`workflow/states/investigation_setup.py`|8|
|`agents/branch_manager.py`|10|
|`api_router.py` (vr)|10|
|`parent_reconciler.py`|**15**|
|`agents/synthesis_agent.py`|**10**|
|`services/target_analysis.py`|7|
|`services/stage_tracker.py`|**11**|
|`services/investigation_reaper.py`|**5**|
|`services/branch_reaper.py`|**2**|
|`services/outcome_review.py`|4|
|`enrichment/function_ranker.py`|5|
|`agents/mcp_adapters/_shared.py`|5|
|`workflow/states/investigation_loop.py`|4|
|`enrichment/profile_builder.py`|4|
|`tools/ida_bridge.py`|4|
|`masvs/verdict_mapper.py`|4|
|`workflow/states/setup.py`|**3**|
|`agents/mcp_adapters/ida_headless.py`|3|
|`agents/mcp_adapters/audit_mcp.py`|3|
|`agents/mcp_adapters/generic.py`|2|
|`agents/mcp_adapters/registry.py`|1|
|`tools/audit_mcp_bridge.py`|3|
|`tools/android_mcp_bridge.py`|2|
|`masvs/seed.py`|3|
|`services/pattern_store.py`|3|

No code touched for §298-330.

---

# Part 18 — auto_steering / claim_verifier / intent_classifier / persona_router

## 331. `auto_steering._already_posted` LIMIT 40 dedup window

**File**: `agents/auto_steering.py:432-438`.

`.limit(40)`. Only scans the most recent 40 auto-steering
messages. For investigations with hundreds of auto-steerings
(plausible at 70-turn × 6-branch fan-out), older "already
posted" entries past the LIMIT are invisible to the dedup
check.

Result: same condition can re-post repeatedly because the
prior copy isn't in the recent 40.

**Fix**: Either drop the LIMIT (let PG scan) OR add an
indexed column `auto_steering_key` and query by exact key
match, not by scanning rows + parsing JSON.

---

## 332. `auto_steering._already_posted` LIMIT 40 hardcoded

**File**: `agents/auto_steering.py:438`.

`.limit(40)` is a magic number — no env override. Operator
who wants to bump the dedup window has no knob.

---

## 333. `auto_steering._already_posted` ACK observable shape inconsistent

**File**: `agents/auto_steering.py:461-464`.

ACK observable parsed as string OR list:

```python
if isinstance(acked_raw, str):
    all_acks.update(x.strip() for x in acked_raw.split(",") if x.strip())
elif isinstance(acked_raw, list):
    all_acks.update(str(x).strip() for x in acked_raw if x)
```

The agent writes either string or list depending on which
code path produces the ACK. Inconsistent shape across the
codebase. Some siblings store as string, some as list.
Reading one branch's case_state might miss ACKs that another
branch wrote in the other shape.

**Fix**: Normalize ACK to one canonical shape (list of
strings) at write time. Add a sanitizer at read time too.

---

## 334. `auto_steering._already_posted` scans ALL branches every call

**File**: `agents/auto_steering.py:451-455`.

For each dedup check, SELECT all branches and parse each
`case_state_json`. With 6 branches × 50KB case_state each =
300KB of JSON parsed per check. Multiplied by every tool
result writing → significant DB bandwidth + CPU spent in
parser.

**Fix**: Store ACKs in a separate normalized table
`vr_auto_steering_acks(investigation_id, message_id)` with
an index. O(log N) lookup instead of O(branches × case_state_size).

---

## 335. `auto_steering._post` primary-branch broadcast assumption

**File**: `agents/auto_steering.py:484-486, 490-496`.

Comment: "branch_id is the PRIMARY branch so the message is
visible to every sibling (the message loader treats
primary-addressed as broadcast)".

This depends on the PROMPT BUILDER scoping by
investigation_id OR special-casing primary-branch messages
as broadcast. Per §249 (outcome_review), the prompt builder
may scope by branch_id only → siblings never see the
auto-steering.

If §249 is real, this auto-steering broadcast is broken too.
The "primary branch sees it; siblings don't" failure mode
would explain why operator-observed cases of "agent keeps
making the same mistake" continue even after auto-steering
posts.

**Action**: Confirm prompt builder behavior. If it scopes
by branch_id, this entire auto-steering mechanism is
partially-broken (only primary persona reacts).

---

## 336. `auto_steering._post` primary branch SELECT may pick terminated row

**File**: `agents/auto_steering.py:490-495`.

`select(branch.id).where(parent_branch_id IS NULL).limit(1)`.
No status filter, no ORDER BY. With multiple terminated
primary branches + one active (post self-heal per §253), PG
may return any of them.

If a terminated primary is picked, the auto-steering message
is attached to a dead branch → frontend won't render it
for the live branch.

**Fix**: Filter `status NOT IN _DEAD_BRANCH_STATUSES`. Pick
the OLDEST live one with explicit `ORDER BY created_at ASC`.

---

## 337. `auto_steering.maybe_post_auto_steering` bare except hides systemic failure

**File**: `agents/auto_steering.py:611-616`.

`except Exception as exc: # noqa: BLE001 — auto-steering must never fail loud`.

If the dedup logic crashes (DB transient), the rule
derivation crashes, OR the post fails, the exception is
swallowed. Auto-steering returns None.

If this fails systemically (e.g. KnowledgeService is broken,
DB schema drift), every auto-steering call returns None.
Operator sees no auto-steering for weeks without realising
the mechanism is broken.

**Fix**: Counter / sentinel that detects "5 consecutive
auto-steering failures" → log at ERROR + opt-in operations
alert.

---

## 338. `auto_steering` fire-then-check race

**File**: `agents/auto_steering.py:555-609`.

Pattern: detector fires → `_already_posted` read-only check
→ correction derivation → `_post` write.

Between the check (line 556) and the write (line 564), a
concurrent call from another branch's tool-result handler
can pass the same check and race to write. Two duplicate
auto-steerings post for the same `auto_steering_key`.

**Fix**: Unique constraint on `(investigation_id, auto_steering_key)`
with `ON CONFLICT DO NOTHING` on the message INSERT — let
the DB enforce dedup atomically.

---

## 339. `auto_steering._post` err_class extraction fragile

**File**: `agents/auto_steering.py:602`.

`err_class = raw_err.split(":", 1)[0][:80] if raw_err else "unknown"`.

First 80 chars before `:`. If the bridge's error format
changes (e.g. "BridgeValidationError: ..." renamed to
"BridgeKwargError: ..."), the err_class differs from prior
steerings. The dedup key shifts → previously-acked steerings
don't match → duplicate posts for the same actual condition.

**Fix**: Use a stable structural key (e.g. tool_name + arg
keys provided) instead of error-text parsing.

---

## 340. `claim_verifier._EXTRACTOR_TASK_TYPE` == `_VERDICT_TASK_TYPE`

**File**: `agents/claim_verifier.py:332-333`.

Both extractor and verdict task_types = `"vulnerability_research.synthesizer"`.
Same routing → same model → no diversity.

The verifier is supposed to be ADVERSARIAL to the panel.
But it shares routing with the synthesizer. The verifier and
synthesizer may be the SAME model giving the SAME biased
answer. The "adversarial" nature is illusory.

**Fix**: Separate task types: `verifier_extractor` and
`verifier_verdict`. Route to a different model than
synthesizer.

---

## 341. `claim_verifier._MAX_PROBES = 8` silently drops preconditions

**File**: `agents/claim_verifier.py:334`.

If the extractor proposes 15 preconditions, only the first
8 are probed. The dropped 7 may be load-bearing — verifier
marks "confirmed" because the 8 it checked all passed,
misses the 9th-15th probe that would have falsified.

**Fix**: Either bump _MAX_PROBES (cost / latency concern)
OR pick the 8 BY rank (extractor sorts by load-bearing
importance) rather than sequence order.

---

## 342. `claim_verifier` `finding_text[:8000]` truncation

**File**: `agents/claim_verifier.py:380`.

Panel narrative + answer truncated to 8K chars before
extractor sees it. For investigations with rich panel
narratives (3-4 personas × 4000-char answer each + synthesis
narrative), 8K is the crux fraction. Extractor reasons on
a snippet.

**Fix**: Bump cap, OR extractor sees TWO inputs (answer +
narrative) separately so panel narrative can be capped
independently of the agent's answer.

---

## 343. `claim_verifier` probe loop SEQUENTIAL

**File**: `agents/claim_verifier.py:403-438`.

8 probes × ~30s each = 4 min sequential. Could be
`asyncio.gather` → ~30s parallel (same shape as §225, §230).

---

## 344. `claim_verifier` `$INDEX_ID` substitution requires exact match

**File**: `agents/claim_verifier.py:419-421`.

`if v == "$INDEX_ID": args[k] = index_id`. Only exact string
match. If args has `{"path": "$INDEX_ID/file.c"}` (concat
intended), no substitution → probe fails with "no such
path".

The extractor LLM may produce concatenated values — it's
a natural prompt pattern. Silent failure.

**Fix**: Substring substitution (`v = v.replace("$INDEX_ID", index_id)`)
for string args. Or refuse to interpolate inside strings
at all (extract pure UUID, fail loud).

---

## 345. `claim_verifier._AUTO_PROMOTE_MIN_CONFIDENCE = 0.70` hardcoded

**File**: `agents/claim_verifier.py:76`.

No env override. Operator can't tune the auto-promote floor
without code change.

---

## 346. `claim_verifier._maybe_auto_promote` `is_negative_finding_claim` phrase list

**File**: `agents/claim_verifier.py:64-74`.

Nine phrases. Synonyms NOT in the list:
  - "patch is in place"
  - "vulnerability does not apply"
  - "not exploitable in practice"
  - "the issue is mitigated"
  - "no exploitable condition reaches here"

An agent that wrote one of these as the answer head + then
the verifier confirmed → AUTO-PROMOTED to DIRECT_FINDING.
But the agent's claim was "no bug here". The promote creates
a false-positive finding.

**Fix**: Expand phrase list OR use a small LLM classifier
for negative-claim detection.

---

## 347. `claim_verifier._maybe_auto_promote` outcome MUTATED in-place

**File**: `agents/claim_verifier.py:595-600`.

`row.outcome_kind = OutcomeKind.DIRECT_FINDING.value` (in-place mutation).

The `promoted_from` payload records the prior outcome_kind,
but the row itself is changed. Subsequent dispatches operate
on the new kind without seeing the original.

For audit trail: the operator can read `promoted_from.kind`
to see the original. But: re-running the dispatcher
post-promote doesn't replay the original dispatch logic
for ASSESSMENT_REPORT (it sees DIRECT_FINDING now).

**Fix**: Either keep BOTH rows (one ASSESSMENT_REPORT,
one DIRECT_FINDING with `derived_from` link), OR have a
dedicated `promoted_kind` column to distinguish.

---

## 348. `claim_verifier._maybe_auto_promote` dispatch outside UoW

**File**: `agents/claim_verifier.py:600-605`.

UoW commits the outcome flip → exits UoW → calls
`dispatcher.dispatch(canonical_id)`.

If dispatch fails (per §115 narrow exception filter), the
outcome is now DIRECT_FINDING with `dispatch_status=PENDING`
but no actual dispatch occurred. Per §111, no reaper sweeps
PENDING outcomes → permanent zombie.

**Fix**: Either dispatch INSIDE the UoW (rollback both if
dispatch fails), OR mark the row with a `dispatch_pending_at`
timestamp and have a reaper retry stalled PENDINGs.

---

## 349. `claim_verifier._fetch_audit_mcp_signatures` swallows HTTPError + ValueError

**File**: `agents/claim_verifier.py:137-138`.

`except (httpx.HTTPError, ValueError): return ""`. On failure
returns empty signatures block. The extractor then proposes
probes using its prior knowledge of audit-mcp tool shapes
— which may be wrong / stale.

No log line on failure. Operator can't tell whether
verifier's wrong-arg probes were due to signature fetch
failure OR LLM hallucination.

**Fix**: Log WARNING with exception class. Surface
"signatures_fetch_failed" in the verifier_report payload so
operators can correlate with probe results.

---

## 350. `intent_classifier` BRANCH_COMMAND false-positives on natural language

**File**: `agents/intent_classifier.py:42`.

Regex catches `\b(stop|halt|abort|kill|pause|resume|...)\b`.

Operator writing: "stop drinking after midnight" (natural-
language quote from a finding's POC), "kill the loop"
(metaphorical), "halt mode" (kernel debug), "let's pause and
reconsider X" → classified as BRANCH_COMMAND.

The engine sees a flow-control directive when the operator
meant something else. May silently halt branches.

**Fix**: Anchor at start-of-message + require the verb is
the first significant token. Treat in-prose mentions as
UNCLASSIFIED.

---

## 351. `intent_classifier` order-dependent classification

**File**: `agents/intent_classifier.py:33-65`.

`stop. why?` matches `stop` first → BRANCH_COMMAND. The `?`
at end indicates question. Trailing-`?` heuristic at line
91 is reached only when no rule matches. So compound
intents resolve to the FIRST rule keyword, losing later
context.

**Fix**: Multi-intent return (list of intents) so the engine
sees both BRANCH_COMMAND + QUESTION.

---

## 352. `intent_classifier.classify_intent` no isinstance(str) guard

**File**: `agents/intent_classifier.py:78-84`.

`if not text: return UNCLASSIFIED`. But: text might be a
non-str (parser hiccup returning dict). `pattern.search(stripped)`
would raise TypeError → uncaught → caller crashes.

**Fix**: `if not isinstance(text, str): return UNCLASSIFIED`.

---

## 353. `persona_router._DEFAULT_TASK_TYPE` for null persona

**File**: `agents/persona_router.py:70`.

`_DEFAULT_TASK_TYPE = "vulnerability_research.audit"`. A
branch with persona_voice=None routes to `audit` task type.

The audit task_type is the most expensive deliberation
routing. For test branches, ad-hoc workflows, or
legacy-data branches without persona, this is wasteful.

**Fix**: New `vulnerability_research.lite` task type for
ad-hoc / null-persona branches → cheaper routing.

---

## 354. `persona_router.persona_to_role` silently returns None on unknown persona

**File**: `agents/persona_router.py:73-82`.

Coerces string → PersonaVoice. If string doesn't match enum
(typo, new persona name), returns None silently. Downstream
task_type resolves to default.

No log, no warning. An agent that misspelled "renxo"
silently runs as `vulnerability_research.audit`.

**Fix**: Log WARNING on coerce failure; let caller decide
whether to use default.

---

## 355. `persona_router._ROLE_TASK_TYPE` KeyError on new role

**File**: `agents/persona_router.py:99`.

`_ROLE_TASK_TYPE[role]`. If PersonaRole gains a new value
(e.g. AUDITOR), the dict lookup raises KeyError. Caller
crash.

**Fix**: `.get(role, _DEFAULT_TASK_TYPE)`.

---

## 356. Summary part 18

25 more bugs (#331-355). Total now 355+ items.

File density updates after part 18:

|file|count|
|---|---|
|`agents/outcome_dispatcher.py`|20|
|`agents/tool_executor.py`|18|
|`masvs/parent_reconciler.py`|15|
|`agents/vuln_researcher.py`|13|
|`workflow/states/investigation_emit.py`|12|
|`agents/claim_verifier.py`|**13** (incl. Part 7 §108-110)|
|`services/stage_tracker.py`|11|
|`agents/auto_steering.py`|**10** (incl. Part 5 §82, Part 11 §172)|
|`agents/synthesis_agent.py`|10|
|`agents/branch_manager.py`|10|
|`api_router.py` (vr)|10|
|`workflow/states/poc_development.py`|9|
|`workflow/states/investigation_setup.py`|8|
|`services/target_analysis.py`|7|
|`enrichment/function_ranker.py`|5|
|`agents/mcp_adapters/_shared.py`|5|
|`workflow/states/investigation_loop.py`|4|
|`services/outcome_review.py`|4|
|`enrichment/profile_builder.py`|4|
|`tools/ida_bridge.py`|4|
|`masvs/verdict_mapper.py`|4|
|`workflow/states/setup.py`|3|
|`agents/persona_router.py`|3|
|`agents/intent_classifier.py`|3|

No code touched for §331-355.

---

# Cutover Phases B / C / D — beyond the §29 baseline

§29 cutover (Phase A) is necessary but insufficient to claim
"investigations self-drive and pause/resume work cleanly". The
remaining three structural redesigns are below. Order matters:
B before C before D. Each builds on the previous.

The thread connecting all three: `workflow_state_cursor` was
supposed to be the single source of truth for "where is this
investigation right now". Today it competes with `inv.status`,
`branch.status`, `TaskRecord.status`, and `arq:in-progress:<id>`.
Phase B promotes the cursor back to the SSOT it was designed to
be; Phase C and D depend on that promotion.

---

# Phase B — pause/resume redesign with workflow_state_cursor as SSOT

## B.0 The problem

Three sources of truth for "is this paused":
  - `VRInvestigationRecord.status = PAUSED`
  - `workflow_state_cursor.current_state` ∈ {paused-equivalent, none today}
  - `arq:in-progress:<task_id>` — Redis presence

Four writers, none coordinated:
  - `api_router.pause_investigation` writes `inv.status` + purges ARQ
    (does NOT touch cursor, does NOT touch TaskRecord per §32).
  - `worker.run_vr_investigate` D-86 SKIP path reads `inv.status` per
    turn, exits the loop; does NOT touch cursor explicitly.
  - `investigation_setup` `_STATUS_LOCKED` gate reads `inv.status` on
    task entry, returns clean exit.
  - Reapers + workflow engine `_force_crashed` mutate cursor on their
    own schedule.

The cursor was never designed to be the SSOT in practice — the
engine's `engine.py` defines `__crashed__`, `__paused__` cursor
states but the VR module bypasses both, writing `inv.status =
PAUSED` directly from the API handler instead of writing to the
cursor.

The result is everything we cataloged in §32-§50 of Part 3:
  - Pause leaves TaskRecord alive → resume no-ops (§32)
  - Resume fans out only to primary → 5/6 branches stay paused (§34)
  - Cursor un-touched at pause → trailing tool call commits during
    pause window (§35)
  - Reset doesn't clear cursor → next task resumes prior state (§47)

## B.1 Promote the cursor to SSOT

Single canonical state-of-the-world per investigation is the
`workflow_state_cursor` row keyed by `(investigation_id,
branch_id)`. Every other "status" field becomes a projection.

Cursor states for VR investigations:
  - `__created__` — row exists, no task ever submitted
  - `<state_name>` — engine is in named state (e.g. `investigation_loop`)
  - `__waiting__` — between states, queued ARQ task pending
  - `__paused__` — operator-initiated halt; no tasks accept; no auto-continue
  - `__crashed__` — engine forced this branch crashed (existing)
  - `__failed__` / `__cancelled__` — terminal failure paths
  - `__completed__` — terminal success

`inv.status` becomes a DERIVED column updated by the engine when
the cursor transitions, NOT a writable field for module code.
The frontend reads `inv.status` for display, but the SSOT is the
cursor.

## B.2 Pause protocol (one atomic transaction)

`POST /vr/investigations/{id}/pause` dispatches a `pause_investigation`
task on the platform queue. The task body:

```python
async with UnitOfWork() as uow:
    # 1. SELECT FOR UPDATE every branch's cursor row.
    cursors = await uow.session.exec(
        select(WorkflowStateCursor)
        .where(WorkflowStateCursor.run_id.in_(
            select(TaskRecord.id).where(
                TaskRecord.investigation_id == investigation_id,
                TaskRecord.status.in_(("queued", "running", "waiting")),
            ),
        ))
        .with_for_update()
    ).all()
    # 2. Flip every cursor to __paused__ with prior state archived.
    for c in cursors:
        c.archived_state = c.current_state
        c.current_state = "__paused__"
        c.updated_at = now
    # 3. Cancel every active TaskRecord.
    await uow.session.exec(
        update(TaskRecord)
        .where(TaskRecord.investigation_id == investigation_id,
               TaskRecord.status.in_(("queued", "running"))),
        .values(status="cancelled", finished_at=now,
                cancellation_reason=f"operator_pause:{user_id}"),
    )
    # 4. Purge ARQ jobs (best-effort; cursor already paused so
    #    re-enqueue from any racing dispatcher is rejected).
    await purge_arq_jobs_for_investigation(investigation_id)
    # 5. Derived projection: inv.status = PAUSED, pause_reason set,
    #    paused_at, paused_by.
    await uow.session.exec(
        update(VRInvestigationRecord)
        .where(VRInvestigationRecord.id == investigation_id)
        .values(status="paused", pause_reason=reason,
                paused_at=now, paused_by_user_id=user_id),
    )
    await uow.commit()
```

Properties:
  - One transaction, one commit. Cursor + TaskRecord + ARQ-purge +
    `inv.status` derived projection all flip together.
  - SELECT FOR UPDATE on cursors prevents racing dispatchers
    from re-enqueueing during the pause window.
  - ARQ purge is the LAST step, after cursor is already paused.
    A surviving ARQ job that wakes the worker reads the cursor,
    sees `__paused__`, exits clean (no work done).
  - `archived_state` field on cursor preserves the prior state so
    resume knows where to restart.

New cursor column needed: `archived_state TEXT NULL` (alembic
migration; one-line add).

## B.3 Mid-LLM-call cancellation (optional — defer to B.5)

B.2 doesn't cancel an in-flight LLM call. The current LLM call
commits whenever it finishes, possibly minutes after the pause.
Operator accepts this for now (commits-through-pause is current
behavior).

If hard cancellation is required later (B.5):
  - `services.llm_client.chat(..., cancel_token=ctx.cancel_token)`
  - Engine generates the token at state entry, references the
    cursor. Token is set when cursor flips to `__paused__`.
  - `chat()` polls the token between retries (cheap) and at HTTP
    timeout boundaries. On set, raises `LLMCancelledError`.
  - Tool bridges similarly thread the token through `httpx.Stream`
    cancellation.
  - investigation_loop catches `LLMCancelledError` and exits clean
    with exit_reason="operator_pause_cancel".

B.5 is large enough to be its own phase. Phase B.1-B.2 ships
without it; the commits-through-pause behavior is acceptable.

## B.4 Resume protocol (one atomic transaction)

`POST /vr/investigations/{id}/resume` dispatches a
`resume_investigation` task. The task body:

```python
async with UnitOfWork() as uow:
    # 1. SELECT FOR UPDATE every paused cursor for this investigation.
    paused = await uow.session.exec(
        select(WorkflowStateCursor)
        .where(WorkflowStateCursor.investigation_id == investigation_id,
               WorkflowStateCursor.current_state == "__paused__")
        .with_for_update()
    ).all()
    if not paused:
        return {"status": "skipped", "reason": "no_paused_branches"}
    # 2. For each paused cursor: restore archived_state + clear archive.
    for c in paused:
        c.current_state = c.archived_state or "investigation_setup"
        c.archived_state = None
        c.updated_at = now
    # 3. Flip inv.status derived projection back to RUNNING.
    await uow.session.exec(
        update(VRInvestigationRecord)
        .where(VRInvestigationRecord.id == investigation_id)
        .values(status="running", pause_reason=None,
                paused_at=None, paused_by_user_id=None),
    )
    await uow.commit()
# 4. AFTER commit, fan out one ARQ task PER paused cursor.
#    Each task is keyed by (investigation_id, branch_id) — the
#    workflow engine resumes the named state for that branch.
for c in paused:
    await task_queue.submit(
        track="vr",
        fn=run_vr_investigate,
        kwargs={"investigation_id": investigation_id, "branch_id": c.branch_id},
        idempotency_key=f"resume:{investigation_id}:{c.branch_id}:{now.isoformat()}",
    )
```

Properties:
  - Fans out to EVERY branch that was paused, not just primary
    (fixes §34).
  - Idempotency key includes the resume timestamp so a second
    resume click within seconds doesn't double-dispatch.
  - Cursor state restored from archive — the engine resumes
    from `investigation_loop` (or wherever it was), NOT from
    `investigation_setup` (which would re-spawn siblings, etc.).

## B.5 (deferred) — hard cancellation of in-flight LLM calls

Already sketched in B.3. Stays a separate phase. Operator can
ship B.1-B.4 without it.

## B.6 Reset endpoint

`POST /vr/investigations/{id}/reset` becomes a "pause + clear
all cursors + clear all outcomes + create fresh primary" task.
Same atomic-transaction shape as B.2/B.4. Fixes §47 and §49.

## B.7 Frontend status display

Wire the cursor's `current_state` to the frontend (the §29
item 6 cleanup). Display the SSOT, not `inv.status` derived
column. `inv.status` becomes display-only fallback when cursor
is missing (legacy).

## B.8 Acceptance criteria for Phase B

Operator-verifiable:
  1. Pause an investigation with 6 active branches. Within 5
     seconds, ALL 6 branches' tool calls cease accepting new
     work. No new turn fires after pause+5s. (Currently fails
     per §35 — trailing tool call commits.)
  2. Resume the same investigation. ALL 6 branches re-spawn an
     ARQ task. Each task's cursor shows the prior state
     (`investigation_loop`, NOT `investigation_setup`). Within
     30 seconds, every branch resumes its turn. (Currently
     fails per §34 — only primary resumes.)
  3. Pause + reset + resume — fresh primary spawned, no
     leftover cursors from prior session. (Currently fails
     per §47.)
  4. `.run/reopen_stalled.py` is deleted. No operator script
     needed to drive pause/resume.

## B.9 Items closed by Phase B

§3 (reopen mutates cursor from handler), §32 (pause doesn't
cancel TaskRecord), §33 (resume no FOR UPDATE), §34 (resume
no branch fan-out), §35 (pause doesn't pause cursor), §47
(reset doesn't delete cursor), §49 (reset button on PAUSED),
§156 (dispatcher doesn't re-verify status before COMPLETED
— cursor SSOT eliminates the race), §287 (loop polls
inv.status per turn — replaced by cursor poll), §288 (loop
doesn't poll branch.status — cursor IS the branch state),
§330 (synthesis UoW 2 doesn't re-check status), §296
(investigation_setup unconditional RUNNING flip — replaced
by cursor-driven transitions).

12+ items closed. The migration to add `archived_state` is
the only schema change. Backward-compatible: existing
cursors without `archived_state` resume from
`investigation_setup` as today.

---

# Phase C — synthesis trigger broadened to a single workflow state

## C.0 The problem

Today, synthesis fires from THREE separate paths:
  1. `investigation_emit._maybe_trigger_synthesis` (line 618-747):
     fires when every active branch in the panel has produced a
     terminal outcome. (the happy path.)
  2. `parent_reconciler._close_rejected_outcomes`: closes when
     primary outcome is REJECTED and quorum siblings reject too.
  3. `parent_reconciler._synthesize_no_finding_outcomes`: catches
     the orphan case where every branch is terminal but no
     outcome exists. Bare except (§315) — failures silent.

Plus a fourth implicit path:
  4. `parent_reconciler._abandon_stale_branches` flips active
     branches → abandoned based on heartbeat staleness. This
     PROMOTES the investigation toward synthesis trigger #1 or
     #3 firing, but doesn't itself synthesize.

These four paths race, each with its own bugs (§315 bare
except, §316 2-min vs 15-min idle grace, §313 turn-count
inflation). Investigations occasionally don't terminate
because no path fires cleanly. Operator pulls out
`.run/reopen_stalled.py` or `.run/backfill_masvs.py` to
nudge.

The §29 cutover items 4 + 7 partially address this by moving
sweeps into workflow states. Phase C completes the move.

## C.1 New workflow state: `investigation_finalize`

After Phase A item 1 (workflow definition rewrite), every
investigation's state graph has explicit transitions to a
`investigation_finalize` state. The state body:

```python
async def state_investigation_finalize(input, services) -> StateResult:
    investigation_id = input["investigation_id"]

    # SELECT all branches + outcomes once.
    async with UnitOfWork() as uow:
        snapshot = await load_finalization_snapshot(uow, investigation_id)

    # Three trigger conditions (any one fires synthesis):
    trigger = pick_finalization_trigger(snapshot)
    if trigger is None:
        # Not ready yet — re-schedule for the next reconciler tick.
        return StateResult(next_state="investigation_finalize_wait", output=input)

    if trigger == "all_outcomes":
        # The happy path — synthesize from contributions.
        outcome = await synthesize_from_panel(snapshot)
    elif trigger == "all_terminal_no_outcome":
        # Orphan case — write audit_memo.
        outcome = synthesize_no_finding_audit_memo(snapshot)
    elif trigger == "rejected_quorum":
        # Rejected canonical — close with explicit failure record.
        outcome = synthesize_rejected_record(snapshot)
    elif trigger == "wall_clock_idle_grace":
        # Wall-clock fired, no active branch wrote in idle window.
        outcome = synthesize_cap_exceeded_audit_memo(snapshot)

    # Single atomic commit: write outcome + flip every branch +
    # flip investigation derived projection.
    async with UnitOfWork() as uow:
        await uow.session.exec(insert_outcome(outcome))
        await uow.session.exec(
            update(VRInvestigationBranchRecord)
            .where(...)
            .where(status="active")
            .values(status="completed", closed_reason=f"finalize:{trigger}"),
        )
        await uow.session.exec(
            update(VRInvestigationRecord)
            .where(id == investigation_id)
            .values(status="completed", primary_outcome_id=outcome.id,
                    stopped_at=now),
        )
        await uow.commit()

    return StateResult(next_state=RESERVED_SUCCEEDED, output={
        "investigation_id": investigation_id,
        "outcome_id": outcome.id,
        "finalize_trigger": trigger,
    })
```

## C.2 Trigger picker logic

`pick_finalization_trigger(snapshot)` returns the first matching:

|order|condition|trigger|
|---|---|---|
|1|every branch has primary terminal outcome|`all_outcomes`|
|2|every branch is in terminal state (active=0)|`all_terminal_no_outcome`|
|3|primary outcome is rejected AND quorum siblings rejected|`rejected_quorum`|
|4|wall_clock_hours exceeded AND idle_grace exceeded|`wall_clock_idle_grace`|
|—|otherwise|None — re-schedule|

Single function, deterministic. Operator can read it in one
screen. Replaces `_close_rejected_outcomes` +
`_synthesize_no_finding_outcomes` + `_abandon_stale_branches`
+ `investigation_emit` wall-clock check + `investigation_reaper`
wall-clock check (six separate sites today).

## C.3 Re-schedule via engine-native mechanism

`investigation_finalize_wait` is an engine-native "park this
cursor; re-enter when any branch's state transitions" pattern.

The engine already supports cursor-pause-on-condition via
`StateResult(next_state="__waiting__", wake_on=[...])`. Phase C
wires:

```python
return StateResult(
    next_state="investigation_finalize_wait",
    wake_on=[
        WakeOn.cursor_transition(investigation_id, branch_id=None),
        WakeOn.timer(wall_clock_hours + idle_grace_s),
    ],
    output=input,
)
```

Any branch transitioning state OR the wall-clock timer firing
wakes the cursor. The state re-evaluates triggers; if still
not ready, re-parks.

If the engine doesn't support `wake_on` today, Phase C ships
with a polling fallback (cron tick every 60s wakes
`investigation_finalize_wait` cursors). Wake_on is a Phase A
stretch goal.

## C.4 Items closed by Phase C

§111 (PENDING outcomes have no reaper — finalize state catches
them), §138 (`_enqueue_dependents` flips WAITING→QUEUED without
ARQ submit — finalize state handles), §156 (synthesis writes
COMPLETED — replaced by finalize state), §282
(investigation_emit cap cascade — moved into finalize),
§285 (ARQ purge after cap-exceeded commit — finalize commit is
atomic so no purge needed), §300 (cap from two sites —
collapsed), §313 (`_synthesize_no_finding_outcomes` inflated
turn count — finalize uses correct accounting),
§315 (`_synthesize_no_finding_outcomes` orphan-forever — finalize
state has retry semantics via engine), §316 (branch_reaper 2-min
vs investigation_reaper 15-min — single timer in finalize),
§330 (synthesis UoW 2 doesn't re-check status — finalize is
the single writer).

9+ items closed. Three files deleted:
`branch_reaper.py`, `investigation_reaper.py`,
`masvs/parent_reconciler._close_rejected_outcomes` +
`_synthesize_no_finding_outcomes` + `_abandon_stale_branches`
helpers. Roughly 1200 LoC net removed.

## C.5 Acceptance criteria for Phase C

Operator-verifiable:
  1. Spawn an investigation. Kill all 6 worker tasks externally
     before any submits an outcome. Within 5 minutes (wall-clock
     + idle-grace), the investigation transitions to COMPLETED
     with an `audit_memo` outcome explaining "every branch
     terminated without producing a finding". (Currently fails
     per §315 — orphan stays orphan.)
  2. Spawn an investigation where the primary persona votes
     REJECT and 2 sibling critics also vote REJECT. Within 60
     seconds, the investigation transitions to COMPLETED with
     the rejected outcome flagged. (Currently bug: rejected
     paths via two helpers race per §86 / §107.)
  3. `.run/backfill_masvs.py` and `.run/diff_masvs.py` are
     deleted. No operator script needed to drive MASVS audit
     completion.

---

# Phase D — prompt builder broadcast verification + fix

## D.0 The problem

Two writers post operator-kind messages with the intent of
reaching EVERY branch's prompt:
  - `outcome_review.post_draft_review_request` (§249)
  - `auto_steering._post` (§335)

Both attach the message to the PROPOSING / PRIMARY branch with
the assumption that the prompt builder broadcasts
OPERATOR-sender messages across siblings. If that assumption
is wrong, the entire deliberation-review and auto-steering
mechanisms are partially broken.

The symptoms operator has observed match this failure mode:
  - "drafts get reviewed but the system rate-limits via the
    LIKE check" — actually: sibling critics never see the
    review request, so they never vote.
  - "agent keeps making the same mistake even after auto-
    steering posts" — actually: only the primary persona's
    next prompt sees the steering; siblings continue
    ignoring the condition.

## D.1 Verification (one read)

Read the prompt builder body (it lives in `vuln_researcher.py`
near `run_turn`, around the part that loads messages for the
current turn's user prompt). Identify the SELECT that filters
messages.

Two outcomes:

**Outcome A**: prompt builder filters by `investigation_id`
and includes OPERATOR-sender messages from any branch. The
broadcast assumption holds. Phase D is then a no-op on the
writer side; just verify §249 / §335 behave as documented.
Single doc update.

**Outcome B**: prompt builder filters by `branch_id`. The
broadcast assumption is wrong. Phase D ships a writer fix:

## D.2 Writer fix if Outcome B

Both `outcome_review.post_draft_review_request` and
`auto_steering._post` write ONE OPERATOR-sender message PER
active branch instead of one message on the primary.

```python
# Pattern: write N messages, one per active branch.
async with UnitOfWork() as uow:
    actives = (await uow.session.exec(
        select(VRInvestigationBranchRecord).where(
            VRInvestigationBranchRecord.investigation_id == investigation_id,
            VRInvestigationBranchRecord.status == "active",
        )
    )).all()
    for branch in actives:
        msg = VRInvestigationMessageRecord(
            investigation_id=investigation_id,
            branch_id=branch.id,
            sender_kind=SenderKind.OPERATOR.value,
            ...
            payload_json=json.dumps({
                "text": text,
                "auto_steering_key": auto_steering_key,
                "broadcast_group": broadcast_uuid,  # for dedup
            }),
        )
        uow.session.add(msg)
    await uow.commit()
```

`broadcast_group` (new payload field) lets the ACK observable
match multiple per-branch messages back to one logical
steering. Each branch ACKs its own copy; dedup matches by
group_id, not individual message_id.

## D.3 Alternative: fix the reader (prompt builder)

If Outcome B is reality, the writer fix above is a band-aid.
The structural fix is to change the prompt builder's SELECT
to:

```python
_select(VRInvestigationMessageRecord)
.where(VRInvestigationMessageRecord.investigation_id == investigation_id)
.where(or_(
    VRInvestigationMessageRecord.branch_id == self.branch_id,
    VRInvestigationMessageRecord.sender_kind == SenderKind.OPERATOR.value,
))
```

OPERATOR messages on ANY branch reach this branch's prompt.
The writer keeps writing to primary only. One write, N reads.

## D.4 Pick reader vs writer fix

Reader fix is structurally cleaner (one write, N reads), but
may surprise other readers of the message table (frontend,
audit log) that don't expect cross-branch leakage. Writer
fix is local (only the two writers change) but multiplies
message-table row count by branch_count.

Recommend: **reader fix**, with the writers explicitly
stamping `broadcast_intent=True` on the payload so other
message-table consumers can opt into the same broadcast logic.

## D.5 Items closed by Phase D

§249 (outcome_review attaches to proposing branch only),
§335 (auto_steering primary-branch broadcast assumption),
§336 (auto_steering primary SELECT no dead filter — moot if
reader fix; minor cleanup if writer fix).

3 items closed. Plus the load-bearing operator-observed
symptoms (panel deliberation broken, auto-steering ignored)
resolve.

## D.6 Acceptance criteria for Phase D

Operator-verifiable:
  1. Trigger an `auto_steering` rule (e.g. `read_lines` past
     EOF). Within 60 seconds, EVERY active branch's next prompt
     contains the steering directive at the OPERATOR position.
     (Currently only primary persona sees it.)
  2. Submit a draft outcome that triggers
     `post_draft_review_request`. Within 60 seconds, every
     sibling critic persona's next prompt contains the review
     request and votes within the next 2 turns. (Currently
     siblings never see the request → never vote → draft
     auto-approved by timeout per §282.)

---

# Combined acceptance: "set and forget" investigation

After Phase A + B + C + D ship in order:

|behavior|works?|why|
|---|---|---|
|6-branch investigation runs to natural completion|✅|Phase A reaper consolidation + Phase C single finalize state|
|Operator pause → 5s → no new turns fire|✅|Phase B cursor-SSOT atomic pause|
|Operator resume → ALL 6 branches re-spawn|✅|Phase B archived_state restore + branch fan-out|
|Investigation with mid-LLM call during pause|⚠️|Commits-through-pause until Phase B.5 ships|
|Orphan investigation (all branches abandon, no outcome)|✅|Phase C finalize state's `all_terminal_no_outcome` trigger|
|Wall-clock cap exceeded|✅|Phase C single timer + idle-grace check|
|Operator steering message reaches all siblings|✅|Phase D reader fix|
|Draft outcome reviewed by every active critic|✅|Phase D reader fix|
|MASVS 53-control audit completes without manual reopen|✅|Phase A reconciler + Phase C finalize|
|`.run/reopen_stalled.py` deleted|✅|All paths converge|
|`.run/backfill_masvs.py` deleted|✅|All paths converge|
|`.run/diff_masvs.py` deleted|✅|All paths converge|
|`.run/diag_inv.py` / `diag_busy.py` deleted|✅|Cursor SSOT means one place to look|

After Phase B.5 (hard cancellation) the ⚠️ becomes ✅. Phase B.5
is operator-elective; the rest is mandatory.

Net code change estimate:
  - Phase A: ~1500 LoC deleted (reapers + sweep helpers) +
    ~800 LoC added (workflow state graph rewrite). Net -700.
  - Phase B: ~400 LoC added (pause/resume tasks, cursor SSOT
    contract, archive column migration). 4 sites changed.
  - Phase C: ~1200 LoC deleted (3 reaper files + 3 sweep
    helpers) + ~400 LoC added (finalize state, trigger picker).
    Net -800.
  - Phase D: ~30 LoC changed (one query in prompt builder OR
    two writers changed). Net ~0.

Total net: ~1500 LoC deleted, ~50 items from the 355
resolved structurally, the rest become correctness/cost
cleanups orthogonal to the topology.

The remaining ~300 items (after structural Phases A-D) are
the "correct silent wrong answers" / "narrow exception filter"
/ "cap drift" cleanups. Those ship incrementally; none of them
block self-driving.

---

# Phase ordering rationale (non-negotiable)

- **A before B**: Phase B's cursor SSOT depends on the
  workflow state graph existing in canonical form. Without A,
  there's no `__paused__` cursor state to write to, no resume
  target state to restore from.
- **B before C**: Phase C's `investigation_finalize` state
  needs the cursor SSOT to know when to fire. Without B, the
  finalize trigger picker can't deterministically read state.
- **C before D**: Phase D depends on the message-table query
  pattern. C's finalize state may introduce new OPERATOR
  messages (e.g. cap-exceeded notification). Aligning the
  broadcast rule with all writers at once avoids two passes.
- **B.5 is independent**: hard cancellation can ship any time
  after B.4. Operator can defer indefinitely.

No code edits in any phase without explicit operator sign-off
on the SEQUENCE above. Phases ship as discrete PRs with their
own acceptance criteria; no half-shipped phases.

---

# Phase D — RESOLVED — Outcome A (no code change)

Read of `src/aila/modules/vr/agents/vuln_researcher.py:1024-1097`
confirms the prompt builder already implements broadcast correctly:

- Line 1028: `SELECT ... WHERE investigation_id == self.investigation_id`
  (scoped to investigation, not branch).
- Line 1029: `AND sender_kind == OPERATOR.value` (filter to operator
  messages).
- Line 1092-1096: explicit broadcast rule — messages whose
  `branch_id == self.branch_id` OR `branch_id == primary_id` OR
  `branch_id is None` are visible; messages addressed to a SPECIFIC
  sibling are suppressed.

Docstring at line 1015-1017: *"Primary-branch addressing is treated
as broadcast."*

Therefore:
- §249 (`outcome_review.post_draft_review_request` attaches to proposing
  branch) — NOT A BUG. The writer attaches to the proposing branch
  (which is the primary), the reader broadcasts. Verified.
- §335 (`auto_steering._post` attaches to primary branch broadcast
  assumption) — NOT A BUG. Same shape. Verified.
- §336 (primary branch SELECT may pick terminated row) — MINOR but
  not critical: line 1043 filters `parent_branch_id IS NULL` and picks
  any one with LIMIT 1. If multiple primaries exist (post self-heal),
  the chosen primary id is non-deterministic but consistent across
  siblings in the same UoW. Defer to E16 if frontend operator-message
  visualization needs the live-primary preference.

The "agent keeps making same mistake despite auto-steering" symptom
the operator reported has a different root cause (likely candidates:
wall-clock TTL filtering at line 1075, ACK filter at line 1086 being
set prematurely, or tool-dispatch not honoring directives even when
the agent sees them — all separate from the broadcast scope).

**Items closed by Phase D outcome A**: §249, §335 (§336 deferred to E16
as minor).

**Verified**: 2026-06-11. No commit; doc update only.
