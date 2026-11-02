# RFC-290 -- Agent-loop consolidation and a module-binding orchestrator contract

Status: Draft (design settled; implementation staged and gated on the decisions in section 7).
Issue: #290. Depends on: #286 (landed -- the `ClaimVerificationHook` module seam).

## 1. Problem

The shared per-turn agent framework is `AgentTurnRunnerBase.run_turn`
(`src/aila/platform/agents/turn_runner.py:146`, pipeline `:881-1628`) plus the
shared loop driver `state_investigation_loop`
(`src/aila/platform/workflows/investigation_loop_base.py:245`) and the shared
`ToolExecutor`. VR (`HonestVulnResearcher`,
`src/aila/modules/vr/agents/vuln_researcher.py`) and malware
(`HonestMalwareResearcher`,
`src/aila/modules/malware/agents/malware_researcher.py`) both subclass the base.

Two gaps remain:

1. The two production researchers duplicate a large block of prompt and
   tool-spec render helpers. About eleven helper bodies are byte-identical and a
   further fifteen differ only in module-specific data.
2. Four agent loops run off the base: `NdayResearcher`
   (`src/aila/modules/vr/agents/nday_researcher.py:206`), `DanteAgent`
   (`src/aila/platform/agents/dante/agent.py:358`),
   `state_forensics_panel_loop`
   (`src/aila/modules/forensics/workflow/panel/loop.py:203`), and
   `HonestInvestigator` (`src/aila/modules/forensics/agents/investigator.py:471`).

There is no single declared contract for "bind a module's agent to the shared
loop." Researchers are wired through class attributes plus the
`InvestigationStateBindings` dataclass
(`src/aila/platform/workflows/investigation_setup_base.py:66`) and module-level
`_LOOP_BINDINGS` / `_SETUP_BINDINGS` / emit bindings. The dead
`InvestigationStateBindings.run_turn` field (never assigned or read) has been
removed as part of this RFC's first commit.

## 2. Goals and non-goals

Goals:
- Remove the byte-identical render-helper duplication between VR and malware
  behind one shared, parameterized surface, with zero change to rendered prompt
  bytes (so the idempotency cache keeps hitting; see R3).
- Formalize a module-binding contract around the existing bindings seam so
  "add a module agent" is a declaration, not a re-implementation.
- Decide and document each off-base loop: migrate or carve out with rationale.

Non-goals:
- Rewriting `run_turn`'s pipeline shape or the single-UoW persist (R1, R2).
- Changing any module's observable investigation behavior as a side effect of
  deduplication. Behavior changes are separated into the explicit decisions in
  section 7 and are each opt-in.

## 3. Carve-out verdicts for the four off-base loops

| Loop | Live? | Verdict | Rationale |
|---|---|---|---|
| `DanteAgent.respond()` | yes (`src/aila/platform/runtime/orchestrator.py:173-176`) | carve out | One-shot request-scoped completion (`agent.py:380-505`). No turn loop, no branch state, no tools, no idempotency. `run_turn`'s pipeline does not apply. |
| `state_forensics_panel_loop` | opt-in only (`src/aila/modules/forensics/workflow/panel/definitions.py:82-85`) | defer | Stub loop; submits on turn 1 (`loop.py:291-317`). No tests reference it (R23). Nothing to consolidate until it has real behavior. |
| `NdayResearcher.research()` | yes (`src/aila/modules/vr/workflow/states/research.py:26`) | carve out; fix R6/R7 separately | Decision source is raw chat JSON, exit is budget-or-adjudication, no branching, no quorum. Structurally unlike `run_turn`. Has two correctness bugs (R6, R7) and zero characterization tests. |
| `HonestInvestigator` (forensics INV) | yes (`src/aila/modules/forensics/workflow/states/freeflow.py:219`) | carve out for #290 | Its unresolved-hypotheses gate is NOT a parity copy of VR/MWR (answer-text citation escape at `investigator.py:1330-1335`, in-memory counter `:1343`, returns a reason string, cap `0` disables). SSH tool dispatch, not `ToolExecutor`. A straight dedupe is impossible; see decision 7. |

Conclusion: the "migrate the loops" half of #290 resolves to carve-outs. The
value is in the render-helper consolidation and the binding contract. The NDAY
bugs are real and are tracked below as spin-off fixes, gated on characterization
tests.

## 4. Render-helper consolidation plan

New home: a platform module `src/aila/platform/agents/prompt_sections.py`
(render helpers) plus additions to the existing
`src/aila/platform/agents/turn_helpers.py` for non-render shared logic.
Precedent for a platform-owned render helper exists
(`src/aila/platform/agents/synthesis_runner.py:_render_verifier_annotation`,
tested at `tests/platform/agents/test_synthesis_runner_verifier_annotation.py:44`).

### 4.1 Verbatim lifts (bodies identical; lowest risk)

Lift unchanged, re-export from each module for the pinned test imports (no
shims -- the module name becomes a thin `from ... import ...`):

| Helper | VR | Malware |
|---|---|---|
| `_render_operator_messages_section` | `vuln_researcher.py:3686-3729` | `malware_researcher.py:1965-2008` |
| `_render_active_directives_section` | `3730-3775` | `2009-2044` |
| `_format_param` | `3956-3975` | `2231-2250` |
| `_render_available_tools_section` | `3976-4068` | `2251-2341` |
| `_render_pattern_section` | `3434-3481` | `1916-1964` |
| `_render_retrieved_knowledge_section` | `3486-3529` | `1872-1915` |
| `_outcome_payload` | `4154-4180` | `2459-2490` |
| `_CONFIDENCE_RANK` | `4189-4192` | `2504-2507` |
| `_load_prompt_seed_from_file` | `4617-4633` | `2899-2915` |

The unresolved-hypotheses gate control flow (VR `1193-1336`, MWR `1005-1146`) is
code-identical; lift the control flow and take the LLM-facing directive prose as
a parameter (decision 4). Budgets that differ (`_render_pattern_section` 3000,
`_render_retrieved_knowledge_section` 4000 vs 4000) become arguments.

### 4.2 Parameterized lifts (same skeleton, module data differs)

`_render_target_snapshot_section` (top_n, sample_path, APK), prior-submissions
section, sibling-context section (recent_activity optional, R24),
`_applicable_servers_for_kind` / `_applicable_servers_by_capability`,
`_fetch_tool_specs` (read-only allowlist, android_mcp), decision payload
envelope, `_terminal_outcome_kind`, `_upsert_canonical_outcome`, prompt key /
load / seed, record-experience. Each takes a module descriptor object; bodies
stay behavior-identical per module.

### 4.3 Stays module-local

`_mcp_family_rule_for_kind`, `_render_cve_intel_section`, the VR fuzz projection
(`vuln_researcher.py:2919-2963`, R10), the VR explorer hook (`:391`), VR
`_build_recall_fetcher` (`:300-356`), the VR wave-2 gates (`:2580-2633`).

### 4.4 Byte-identity guard

Because the idempotency cache keys on `sha256(system + NUL + user)`
(`turn_runner.py:1047-1053`, R3), every lift MUST keep rendered output
byte-identical. The implementation adds a characterization test that renders a
fixed decision/case_state through both the pre-lift and post-lift path and
asserts equal bytes, for each lifted section, before the module copies are
deleted.

## 5. Module-binding contract

Formalize around the existing seam rather than inventing a parallel one:

- Keep researcher class attributes as the per-researcher binding
  (`_MODULE_ID`, `_LOG_LABEL`, `_result_cls`, `known_allocators`,
  `known_input_readers`, `_record_experience_on_verdict`).
- Keep `InvestigationStateBindings.researcher_factory`
  (`investigation_loop_base.py:344-347`) as the one loop seam.
- Keep the #286 `ClaimVerificationHook` on the dispatcher class
  (`outcome_dispatcher.py:244`). Do NOT duplicate it on the researcher (R20).
- Introduce a `ModuleAgentBinding` descriptor (frozen dataclass in
  `src/aila/platform/agents/module_binding.py`) that a module constructs once and
  that supplies the parameterized render descriptors from section 4.2 plus the
  gate prose (section 4.1). The researcher reads it; `create_module` is not
  changed (bindings remain module-level constants imported by `definitions_hub`,
  matching current wiring at `vr/workflow/definitions_hub.py:36-51`).

This keeps platform import discipline (R22): no `aila.modules` import lands in
`src/aila/platform/agents/`.

## 6. Risk register (carried from the scoping map)

Load-bearing, must not regress: R1 (gate order vs empty-tool-run coercion),
R2 (single UoW + row lock), R3 (prompt-byte idempotency), R14 (base helpers
called unbound on duck-typed `self` in tests), R15 (name-based honesty audit),
R16 (prompt-store monkeypatch targets). The full table (R1-R25) lives in the
scoping notes attached to issue #290.

Spin-off correctness bugs found while scoping (NOT caused by this RFC):
- R6: NDAY blocked-submit leak -- a rejected, unadjudicated claim can be
  reported `status=completed` (`nday_researcher.py:358,368,553-558`;
  `research.py:50-51`).
- R7: NDAY does not catch `LLMError` / `LLMCancelledError`
  (`nday_researcher.py:266`; `research.py:49` has no try). An LLM error escapes
  the state.

## 7. Decisions required before the behavior-touching work

These change observable behavior on production investigation pipelines, so they
are explicit choices, not defaults the implementer may pick:

1. Malware superseded-row filter on loaders/consume (R8). Add it (align with VR,
   changes malware reads) or leave it (keeps the latent message-reinjection gap).
2. Malware evidence seed `'[]'` vs VR canonical refs in `_upsert_canonical_outcome`
   (R18). Unifying changes malware's persisted rows.
3. `acked_at` predicate placement (R9) -- malware-only column; keep as a
   module predicate or promote to VR.
4. Unresolved-hyp directive prose (R4) -- one shared text or a per-module
   parameter. Recommended: parameter (preserves current prompts, keeps cache).
5. Gate counter key convention (R5). Recommended: keep existing keys (renaming
   resets in-flight counters on persisted case_state).
6. Per-module unresolved-hyp cap defaults (R17): VR 10, MWR 3, INV 3. Keep.
7. INV gate: adopt VR semantics (drop the answer-text escape, persist the
   counter) or document the divergence permanently.
8. NDAY R6/R7: fix within #290 or as separate issues (recommended: separate,
   gated on new characterization tests, R23).
9. Add characterization tests for NDAY/DANTE/PANEL before any future migration
   (R23) -- currently none exist.

Recommended posture for a pure consolidation: resolve 4, 5, 6 as "preserve
behavior via parameterization"; defer 1, 2, 3, 7 as independent behavior changes;
split 8 into its own bug issue. That yields a zero-behavior-change consolidation
PR, with the behavior questions handled separately and visibly.

## 8. Staged delivery

1. (done) Remove the dead `InvestigationStateBindings.run_turn` field.
2. Add `prompt_sections.py` + byte-identity characterization tests; lift the
   section 4.1 verbatim helpers; update the test importers (scoping map section
   2.6); honesty audit green.
3. Lift the section 4.2 parameterized helpers behind `ModuleAgentBinding`.
4. Land the behavior decisions from section 7 that the operator approves, each
   as its own commit with its own test.
5. File the NDAY R6/R7 fixes as a separate issue with characterization tests.
