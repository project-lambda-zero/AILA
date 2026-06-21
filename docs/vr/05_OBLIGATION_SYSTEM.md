# VR Module — The Evidence Obligation System: Anti-Bluffing Mechanics

The reasoning loop (`docs/vr/01_REASONING_LOOP.md`) sketches an "adjudicator" that catches LLM bluffs. The exploitation doc (`docs/vr/03_EXPLOIT_AUTOMATION.md`) sketches a per-tier obligation table for runtime claims. The MCP doc (`docs/vr/02_IDA_HEADLESS_MCP.md`) sketches obligation-aware audit logs for static-analysis evidence. This document collapses the three views into one mechanism: how the obligation system is structured, what claims it tracks, how obligations are lifecycle-managed, what the deterministic rule engine actually checks per turn, and where the system breaks at the seams.

The frame: **the LLM is allowed to be confident only when the evidence graph contains the artifacts that justify the confidence.** Every claim creates a debt; the loop discharges debts by collecting matching evidence. Submission is gated on the debt being paid. This is the Metis pattern (prior design notes), specialized to vulnerability research where claims fan out across static, dynamic, and exploitation domains.

> **Status: design exploration.** This document predates the shipped VR
> engine and describes an idealised contract, not current code. The
> shipped implementation diverges in class names, enum values, table
> schemas, routes, and state machines. Use this doc for intent and
> taxonomy; verify every concrete claim against the files listed in
> "Current implementation pointers" below before relying on it.
>
> **Current implementation pointers** (verified 2026-06-21):
>
> | Topic | Shipped location |
> |---|---|
> | Reasoning loop | `src/aila/modules/vr/agents/vuln_researcher.py` |
> | Submit-time gates | `vuln_researcher._maybe_reject_submit_when_draft_pending`, `_maybe_reject_submit_with_unresolved_hypotheses`, variant-hunt gate |
> | Per-LLM-call idempotency | `src/aila/platform/llm/idempotency_cache.py` + migration `061_llm_idempotency_cache.py` |
> | Auto-steering | `src/aila/modules/vr/agents/auto_steering.py` |
> | Outcome routing | `src/aila/modules/vr/agents/outcome_dispatcher.py` |
> | DB schema (19 tables) | `src/aila/modules/vr/db_models/__init__.py` |
> | Contract enums (TargetKind, InvestigationKind, InvestigationStatus, HypothesisState, OutcomeKind, PersonaVoice) | `src/aila/modules/vr/contracts/` |
> | Alembic head | `src/aila/alembic/versions/067_workflow_state_cursor_archived_state.py` |

## 0.1  What shipped instead

The formal VR-side `VRObligation` table + standalone rule engine is
unbuilt. Honesty discipline ships today through:

- **`ClaimVerifierAgent`** (`agents/claim_verifier.py`) — adversarial
  post-synthesis verification with probe-based refutation.
- **Auto-steering** (`agents/auto_steering.py`) — dead-end pattern
  detection with corrective operator-message injection at PROMPT
  POSITION 2; see `docs/PITFALL_GUIDE.md` Pitfall 33.
- **Three submit-time gates** in `vuln_researcher.py`:
  `_maybe_reject_submit_when_draft_pending`,
  `_maybe_reject_submit_with_unresolved_hypotheses`, and the
  variant-hunt exhaustion gate.
- **Sibling-consensus rejection** — branch siblings vote to drop a
  hypothesis even when the originating branch still has it live;
  a `_directive.sibling_consensus_rejection` observable is injected.

Treat the obligation taxonomy below as design vocabulary, not a
spec of running code.

---

## 1. Why Obligations Exist

A standard chat-style agent emits a paragraph of conclusions, the user reads it, and trust is interpersonal. A research workbench emitting CVE-class findings is not interpersonal; the consumer of the output is a vendor PSIRT, a customer security team, or — eventually — a CVE database. The cost of a wrong "exploitable" verdict is reputational damage to the platform and, downstream, an inflated CVSS that wastes engineering attention.

The single behavior we want to prevent is **uncorrelated confidence**: the LLM saying "this is RCE" with the same surface fluency whether it has a working PoC or a hypothesis. The obligation system breaks the correlation by making confidence a function of artifacts in the evidence graph, not of word choice in the LLM's prose.

Three mechanisms together do this:

1. **Obligation registration.** Every claim with `confidence ≥ medium` registers a typed obligation that names the artifact class needed.
2. **Deterministic adjudication.** A rules engine runs after every turn and checks obligations, contradictions, and uncertainty signals. The engine does not call the LLM.
3. **Submit gating.** A finding cannot be persisted until all CRITICAL and REQUIRED obligations linked to its claims are satisfied or operator-waived.

The LLM cannot route around any of these by being more eloquent.

---

## 2. Obligation Taxonomy

Obligations are typed by claim category. The table below is exhaustive for v0.1 and is the source of truth that the rules engine compiles to runtime checks. Each row maps a claim shape to (a) the artifact class that satisfies it, (b) the source tool that produces the artifact, (c) the severity level (see §4), and (d) notes for the rules engine.

### 2.1 Exploitability claims

| Claim shape (LLM text or contract field) | Required evidence | Source artifact / tool | Severity | Adjudicator notes |
|---|---|---|---|---|
| "heap overflow" / `bug_class=heap_overflow` | ASAN/HWASAN report containing `heap-buffer-overflow` AND a target-side allocator state dump | run_target with ASAN + pwndbg `vis_heap_chunks` | CRITICAL | Reject if claim is heap but ASAN report says `stack-buffer-overflow` (contradiction). Reject if no ASAN run is in the graph. |
| "stack overflow" / `bug_class=stack_overflow` | ASAN report `stack-buffer-overflow` OR core dump showing return address overwrite | run_target / GDB | CRITICAL | If both ASAN and GDB disagree on bug class, force `confidence=inconclusive`. |
| "use-after-free" / `bug_class=uaf` | ASAN `heap-use-after-free` with allocation-stack and free-stack frames | ASAN | CRITICAL | The free-stack frame must be present in the report — "UAF without a free site" is a false-positive shape ASAN occasionally produces with mmap'd objects; flag as caveat. |
| "double-free" / `bug_class=double_free` | ASAN `attempting double-free` | ASAN | CRITICAL | — |
| "controlled write" | GDB output showing `mov [rdi], rax` (or equivalent) where `rdi` and `rax` both contain untrusted-input bytes; bytes traceable to the input | GDB session log + input-mapping artifact | CRITICAL | Both the address and the value must derive from untrusted input. "Crash in `mov` instruction" is not a controlled write. |
| "controlled call / RIP control" | Core dump or GDB output where instruction pointer equals untrusted-input bytes | core file, GDB | CRITICAL | The bytes must be matchable against an entry in the trigger input (the model can't claim RIP control with a hardcoded `0x4141414141414141` if the input is JSON). |
| "exploitable" | All target mitigations enumerated; bypass primitive present for each enabled mitigation OR explicit "no bypass needed" justification per mitigation | `analyze_binary` mitigations block + per-mitigation evidence | CRITICAL | The mitigation set is read from `analyze_binary` (deterministic). Each enabled mitigation must be addressed in the reasoning. CFI on, ROP claimed, no CFI bypass cited → reject. |
| "RCE" | Either (a) a working PoC that executes a marker command in the target context, OR (b) demonstrated RIP control + a verified ROP/JOP chain that reaches a syscall/library call equivalent to code execution | exploit-run log with marker output, OR ROP chain log + gadget verification | CRITICAL | If (b), every gadget address must appear in `ROPgadget --binary` output. If (a), the marker command's output must be captured (not "presumably worked"). |
| "ASLR bypassed" | Info-leak primitive that prints a concrete address from a randomized region; computed module base from leak; runtime confirmation that base + offset hits expected symbol | exploit-run log showing leaked pointer, GDB confirmation | REQUIRED | The leaked value must be different across runs (or the model is reading a non-randomized region). Reject "ASLR bypassed" if run-to-run leaked value is identical. |
| "canary bypassed" | Either canary value leaked OR overflow path proven (decompilation + trace) to skip the canary check | leak primitive log, OR control-flow trace bypassing `__stack_chk_*` | REQUIRED | "We overflow past the canary" without a leak or skip-path is the most common bluff shape. |
| "DEP/NX bypass" | ROP chain executed end-to-end OR mprotect/VirtualProtect call demonstrated | exploit-run log, GDB | REQUIRED | Tied to the RCE obligation; satisfied as a side-effect when RCE evidence is present. |
| "CFI bypass" / "CET bypass" / "MTE bypass" | Specific bypass technique cited (data-only attack, indirect branch into valid target, signature collision, etc.) AND evidence the technique succeeded against the target's specific configuration | exploit-run log + `analyze_binary` mitigation block confirming CFI flavor | CRITICAL | These are the highest-bluff-rate claims. Any modern mitigation bypass requires per-target proof; generic blog-post citations are not evidence. |
| "kernel LPE" | Post-exploit privilege transition demonstrated (`getuid()`, `cat /proc/self/status`) | exploit-run log | CRITICAL | "We get RIP control in kernel context" does not satisfy. |
| "sandbox escape" | Side-effect demonstrably outside the sandbox (file written outside chroot, syscall executed that policy disallows) | exploit-run log + sandbox-policy artifact | CRITICAL | The sandbox policy must be a captured artifact (seccomp profile dump, AppArmor profile), not LLM-summarized. |
| "info leak" | Specific bytes leaked + symbol resolution showing what they are | byte dump + symbol resolution from `analyze_binary` | REQUIRED | "We leak the libc base" without showing the leaked bytes is bluff. |
| "reliable exploit" | N-of-M sweep, M ≥ operator-set threshold (default 50), N/M ≥ operator-set ratio (default 0.95), on the same build hash as the finding | reliability-sweep log artifact | REQUIRED | Sweep run on a different build hash than the claim → reject. Sweep with M < threshold → downgrade `reliable` → `usually-works`. |

### 2.2 Reachability claims

| Claim shape | Required evidence | Source artifact / tool | Severity | Adjudicator notes |
|---|---|---|---|---|
| "reachable from network" | Trailmark taint path from a network source (recv/accept/socket APIs) to the vulnerable function, OR a dynamic trace from packet ingress to function entry | Trailmark report or GDB/Frida trace | CRITICAL | "It's a parser, parsers are reachable" is not evidence. Path must be concrete. |
| "reachable from unauthenticated context" | Same as above + auth-check enumeration on the path showing no auth gate, OR exploit run from unauthenticated client | Trailmark + decompilation of all auth checkpoints, OR live exploit | CRITICAL | The hardest reachability claim to satisfy honestly. Most bugs are gated by *something*; the LLM under-counts. |
| "reachable in default config" | Config-loading path traced + default config artifact captured | `analyze_binary` + config file artifact | REQUIRED | If the bug requires a non-default flag, the claim is "reachable when X enabled" not "reachable in default config." |
| "no bounds check" | Decompiled code of the *entire* path from input to vulnerable op, not just the target function | batched decompile of caller chain | REQUIRED | The most common false negative: the model decompiles the function with the bug, sees no check, and concludes there's no check anywhere. The check is often two callers up. |
| "no validation exists" | Explicit `absent` observable with the search method recorded (e.g., "searched callees of `parse_packet`, no `len_check_*` symbol exists") | grep / xrefs / search_pattern log | REQUIRED | Per `01_REASONING_LOOP.md` §6.4 — `absent` is evidence only when search method is recorded. |
| "same pattern as CVE-X" | Side-by-side comparison of the prior pattern (from disclosure or commit) and the candidate pattern, with the matching elements named | comparison artifact (model-produced, evidence-cited) | REQUIRED | The model must cite the *prior* artifact (commit hash, advisory URL) and the *new* code, with the equivalence explicit. "Looks like CVE-X" is not enough. |
| "variant of confirmed bug" | Both the confirmed bug's evidence and the variant's evidence in the graph; equivalence cited | two CONFIRMED_VULNERABILITY nodes + VARIANT_OF edge | RECOMMENDED | Encouraged for variant analysis productivity. Logged as a gap if missing but does not block submit. |

### 2.3 Scoring and impact claims

| Claim shape | Required evidence | Source / tool | Severity | Adjudicator notes |
|---|---|---|---|---|
| "CVSS 9.8" / specific CVSS score | CVSS vector string AND deterministic computation from vector | `cvss_compute(vector)` deterministic call | REQUIRED | The LLM may not assert a CVSS score; it asserts a vector, the engine computes the score. Score-without-vector → reject. |
| "affects versions X–Y" | Tested on at least one version in range AND on first known-good version; commit-bisect or version-bisect artifact if range claimed wide | run_target on multiple versions + artifact log | REQUIRED | Range claim with single-version evidence → downgrade to "tested on X." |
| "fixed in version Z" | Diff of the patch + run_target on Z showing the trigger no longer crashes/exploits | patch diff artifact + post-patch run log | REQUIRED | This is the N-day workflow's central claim. Bisect-without-trigger-rerun → downgrade. |
| "no patch available" / "0-day" | Vendor advisory search log (no advisory found) + commit history scan (no fix commit found) | tool_run artifact citing search method | RECOMMENDED | Logged with caveat; the claim has tail risk (a fix may exist that we haven't seen). |
| "kev-listed" / "exploited in the wild" | KEV catalog query result OR public exploit reference URL with capture date | KEV artifact / web-cache artifact | RECOMMENDED | Sourced from external systems; the workbench should cache the source-of-truth document. |
| "EPSS X" | EPSS API query log | EPSS artifact | RECOMMENDED | Same shape as KEV. |

### 2.4 Process claims

| Claim shape | Required evidence | Source / tool | Severity | Adjudicator notes |
|---|---|---|---|---|
| "we ran the fuzzer for N hours" | Fuzzer log artifact with start/end timestamps and edges/exec count | AFL/libFuzzer/WinAFL log | REQUIRED | Trivially fakeable in prose, trivially verifiable in log. Log absent → reject. |
| "coverage plateau" | Coverage time series with the plateau visible | edges-vs-time series artifact | REQUIRED | "Coverage isn't growing" without the series is unfalsifiable. |
| "harness reaches target" | Coverage report showing the target function in `lcov`/`afl-cov` output OR a direct trace from harness into target | coverage artifact OR trace | CRITICAL | Without this, every fuzz claim is unsupported. |
| "all bug variants enumerated" | Variant search query + result list with each variant either dismissed-with-reason or upgraded to a hypothesis | `search_code` log + per-result disposition | RECOMMENDED | Used in close-out reports to defend "we looked broadly." |

### 2.5 Counted

The taxonomy above contains 28 distinct claim → obligation mappings. The number is a planning artifact, not a target — the rule engine grows as new claim shapes are observed in development. New rows are added by patching the rule registry; the LLM doesn't see the registry, only its effects.

---

## 3. Obligation Lifecycle

An obligation is a node in the evidence graph. Its lifecycle has five named states.

```
                    ┌──────────────────────────┐
                    │                          │
                    │    LLM proposes claim    │
                    │  in ReasoningTurnDecision │
                    │                          │
                    └────────────┬─────────────┘
                                 │ engine reads claim, matches taxonomy
                                 ▼
                    ┌──────────────────────────┐
            ┌──────►│         CREATED          │
            │       │   (ObligationNode in     │
            │       │    evidence graph)       │
            │       └────────────┬─────────────┘
            │                    │
            │                    │ LLM produces matching artifact
            │                    │ (or operator does)
            │                    ▼
            │       ┌──────────────────────────┐
            │       │         TRACKED          │
            │       │ (graph edges to candidate│
            │       │  artifacts; not yet       │
            │       │  validated)              │
            │       └────────────┬─────────────┘
            │                    │ adjudicator validates
            │                    │ artifact actually proves the claim
            │                    │
            │       ┌────────────┼────────────┐
            │       ▼            ▼            ▼
            │   SATISFIED    UNMET         WAIVED
            │       │            │            │
            │       │            │            │ operator decision,
            │       │            │            │ recorded with reason
            │       │            │            │
            │       └────┬───────┴────────────┘
            │            │
            │            ▼
            │       Submit gate evaluates:
            │         - all CRITICAL → SATISFIED or WAIVED
            │         - all REQUIRED → SATISFIED or WAIVED
            │         - RECOMMENDED logged as gaps regardless
            │
            └─── If new evidence invalidates a SATISFIED obligation,
                 it returns to CREATED with a REGRESSED flag.
```

### 3.1 CREATED

When the LLM emits an obligation in `ReasoningTurnDecision.obligations` (per the contract in `01_REASONING_LOOP.md` §3), or when the rules engine derives one implicitly from a high-confidence claim, an `ObligationNode` is added to the project's evidence graph. Schema:

```python
class ObligationNode:
    id: str                             # O-{project}-{seq}
    claim_text: str                     # the LLM's words, verbatim
    claim_category: ClaimCategory       # exploitability | reachability | scoring | process
    canonical_claim: str                # normalized form, e.g. "rce", "aslr_bypass"
    severity: Severity                  # CRITICAL | REQUIRED | RECOMMENDED
    required_evidence: list[EvidenceSpec]
    state: ObligationState              # CREATED | TRACKED | SATISFIED | UNMET | WAIVED
    created_turn: int
    created_by: Literal["llm", "engine", "operator"]
    linked_finding_id: str | None       # if this obligation came from a draft finding
    linked_hypothesis_id: str | None    # if from an active hypothesis
    history: list[ObligationEvent]      # state transitions, immutable
```

`required_evidence` is a list of `EvidenceSpec` records — these are the artifact-class predicates the adjudicator runs. Example for "RCE":

```python
EvidenceSpec(kind="exploit_run_log",
             must_match=ContainsRegex(r"^MARKER: pwned by VR-\w+$"),
             cite_field="poc_artefact_id"),
EvidenceSpec(kind="rop_gadget_verification",
             must_match=AllPresent(claimed_gadgets),
             cite_field="reasoning")
```

Both must validate before the obligation flips to SATISFIED. `must_match` is a small predicate language compiled deterministically.

### 3.2 TRACKED

The LLM (or engine) attaches a candidate artifact via `obligation_satisfied: list[str]` in a subsequent `EvidenceArtifact`. The graph adds edges from the obligation to the artifact. State remains TRACKED until the adjudicator confirms the artifact actually matches the spec.

The split between TRACKED and SATISFIED is intentional: the LLM frequently *attempts* to satisfy obligations with weak evidence ("the strings dump shows the libc base") that doesn't meet the spec ("the spec required a leaked pointer + offset confirmation"). TRACKED is the pending state; SATISFIED is the verified one.

### 3.3 SATISFIED

The adjudicator ran every `EvidenceSpec` against the linked artifact and they all returned true. The obligation flips state. The transition is immutable in `history` — even if the obligation later regresses, the original satisfaction stays in the audit trail.

### 3.4 UNMET

The adjudicator ran the spec and one or more checks failed. The obligation returns to CREATED with a `failed_specs` annotation explaining which check fell over. The next user prompt to the LLM includes this annotation:

```
Obligation O-vr-0042 (claim: "RCE") not satisfied:
  - exploit_run_log: marker regex did not match (saw: "Segmentation fault")
  - rop_gadget_verification: 2 of 11 claimed gadgets not found in ROPgadget output
                             (0x401234, 0x4015a0)
```

The LLM either produces a real artifact or downgrades the claim. It cannot make the obligation go away by re-asserting.

### 3.5 WAIVED

A human operator can mark an obligation WAIVED with a free-text reason. The waiver is a first-class graph node (`WaiverNode`), permanently linked, surfaces in every report, and contains the operator's identity and timestamp. Unblockable downstream.

The product reason for waivers is unblocking the loop when the obligation is structurally unsatisfiable on this target — see §6 — without forcing the LLM to lie. The audit reason is that a waived obligation is *visibly* waived rather than silently elided.

### 3.6 REGRESSION

If new evidence contradicts a SATISFIED obligation (e.g., the reliability sweep was rerun on a fresh build and the success rate dropped), the obligation returns to CREATED with a REGRESSED flag and a pointer to the contradicting evidence. This is rare but catches the case where an exploit "works" on build N and the operator wants to ship the finding against build N+1.

---

## 4. Severity Levels

Three levels. The level controls what the submit gate enforces.

| Level | Submit gate behavior | Examples |
|---|---|---|
| **CRITICAL** | Submit blocked until SATISFIED or WAIVED. Adjudicator forces `confidence ≤ inconclusive` if unsatisfied at submit time. | Mitigation analysis before "exploitable", controlled-write proof for "RCE", auth-path proof for "reachable from unauthenticated", per-mitigation bypass for "modern hardened target." |
| **REQUIRED** | Submit blocked until SATISFIED or WAIVED. Adjudicator forces `confidence ≤ caveated` if unsatisfied. | Reliability sweep for "reliable", version-bisect for "affects X-Y", patch-diff verification for "fixed in Z." |
| **RECOMMENDED** | Submit allowed. Unsatisfied RECOMMENDED obligations are surfaced in the finding's `gaps` field and the operator can choose to upgrade them before publishing. | Variant enumeration, KEV/EPSS lookup, prior-art comparison. |

The level is not the LLM's choice — it's set by the rule that emits the obligation. The LLM can request an upgrade ("this should be CRITICAL because…") but the engine decides.

The line between CRITICAL and REQUIRED is whether the claim is *false* without the evidence (CRITICAL) or *unsupported* without the evidence (REQUIRED). "RCE without controlled-write proof" is a *false* claim — the model is asserting something it has no basis for. "Reliable without sweep" is *unsupported* — the exploit may well be reliable, we just haven't measured.

This distinction matters because a CRITICAL miss is a bug-report-shape error (we said RCE, it's not RCE), while a REQUIRED miss is a confidence-shape error (we said reliable, we don't know yet).

---

## 5. The Adjudication Rules Engine

The engine runs after every LLM turn, before the engine prepares the next user prompt. It is deterministic, stateless across turns (reads the graph fresh each time), and never calls the LLM. Rule output is written back to the graph and surfaced to the LLM in the next prompt.

### 5.1 Rule categories

Five rule categories run in fixed order. Earlier categories can short-circuit later ones.

```
1. Contradiction detection         → may force confidence=inconclusive
2. Uncertainty language detection  → may force action=reasoning next turn
3. State transition gating         → may reject turn outright
4. Obligation satisfaction         → updates obligation states
5. Submit-gate evaluation          → only on action=submit; allow or reject
```

### 5.2 Pseudocode

```python
def adjudicate(turn: ReasoningTurnDecision,
               state: VRCaseState,
               graph: EvidenceGraph,
               project: VRProject) -> AdjudicationResult:

    findings = []  # rule violations
    new_obligations = []
    obligation_updates = {}

    # ─────────────────────────────────────────────
    # 1. CONTRADICTION DETECTION
    # ─────────────────────────────────────────────
    for claim in extract_claims(turn):
        for prior in graph.evidence_artifacts(linked_to=claim.target):
            if contradicts(claim, prior):
                findings.append(Contradiction(
                    claim=claim,
                    contradicted_by=prior.id,
                    severity="block"))

        # Bug-class consistency: if claim says "heap" and ASAN says "stack",
        # it's a contradiction even if both are recent.
        if claim.bug_class:
            asan_reports = graph.artifacts(kind="asan_report", target=claim.target)
            for report in asan_reports:
                detected = parse_asan_bug_class(report)
                if detected and detected != claim.bug_class:
                    findings.append(Contradiction(
                        claim=claim,
                        contradicted_by=report.id,
                        message=f"claim says {claim.bug_class}, ASAN says {detected}"))

    # ─────────────────────────────────────────────
    # 2. UNCERTAINTY LANGUAGE DETECTION
    # ─────────────────────────────────────────────
    HEDGES = {"might", "could", "possibly", "perhaps", "in theory",
              "should be", "seems to", "appears to", "likely",
              "probably", "i think", "i believe"}
    for claim in extract_claims(turn):
        if claim.confidence in {"strong", "exact"}:
            hedges_in_text = [h for h in HEDGES if h in claim.text.lower()]
            if hedges_in_text:
                findings.append(UncertaintyLaundering(
                    claim=claim,
                    hedges=hedges_in_text,
                    forced_action="reasoning"))

    # Hedges in the reasoning section are fine; hedges in claims with
    # confidence >= medium are flagged.

    # ─────────────────────────────────────────────
    # 3. STATE TRANSITION GATING
    # ─────────────────────────────────────────────
    for claim in extract_claims(turn):
        prior_verdict = state.verdict_for(claim.target)

        # not-exploitable → exploitable requires NEW evidence since prior verdict
        if prior_verdict == "not_exploitable" and claim.exploitable:
            new_evidence = graph.evidence_artifacts(
                linked_to=claim.target,
                created_after=prior_verdict.turn)
            if not new_evidence:
                findings.append(InvalidStateTransition(
                    claim=claim,
                    from_state="not_exploitable",
                    to_state="exploitable",
                    reason="no new evidence since prior verdict"))

        # exploit-fails → exploit-works requires both a code change AND a passing run
        if prior_verdict == "exploit_fails" and claim.exploit_works:
            had_code_change = any(a.kind == "exploit_code_revision"
                                  for a in graph.artifacts(linked_to=claim.target,
                                                           created_after=prior_verdict.turn))
            had_passing_run = any(a.kind == "exploit_run_log" and a.exit_status == "marker_hit"
                                  for a in graph.artifacts(linked_to=claim.target,
                                                           created_after=prior_verdict.turn))
            if not (had_code_change and had_passing_run):
                findings.append(InvalidStateTransition(
                    claim=claim,
                    reason="exploit-works requires code change + successful run since prior fail"))

        # unreliable → reliable requires fresh sweep on current build hash
        if prior_verdict == "unreliable" and claim.reliable:
            sweep = graph.latest_artifact(kind="reliability_sweep_log",
                                          linked_to=claim.target)
            if not sweep or sweep.build_hash != project.current_build_hash:
                findings.append(InvalidStateTransition(...))

    # ─────────────────────────────────────────────
    # 4. OBLIGATION SATISFACTION
    # ─────────────────────────────────────────────
    # 4a. Register new obligations from claims in this turn
    for claim in extract_claims(turn):
        for spec in obligation_specs_for(claim, project.target_context):
            ob = ObligationNode(
                claim_text=claim.text,
                canonical_claim=spec.canonical,
                severity=spec.severity,
                required_evidence=spec.evidence_specs,
                state="CREATED",
                created_turn=turn.idx,
                created_by="engine",
                linked_finding_id=claim.draft_finding_id,
                linked_hypothesis_id=claim.hypothesis_id)
            new_obligations.append(ob)

    # 4b. Re-evaluate existing obligations against the updated artifact set
    for ob in graph.obligations(state__in={"CREATED", "TRACKED"}):
        candidates = graph.linked_artifacts(ob)
        if not candidates:
            continue
        results = [validate_spec(spec, cand)
                   for spec in ob.required_evidence
                   for cand in candidates]
        if all(r.passed for r in results):
            obligation_updates[ob.id] = ("SATISFIED", results)
        elif any(r.evaluated for r in results):
            obligation_updates[ob.id] = ("UNMET", results)

    # 4c. Detect missing obligations on existing high-confidence claims
    for finding in state.draft_findings:
        if finding.confidence in {"strong", "exact"}:
            specs = required_specs_for_finding(finding, project.target_context)
            for spec in specs:
                if not any(ob.canonical_claim == spec.canonical
                           for ob in graph.obligations(linked_finding_id=finding.id)):
                    findings.append(MissingObligation(
                        finding=finding.id,
                        claim=spec.canonical,
                        severity=spec.severity))

    # ─────────────────────────────────────────────
    # 5. DUPLICATE HYPOTHESIS PREVENTION
    # ─────────────────────────────────────────────
    for h in turn.hypotheses:
        if h.id in {existing.id for existing in state.hypotheses}:
            continue  # same id, allowed
        for rejected in state.rejected:
            sim = embedding_cosine(h.claim, rejected.claim)
            if sim >= 0.85:
                findings.append(DuplicateHypothesis(
                    new_id=h.id,
                    similar_to=rejected.id,
                    similarity=sim,
                    action="fold_into_rejected"))

    # ─────────────────────────────────────────────
    # 6. SUBMIT-GATE EVALUATION (only on action=submit)
    # ─────────────────────────────────────────────
    if turn.vr_action.kind == "submit":
        finding = turn.vr_action.params.finding
        relevant_obs = graph.obligations(linked_finding_id=finding.id)

        unsatisfied_critical = [o for o in relevant_obs
                                if o.severity == "CRITICAL"
                                and o.state not in {"SATISFIED", "WAIVED"}]
        unsatisfied_required = [o for o in relevant_obs
                                if o.severity == "REQUIRED"
                                and o.state not in {"SATISFIED", "WAIVED"}]

        if unsatisfied_critical:
            findings.append(SubmitBlocked(
                level="CRITICAL",
                obligations=[o.id for o in unsatisfied_critical]))
        elif unsatisfied_required:
            # Allow submit but force confidence cap
            findings.append(ConfidenceDowngrade(
                from_=finding.confidence,
                to="caveated",
                reason="unsatisfied REQUIRED obligations",
                obligations=[o.id for o in unsatisfied_required]))

        # RECOMMENDED obligations attach as gaps but don't block
        unsatisfied_recommended = [o for o in relevant_obs
                                   if o.severity == "RECOMMENDED"
                                   and o.state != "SATISFIED"]
        if unsatisfied_recommended:
            finding.gaps = [o.canonical_claim for o in unsatisfied_recommended]

    return AdjudicationResult(
        findings=findings,
        new_obligations=new_obligations,
        obligation_updates=obligation_updates,
        action_decision=decide(findings))
```

### 5.3 Rule outcomes

`decide(findings)` collapses rule findings into one of:

- **`accept`**: turn proceeds, obligations updated, next prompt prepared normally.
- **`accept_with_caveats`**: turn proceeds but next prompt prefixes the rule output (e.g., "your claim contained 3 hedge words; consider downgrading confidence").
- **`force_reasoning`**: the LLM's chosen action is rejected; next turn is forced to `kind="reasoning"` with the rule findings as input. This is the most common non-accept outcome — the LLM tried to act on a confabulation and the engine bounced it.
- **`reject_submit`**: only on submit. The finding is not persisted; the LLM is told why and continues.
- **`escalate_to_operator`**: same rule has fired ≥3 times in a session, or the rule output indicates a structural problem the LLM can't resolve (e.g., contradictory ASAN reports). The workflow pauses; operator sees the rule trace and decides.

### 5.4 What the rule engine cannot do

It cannot judge *correctness* of claims that aren't verifiable from the evidence graph. It can detect bluffs but it cannot detect *correct claims with insufficient evidence*. The latter is by design — the system errs on the side of forcing more evidence collection rather than accepting under-justified claims.

It also cannot detect cleverly-worded bluffs that don't trip the regex/embedding heuristics. A model that says "the controlled write is established by the trace" without producing a trace will be caught by `MissingObligation`. A model that says "trace artifact T-042 establishes the controlled write" referring to a real T-042 that doesn't actually establish that — that requires the spec validator to actually parse T-042 and check. This is the §6.4 case below.

---

## 6. Edge Cases

The rule system is clean in the abstract. The hard cases are at the seams.

### 6.1 Right answer, evidence dropped from the bounded pack

The bounded evidence pack (per `01_REASONING_LOOP.md` §6) excludes older evidence to fit the context window. The LLM may correctly remember from earlier turns that "checksec ran and the binary has no NX," but the checksec artifact has rolled out of the pack. The model's claim is correct; the rule engine doesn't see the artifact in the immediate context and might raise `MissingObligation`.

**The mechanism doesn't make this mistake.** The rule engine reads the *full* evidence graph, not the bounded pack. The pack is for the LLM's reasoning context; the graph is for the adjudicator. As long as the artifact exists in the graph and is linked to the obligation (via `obligation_satisfied` from a prior turn), the obligation stays SATISFIED regardless of whether the artifact is in the current pack.

The LLM does need to *cite* the artifact id in `provenance.primary_artifact` or `provenance.corroboration` on submit, even if the artifact is not in the current pack. The engine validates the citation against the graph, not against the pack. The model knows artifact ids from the running case-model summary.

The failure mode here is the LLM forgetting the artifact id (it's been many turns; the id wasn't included in the case-model summary). Mitigation: critical artifact ids are always pinned into the case model, not the rolling pack. The case model is small enough that pinning a dozen artifact ids is cheap.

### 6.2 Obligation requires a tool that's not available

Example: target is a Windows kernel driver. The "exploitable → mitigations enumerated" obligation includes `analyze_binary` returning a CFI/CET/CFG/CFG-strict matrix. `checksec` is Linux-only. `analyze_binary` falls back to Windows-equivalent (PE characteristics flags, /GUARD:CF, /CETCOMPAT). But suppose the target is a niche embedded RTOS where neither checksec nor a PE-style mitigation report is meaningful.

**Three options, in order of preference:**

1. **Backend-aware obligation specs.** The MCP advertises which evidence kinds are available for the current target (per `02_IDA_HEADLESS_MCP.md` §10). The obligation spec is parameterized on backend capabilities. For RTOS, the mitigation evidence becomes "manual mitigation analysis artifact authored by operator" — a different artifact class with the same role.

2. **Operator waiver with technical justification.** The operator inspects the target manually, writes a `MitigationAnalysisArtifact` by hand, and uploads it. This is the artifact class the obligation expects; it's just human-produced. The rule engine doesn't care who authored it.

3. **Project-level capability declaration.** The project's `target_context` has a `mitigation_set: explicit` field. When set, the LLM enumerates mitigations from this field instead of from a tool call, and the obligation reads `target_context.mitigation_set` as evidence. This is the operator saying "I've inspected the target; here's the mitigation set; the LLM should reason against this."

The pattern: **obligations don't require a specific tool. They require an artifact class that satisfies a spec.** The artifact's provenance (tool, operator, hand-written) is metadata; the rule engine validates the artifact contents.

What is *not* allowed: silently dropping an obligation because the standard tool doesn't exist. That's the bluff path — "we couldn't run checksec so we'll just claim no NX." The waiver path forces the operator to *explicitly* take responsibility for the assertion, with timestamp and reason in the audit trail.

### 6.3 Operator disagrees with an obligation

The operator is a senior researcher; they sometimes know things the obligation system doesn't. "I've been writing exploits for this allocator for 10 years; the heap-state oracle obligation is overkill for this trivial UAF." The obligation system should yield to operator expertise without being undermined by it.

**The mechanism is the WAIVED state.** The operator clicks "waive" on the obligation, types a reason, and the obligation flips. The audit trail shows:

```
ObligationEvent {
    obligation_id: "O-vr-0084",
    transition: "CREATED -> WAIVED",
    actor: "operator:rkim",
    timestamp: 2026-04-12T14:23:11Z,
    reason: "tcache layout is irrelevant here; the UAF reuses an
             input-allocated chunk in the same arena. See ../notes/2026-04-12-tcache.md"
}
```

The waiver propagates: the finding can submit, but the report carries a `waivers` section listing every waived obligation with the reason. A consumer of the finding (vendor PSIRT, CVE issuer, customer) sees what was waived and decides whether to trust the operator's judgement.

What the operator *cannot* do: edit the rule registry to make obligations not fire. The rule registry is project-shared and version-controlled; rule changes need a code review. Per-finding waivers are operator-scoped; rule changes are platform-scoped. Different review path.

The risk this creates: a busy operator waiving obligations as a way to silence the loop. Mitigation: a "waiver rate" metric on the operator-overview UI. If waiver rate exceeds (say) 20% of created CRITICAL obligations across a project, the platform raises a soft warning. Not blocking — operators have legitimate reasons for high waiver rates on certain target types — but visible.

### 6.4 The LLM fabricates evidence

The hardest case. The LLM claims "ASAN report A-072 shows heap-buffer-overflow at parse_packet+0x140." The artifact A-072 *exists* in the graph. The model wrote `obligation_satisfied: ["O-0042"]` referencing it. The obligation flips TRACKED. The adjudicator runs `validate_spec(EvidenceSpec(must_match=ContainsRegex(r"heap-buffer-overflow")), A-072)`. The regex matches. SATISFIED.

Except A-072 is the ASAN log from a *different* run, on a *different* binary, that just happens to contain "heap-buffer-overflow" at a different offset. The model has reused an unrelated artifact to satisfy this obligation.

**This is the failure mode where the rule engine is structurally weakest.** The engine validates *content*; it does not validate *causation* (did this artifact actually arise from running the trigger that the claim describes?).

Three layers of mitigation, none perfect:

1. **Provenance binding.** Every artifact in the graph has a provenance record: the action that produced it, the inputs, the timestamps, the tool's invocation arguments. `EvidenceSpec` can require `provenance.command` to match a pattern (e.g., the ASAN run's argv must include the trigger input file referenced in the claim). The rule engine checks this. Forcing the LLM to cite an artifact whose provenance matches the claim raises the bar.

2. **Linkage requirements.** An artifact alone doesn't satisfy an obligation; the *link* between the artifact and the claim's hypothesis must be stated. The LLM has to write "A-072 (run on input I-019, which is the trigger from H-03)" not "A-072 shows the bug." If the linkage chain is broken — A-072 was run on input I-014, not I-019 — the rule engine sees the discrepancy and the obligation goes UNMET.

3. **Tool-side ground truth.** The IDA MCP and the run_target tool both record exactly what they ran, when, and against what binary. The rule engine cross-references the LLM's cited provenance against the tool's ground-truth log. If the LLM cites "A-072 from running ./target with input I-019" and the tool log says A-072 was produced by running ./target_v2 with input I-014, the rule engine raises a `ProvenanceMismatch` finding. CRITICAL severity, blocks submit, escalates to operator.

The tool-side ground-truth check is the most reliable. The audit log lives outside the project root (`/vr/audit/`), is append-only, and is what `02_IDA_HEADLESS_MCP.md` §10 calls "auditable provenance." The rule engine treats the audit log as canonical and the LLM's `reasoning` text as a claim *about* the audit log.

What survives all three layers: an LLM that fabricates a hypothetical ID for an artifact that doesn't exist. That's the cheap case — the engine just looks up the ID in the graph and finds nothing. Caught at TRACKED time.

What doesn't survive: an LLM that cites a real artifact that doesn't actually pertain to the claim *and* invents matching provenance fields. This would require the model to lie about the audit log entries, which it can do in `reasoning` text, but the rule engine reads the audit log directly, not the model's summary of it. The model can't actually rewrite the audit log.

The residual risk: a deeply confused model citing the wrong artifact id without intent to deceive. The provenance check catches it; the failure mode is mistaken-identity, not lying. The operator-facing language in such cases should be "the cited artifact does not match the claimed scenario" rather than "the model fabricated evidence" — the latter implies intent we have no way to attribute.

### 6.5 Obligation chains and their failure modes

Some obligations depend on others. "ASLR bypassed" depends on "info leak demonstrated." "Reliable exploit" depends on "exploit works." The dependency graph is small but it has to be evaluated correctly.

The rule engine treats this as ordinary graph traversal: when obligation O-A depends on O-B, O-A cannot be SATISFIED unless O-B is SATISFIED. If O-B regresses (REGRESSED state), O-A regresses with it. This is the same propagation `04_MULTI_TARGET.md` §6 describes for project-level chains.

The failure mode: **operator waives the prerequisite to unblock the loop, and the dependent obligation is auto-satisfied through the waiver propagation.** The operator wanted to skip the heap analysis; they didn't intend to also retroactively bless the "reliable exploit" claim that depends on it. The mechanism to prevent this is **non-propagating waivers**: a waiver waives one obligation only; dependents must be independently waived. The UI shows the dependency chain so operators see the cascade.

---

## 7. Where the Obligation System Lives in the Code

For grounding the design in the actual repo:

- **Spec registry**: `src/aila/modules/vulnerability/services/obligation_specs.py` — maps canonical claims to `EvidenceSpec` lists. Plain-data, version-controlled, tested with golden examples.
- **Rule engine**: `src/aila/modules/vulnerability/adjudication/` — runs after every turn. Pure functions over `(turn, state, graph, project) -> AdjudicationResult`. No LLM calls. Heavily tested.
- **Obligation graph**: a SQLModel table (`ObligationRecord`) plus helpers; lives alongside the rest of the evidence graph schema in `src/aila/storage/`.
- **Waiver UI**: a panel in the VR frontend (`frontend/src/modules/vulnerability/`) that surfaces obligations with state, severity, linked artifacts, and a "waive" button with required reason text.
- **Audit log**: per `02_IDA_HEADLESS_MCP.md` §10, lives outside project root in `/vr/audit/`. Append-only. Read by the rule engine for provenance binding.

No part of this lives in `aila.platform.*`. The obligation system is VR-specific. The forensics module has its own evidence semantics; copying the rule engine across modules would be premature. If a third module needs the same shape, the abstraction goes into `platform/services/adjudication/` and both modules consume it. Until then, it's a VR concern.

---

## 8. What the LLM Sees

The LLM never sees the rule engine, the obligation registry, or the rule code. It sees:

- The current obligations linked to its draft finding (in the user prompt's case-model summary).
- The state of each obligation (CREATED / TRACKED / SATISFIED / UNMET / WAIVED).
- The `failed_specs` annotation when an obligation is UNMET, in plain language.
- Adjudication findings from the previous turn ("submit rejected: missing PoC artefact").

What it *doesn't* see:

- The rule pseudocode.
- The full registry of canonical claims.
- The list of artifact classes the spec is checking.

This asymmetry is intentional. The LLM should be solving "how do I prove this claim" in domain terms, not "how do I make the rule engine accept my output." Exposing the rule code optimizes the LLM toward the rules, which is a good way to silently train against the audit layer.

---

## 9. Failure Modes of the System Itself

Cataloguing where the obligation system can be wrong, not just the LLM.

**False positives (rule engine flags a valid claim):**
- Hedge-word detection over-triggers on legitimate technical caveats ("the bug appears to be a UAF" is precise hedging, not laundering). Mitigation: confidence-aware regex — the same hedge in `reasoning` is fine; in a `confidence=strong` claim it's flagged.
- Contradiction detection misreads ASAN output (an ASAN report of "container-overflow" gets parsed as "stack-buffer-overflow" by a sloppy parser, contradicting a correct heap claim). Mitigation: the parser is a small, audited piece of code with golden tests.
- State-transition gating fires on legitimate verdict reversals where the operator added new evidence offline and the loop didn't see the source. Mitigation: operator-added artifacts carry the operator's identity, and state transitions backed by operator artifacts are accepted.

**False negatives (rule engine misses a real bluff):**
- Cleverly-worded claims that don't trip any heuristic ("the trace establishes the primitive" — no hedge, no missing artifact, but the trace doesn't actually establish anything). Mitigation: spec validators that parse artifact contents, not just metadata. The cost of writing a good spec is high; coverage will start partial and grow.
- Reused artifacts across unrelated claims (§6.4). Mitigated by provenance binding, not perfectly.
- Off-by-one obligation scope: the rule engine requires evidence for "RCE" but accepts the same evidence for two distinct RCE claims in the project, when only the first one was actually demonstrated. Mitigation: obligations are linked to specific finding ids; the same artifact can satisfy multiple obligations only if its provenance covers each claim's scope.

**Operational failures:**
- Rule changes during a long-running project invalidate prior SATISFIED obligations. Mitigation: project-pinned rule version. Rule updates apply to new projects; existing projects keep their pinned version unless the operator explicitly migrates.
- Rule engine bug suppresses real findings. Mitigation: the rule engine has its own test suite with adversarial cases (LLM transcripts that historically tried to bluff) as regression fixtures.
- Audit log corruption (disk full, write race). Mitigation: append-only file, fsync on every write, daily integrity check. If integrity fails, the affected project is marked `audit_compromised` and submit is blocked across the board for that project until the operator triages.

---

## 10. What the Obligation System Doesn't Do

A short list of things the system is *not* responsible for:

- **It doesn't grade exploit quality.** Reliability sweep is part of the obligations for the "reliable" claim; whether the resulting exploit is *good* (clean, portable, OPSEC-aware) is an operator/reviewer concern.
- **It doesn't decide what to research.** Strategy selection (`01_REASONING_LOOP.md` §5) is the LLM's call, with engine-derived suggestions. The obligation system acts on output, not on direction.
- **It doesn't replace human review.** A finding that passes adjudication is not yet a CVE submission. The operator reviews the finding, the evidence pack, and the waivers list before publishing.
- **It doesn't enforce ethics.** "Should this exploit be developed?" is a separate policy concern. The rule engine treats every project as authorized; authorization is a workflow-level check at project creation.

---

## 11. Open Questions

1. **Rule registry granularity.** Should obligations be per-claim (current design) or per-finding (one composite obligation per finding that aggregates sub-claims)? Per-claim is more granular and easier to satisfy incrementally; per-finding is closer to what consumers actually want to read. Reporting may want a per-finding view *over* a per-claim representation.

2. **Spec language expressiveness.** `EvidenceSpec` is a small predicate language. Does it stay small (regex + a few primitives) or grow (Cedar/Rego/CEL-style)? The temptation is to grow; the cost is that complex policy languages become unauditable. Probably stays small with explicit Python escape hatches for the rare hard case.

3. **Cross-project obligation reuse.** A vendor's platform mitigation (e.g., "this product family always has CFI on") is a project-pinned fact. Should it be a shared knowledge file the obligation engine reads, or duplicated per project? Sharing is cheaper but creates a bleed surface where one bad fact poisons many projects.

4. **Time-bounded obligations.** Some claims age out — "no patch available" is true on the day of the search but may be false a week later. Should obligations have a `valid_until` field that triggers re-verification on age? Or does this belong in a separate "claim freshness" layer? Probably the latter.

5. **Obligation back-pressure.** The rule engine doesn't currently surface "your finding has 14 outstanding REQUIRED obligations; consider scoping down" before the LLM hits submit. Should it? Pre-submit guidance is helpful; over-supplying it makes the loop noisy. Where's the threshold (5 outstanding obligations? 10? after N turns of growth?)?

6. **Inter-rater agreement on canonical claims.** Two different LLMs reading the same evidence may produce different canonical claims ("RCE" vs "remote code execution" vs "arbitrary code execution"). The canonical-claim normalizer is a small map; how do we keep it complete as the LLM's vocabulary drifts across model versions?

7. **Auto-waivable RECOMMENDED obligations.** Some RECOMMENDED obligations (KEV lookup, EPSS query) are pure data fetches. The engine could auto-fulfil them by running the lookup itself rather than waiting for the LLM to. This blurs the line between "obligation" and "automatic enrichment." Likely correct for low-cost automatic lookups; needs a clear list of what the engine fulfils unilaterally.

8. **Severity inflation.** The temptation, when a bluff slips through, is to re-classify the relevant obligation from REQUIRED to CRITICAL. If we do this every time, eventually everything is CRITICAL and the gradient is meaningless. What's the policy for severity changes? Probably: a one-time event (this specific bluff) is a CRITICAL annotation on the rule's history, not a severity change to the rule itself.

9. **Obligation-driven prompt construction.** Does the user prompt to the LLM include a "to advance, you need to satisfy obligation O-X by producing evidence Y" hint, or is that too directive (steers the model toward gaming the rule)? Currently designed as visible-but-not-prescriptive — the LLM sees outstanding obligations and is told what artifact class is needed, but is not given the spec details.

10. **Multi-operator waiver workflows.** A waiver by a junior operator is different from one by a senior. Do we want approval workflows on waivers (junior proposes, senior approves), or is the operator-identity stamp enough for downstream consumers to weight? Approval workflows add latency; identity stamps add ambiguity ("how senior is rkim?"). Probably project-policy-configurable.

11. **Negative obligations.** Currently, obligations are "evidence X must exist." Some claims need "evidence X must *not* exist" — e.g., "no auth check on the path" requires demonstrating absence. Per `01_REASONING_LOOP.md` §6.4, absence is encoded as `absent` observables with explicit search method. Should `absent` observables themselves carry obligations (to verify the search method actually ran)? That's an obligation-on-obligation, which is fine in the schema but worth thinking through before it shows up.

12. **Performance.** The rule engine runs after every turn. On a project with thousands of artifacts and hundreds of obligations, each turn re-evaluates a non-trivial graph. At what scale do we need to cache spec validation results, and what invalidates the cache? Artifact provenance is immutable, so a SATISFIED obligation can be cached as long as its linked artifacts don't gain new contradicting evidence. Probably fine for v0.1; revisit at v0.2.

These do not need answers before the obligation system is implemented. They need answers before the system is exposed to a second module or to external users.
