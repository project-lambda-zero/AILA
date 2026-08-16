# platform/llm

Async LLM client, routing, cost/drift accounting, sanitization, evidence
validation, seals, and pipeline glue. Every call in the codebase goes through
`AilaLLMClient` (see `__init__.py` for the public surface).

This README is deliberately narrow: it captures traps and design constraints
that are not obvious from reading the code, so future changes do not silently
regress LLM behavior.

## Cross-branch KV-cache reuse fragility (pre-vLLM/SGLang guard)

**Scope.** This section governs any future rollout of self-hosted LLM serving
with automatic prefix caching (vLLM, SGLang, TensorRT-LLM, or equivalent). It
does not affect the current OpenRouter path, which does not expose
prefix-cache reuse across independent requests.

**The trap.** Sibling branches in a debate/critic/judge workflow deliberately
share a long common prefix -- system prompt, task description, evidence
fences, prior turns -- and differ only in the per-candidate segment
(candidate hypothesis, per-branch scratchpad, per-branch tool observations).
A prefix cache with naive block-level reuse will reuse the shared KV blocks
across sibling requests. The judge's next-token distribution over "prefer A
vs prefer B" then conditions on KV blocks that were computed against a
different candidate's downstream context, and the judge's ability to
discriminate between siblings degrades measurably. This is a silent quality
regression: latency drops, cost drops, verdicts still look well-formed, and
the loss shows up only in judge reliability (agreement with a full-recompute
baseline, calibration, and rank stability across seeds).

**Why the naive fix is not enough.** Fully disabling prefix caching for
judge/critic prompts recovers correctness but discards the throughput win
that motivated the rollout. CacheBlend and similar selective-recompute
schemes recompute the cross-candidate segment while keeping the earlier
shared prefix cached; they trade a bounded compute cost for the correctness
gap, but they have their own failure modes (recompute window sized wrong,
attention-sink tokens misidentified, position-id drift when the retained
prefix is not a strict left-substring of the full context).

**References.**
- Cross-branch KV-cache reuse degrades LLM judge reliability: arXiv 2601.08343
  (https://arxiv.org/pdf/2601.08343).
- CacheBlend selective-recompute for shared-prefix serving:
  https://arxiv.org/abs/2405.16444.

**Pre-rollout guard (blocking).** Before any vLLM/SGLang/self-hosted-serving
adoption lands, a regression benchmark MUST be added to `platform/eval/` that:

1. Runs a fixed judge/critic scenario suite with N >= 3 sibling candidates
   per task, over a stable seed set.
2. Produces two verdict distributions -- one with prefix reuse disabled
   (baseline), one with the target serving stack's prefix caching enabled
   with production settings.
3. Compares the distributions on judge agreement rate, rank-stability across
   seeds, and per-candidate score calibration.
4. Fails the rollout if any of those metrics regress beyond a documented
   parity threshold. If a selective-recompute mode (CacheBlend or vendor
   equivalent) is used, it is a separate arm and must also clear parity.

The benchmark itself is intentionally deferred: it exists as an RFC guard
(see issue #162) until a self-hosted serving path is on the roadmap, at
which point it becomes a merge blocker on the rollout PR, not a follow-up.

**Reviewer checklist for any future PR that enables prefix caching.**

- [ ] The parity benchmark above is present, runnable, and green.
- [ ] Judge/critic prompts either bypass prefix caching or route through a
      selective-recompute mode whose parity is proven in the benchmark.
- [ ] The rollout is gated behind a `ConfigRegistry` flag defaulting to OFF
      (behavior-preserving), with the flag documented in
      `PlatformConfigSchema`.
- [ ] Operator-facing docs state which prompt classes bypass prefix caching
      and why, so a later change does not quietly flip judge prompts into
      the reused-prefix path.
