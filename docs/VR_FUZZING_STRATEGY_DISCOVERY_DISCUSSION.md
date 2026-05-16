# VR Fuzzing — Strategy Discovery Multi-Turn Discussion

## Purpose

This document is a multi-turn discussion that **models the strategy-discovery process used in the 2026-05-15 V8MapInferenceProfile session**. It is designed to be FED BACK to AILA as planning input for finding strategies against other targets (other JS engines, kernel components, WASM runtimes, etc.).

Each topic captures a real pivot from the session: a naive starting position, adversarial pushback from senior researchers, evidence-gathering, and a consensus decision. Each topic ends with an **AILA Replay Protocol** — a template AILA can execute when hunting strategies for a NEW target.

The discussion is interruptible at any topic. When AILA reaches a topic that does NOT apply (e.g., "we're targeting kernel, not JS engine"), it skips. When AILA needs to gather data (e.g., "what CVEs exist for target X?"), it pauses and queries first.

## Personas (continued from VR_STAFF_RESEARCHER_DISCUSSION.md)

- **S1: Halvar** — Staff Exploit Engineer. Demands PoCs and primitives, not theories.
- **S2: Maddie** — Staff Binary Analysis. Reads patches, knows what diffs hide.
- **S3: Yuki** — Staff Fuzzing Engineer. Runs syzkaller fleets, opinions on triage at scale.
- **S4: Renzo** — Staff Web/App Security. Source-level mindset.
- **S5: Noor** — Staff Mitigation/Defense. Evaluates exploit feasibility against hardened deployments.

Plus one new persona introduced this session:

- **S6: Wei** — Staff Compiler Engineer (added 2026-05-15). 12 years building JIT optimizers (V8/Hermes/JSC). Speaks fluent SSA, sea-of-nodes, and tier transitions. Has a binder full of "compilers I have broken" stories. Says most fuzzing of JIT compilers misses the point because fuzzers don't model IR-level invariants — they just mash JS source and hope.

---

## Topic 1: Should We Run Stock Fuzzer Profiles, or Write Custom?

**Halvar:** The first question for ANY new target. Stock fuzzers exist for a reason. Google's team has been running FUZZILLI's v8 + v8Sandbox profiles continuously for years on dedicated fleets. Running them on a workstation for 72h is pure ego. You won't outperform their fleet by running the same code with less hardware.

**Yuki:** Disagree partially. Stock profiles cover the WELL-KNOWN attack surface. They're tuned by the maintainer's hypothesis of "what bugs look like." If the maintainer's hypothesis lags reality (e.g., new compiler tier shipped without new generators), the stock profile under-covers it. There's always a window between "feature ships" and "fuzzer learns to attack it."

**Wei:** Both right, but the gap is more specific than "new tier shipped." It's: **stock profiles attack the JS surface; they do NOT model COMPILER IR invariants**. When V8 ships a new IR node (`TransitionElementsKindOrCheckMap` from CVE-2025-2135's commit `b8d3f7d0cf`), stock generators don't immediately exercise the IR-level dataflow that exposes its bugs. Custom generators that target SPECIFIC IR-level invariant violations have months of head-start before stock catches up.

**Maddie:** The TEST is: pull every CVE in the target component for the last 12 months. Classify by bug class. If >30% are clustered in ONE bug class, that class is under-fuzzed by stock and worth custom. If they're scattered, stock is probably catching what it can and custom won't help.

**Noor:** Adding: even when custom is justified, custom-without-data is worse than stock. The strategy MUST be derivable from CVE patches. "I had an idea" is not a strategy. "CVE-2026-3910 fixed Phi untagging at file X line Y; the bug class hits this specific code path; here's a generator that produces input matching the pre-fix pattern" — that's a strategy.

### Consensus

- **Run stock profiles ALWAYS as baseline.** They have 0% marginal cost (already built) and catch what they catch.
- **Add custom profile only when CVE clustering data justifies it.** Threshold: 3+ CVEs in last 12mo with same root-cause class.
- **Custom generators MUST cite specific CVE patches.** Each generator has a `cve_targets` list. No "creative" generators without lineage to a real bug.
- **Re-evaluate quarterly.** When stock catches up to the pattern (FUZZILLI maintainer adds a generator that covers our area), retire the custom one or downgrade its weight.

### AILA Replay Protocol — "Should we go custom for target X?"

1. Pull last 12 months of CVE data for target X (source: vendor advisories, NVD, vendor commit log filtered for "Security:" or CVE references).
2. Classify each CVE by ROOT CAUSE (not by impact — root cause). Common classes: type confusion in JIT, memory safety in C++ component, logic bug in dispatch, race in concurrent code.
3. If top class has ≥3 CVEs AND ≥30% share → custom is justified.
4. If no class dominates → stick with stock + tune throughput.
5. Capture the analysis in `data/strategies/_evidence/<target>_cve_cluster_<YYYY-MM>.md` so AILA can revisit when classes shift.

---

## Topic 2: Is "I Have Arbitrary Read/Write" An Attack?

**Halvar:** We had to spend 4 messages this session arguing this. Some people thought because the FUZZILLI sandbox-testing API gives a `MemoryView` of the sandbox cage, calling it gives you "an attack." It does not.

**Wei:** Correct. The V8 sandbox threat model is EXPLICITLY: "given full in-sandbox arbitrary read/write, prevent out-of-sandbox effects." The `Sandbox.MemoryView` API SIMULATES the assumed attacker state. Hunting bugs that escape FROM that state is the whole point of the v8Sandbox profile. But the simulation itself is not the attack.

**Maddie:** Same fallacy at OS level. "I have ring-3 arb r/w" is the assumed starting state for kernel exploitation. Sandbox testing APIs (KASAN's `kmemleak`, etc.) provide that state for the fuzzer; they don't BE the exploit. People newly entering this space confuse the test scaffold with the attack.

**Yuki:** Practical: when triaging a fuzz crash, the first question is "what does this give the attacker that they didn't have before?" If the answer is "in-sandbox arb r/w" and the target's threat model already grants that, the bug is hardening — file it, downgrade priority. If the answer is "this writes outside the sandbox cage" or "this gets code execution on the host OS," that's the actual bug.

**Noor:** I want to add the corollary: **anti-attacks are still useful for chains.** In-sandbox arb r/w + a SEPARATE bug (compiler typer mistake) = real escape. The arb r/w primitive is a precondition for many chains, just not the final link. The strategy implication: hunting in-sandbox primitives is worthwhile IF we have a confirmed final-link bug to chain with. Otherwise hunt the final link directly.

**Renzo:** For web bugs, the equivalent: "I can XSS" is an attack only if the target's threat model assumes the attacker CAN'T inject script. If the page is a sandboxed `srcdoc` iframe and the threat model permits attacker script there, your XSS is in-scope-already.

### Consensus

- **Distinguish three states explicitly in strategy design:**
  - `assumed_attacker_state` — what the target's threat model grants (in-sandbox r/w, network access, etc.)
  - `attack_primitive` — what THIS strategy aims to gain (out-of-sandbox r/w, code exec, info leak across origin, etc.)
  - `chain_position` — where this primitive fits (initial, intermediate, final)
- **Reject strategies whose `attack_primitive` is already in `assumed_attacker_state`.** Those are hardening efforts, not exploit research. File separately.
- **For each strategy, document the chain explicitly.** If the strategy produces an intermediate primitive, the doc must name the OTHER bug class needed to complete the chain.

### AILA Replay Protocol — "Is my proposed strategy actually an attack?"

1. Articulate the target's documented threat model (from vendor docs, security blog posts, CVE classifications).
2. State the strategy's claimed `attack_primitive` in one sentence.
3. Check: is the claimed primitive INSIDE the assumed attacker state? If yes → strategy is hardening, not exploit.
4. If outside: document the COMPLETE CHAIN from `assumed_attacker_state` to RCE-or-equivalent. Each link must be either:
   (a) a documented other bug (CVE reference)
   (b) explicit assumption ("attacker has separately found X" — flag as a dependency)
5. A strategy with chain length > 3 is too speculative; flag for manual review.

---

## Topic 3: When Is a New Strategy "Novel" vs "Reinvented"?

**Wei:** The most common failure mode in JIT fuzzing strategy proposals is "I have a great idea: mutate the proto chain mid-flight!" Then you grep FUZZILLI's source and find `ProtoAssignSeqOptFuzzer` shipping since 2023. Novelty is a falsifiable claim about what existing tools DON'T do.

**Halvar:** The test for novelty is mechanical: grep the existing tool's source for the pattern you claim to be novel. If you find ANY generator/mutator/probe that produces the same shape of input, your claim is reinvention. There's no "but mine is BETTER" — different parameter values or different weights aren't novelty.

**Maddie:** Strengthen that: the test is also EMPIRICAL. Read the actual implementation. CVE-2025-2135's PoC was `f(v1, v1)` — calling a function with same arg in two slots. I'd have said "obviously FUZZILLI generates that sometimes." But the user pushed us to read `randomArguments(forCallingFunctionWithParameters:)` and we saw `parameterTypes.map({ randomVariable(forUseAs: $0) })`. Each slot is INDEPENDENTLY picked. The pool is large. Coincident picks are essentially never produced. THAT is what makes the alias generator novel — and we only know because we read the source.

**Yuki:** In syzkaller world, the same trap. People propose "syscall sequence fuzzing" — syzkaller does that. People propose "argument tampering" — syzkaller does that. The REAL novelty in kernel fuzzing in 2024 was modeling COMPOUND state (mount state + filesystem state + namespace state simultaneously). That's because no existing fuzzer modeled three independent state machines interacting. Novelty = a state-shape no existing generator covers.

**Renzo:** For web fuzzing the equivalent: "fuzz GET parameters" — every web fuzzer does that. The real novelty is fuzzing CROSS-FEATURE INTERACTIONS: e.g., uploading a SVG with embedded XML that exploits the image-processor's XML parser. The state-shape is "two independent parsers handed the same blob." Stock fuzzers don't model that combinatorial.

**Noor:** I'll articulate the test explicitly. To claim novelty, you must:
1. Identify a CONCRETE pattern (token sequence, IR shape, call sequence, state shape).
2. Quote the source of the existing tool that fails to produce it.
3. Show a CVE (real one, with patch reference) that the pattern would have caught.

Without all three, the claim is hand-wavy and should be downgraded.

### Consensus

- **Novelty has THREE required components:** (1) concrete pattern definition, (2) source-code citation of why existing tools miss it, (3) CVE that the pattern catches.
- **"Slight variation on existing X" is reinvention.** Don't ship it as novel.
- **Document the novelty triple in each strategy file.** Strategy JSON must include `novelty_evidence: { pattern, missing_in, cve_caught }`. Without that block, strategy is auto-classified as "stock variant" and given low priority.

### AILA Replay Protocol — "Is my proposed strategy actually novel?"

1. Write the strategy pattern as concretely as possible (Python pseudo-code, AST shape, JS skeleton).
2. Identify the closest 3 existing generators/mutators in target tool. Open their source. Read.
3. Test mechanical equivalence: does ANY existing generator produce inputs matching the pattern? If yes → reinvention.
4. If no: find the source line that proves the gap (e.g., `parameterTypes.map({ randomVariable(...) })` — confirms independent picks, no aliasing).
5. Find ≥1 CVE in the target's history that the pattern would have caught. Cite the patch.
6. Only if all 3 satisfied: classify as novel, weight high in profile.
7. If fails on any: either downgrade weight or drop. No "but I think it might find new bugs" exception.

---

## Topic 4: How Do We Avoid Speculation When Naming "Underexplored" Areas?

**Halvar:** This was the moment the user caught me. I said "concurrent compilation races are underexplored" without checking. The user demanded evidence. I had none. The lesson: NEVER say "X is underexplored" without citing the data that says X is underexplored.

**Maddie:** Two types of evidence count:
- **Negative:** No CVEs in the last N months for class X → MAY be underexplored (or may be infeasible, or may not exist). Weak signal.
- **Positive:** Researcher write-ups EXPLICITLY say "FUZZILLI doesn't do X." Strong signal. Examples: Zellic's 2026 blog said V8 type confusions are "formulaic" — that's an explicit signal that this class is being found by humans, NOT fuzzers, AND that the class is recurring.

**Wei:** Compiler-specific: the V8 team blog posts and design docs say what THEY consider their fuzz coverage to be. If they describe a tier as "extensively fuzzed," believe them. If they introduce a new optimization without a post about its fuzz coverage, that's a signal. CVE-2026-3910 (Maglev Phi untagging zero-day) hit precisely because Maglev is newer than TurboFan and the maintainer's fuzz coverage hadn't fully caught up.

**Yuki:** I've made this mistake. Claimed "userspace IPC fuzzing is underexplored" because I hadn't seen public talks about it. Then someone showed me three internal Google projects fuzzing exactly that. Lesson: "I haven't seen X" is NOT evidence X is underexplored. It's evidence I don't have full visibility.

**Renzo:** Strongest evidence: ACTIVE BUG BOUNTY for class X with PAYOUTS in last 12mo. Vendors pay for what their internal teams can't find. If there's a $50K+ bounty being paid for class X, X is underexplored by the internal team.

**Noor:** And the inverse: if vendor announces "we've increased fuzzing of class X by 10x," that area is now well-explored and yields will drop. Track those announcements; rotate strategies away from those areas.

### Consensus

- **"Underexplored" requires ≥2 lines of evidence:**
  - Recent CVEs in the class (positive signal of bugs being there)
  - Researcher/vendor commentary acknowledging the class is hard to fuzz (positive signal of fuzzer gap)
- **Single anecdotal claim = downgrade strategy.**
- **Bounty payouts are a strong proxy.** $20K+ payouts indicate the class is genuinely hard for the vendor to catch.
- **Vendor "we improved fuzzing" announcements = rotate away.** The area is now well-covered; yields will drop.

### AILA Replay Protocol — "Is class X underexplored?"

1. Gather data:
   - All CVEs in target's component matching class X, last 18mo. (Use NVD + vendor advisories)
   - Researcher blog posts (Zellic, Project Zero, JSEC, etc.) mentioning class X with terms like "formulaic," "recurring," "still finding"
   - Bounty payouts for class X
   - Vendor announcements about improved fuzzing
2. Score:
   - +1 per CVE in the class
   - +2 per researcher write-up confirming class is hot
   - +3 per bounty payout >$20K
   - -3 per vendor announcement of new fuzzing infrastructure for the class
3. Total score >5 → class is underexplored; strategy targeting it is worthwhile.
4. Total <5 → class is well-covered; either skip or find a sub-niche.

---

## Topic 5: Where Is the Real Throughput Bottleneck?

**Wei:** Naive answer: "add more workers." Wrong because each worker has overhead in the master that doesn't scale. FUZZILLI's `--jobs=N` is N threads in ONE master process. Master serializes program generation. Throughput ceiling = master's generation rate, regardless of worker count.

**Yuki:** Confirmed for FUZZILLI. We measured: jobs=12 hit ~30 execs/sec, full CPU saturation, master was the bottleneck. Going to 16 jobs didn't help — workers were idle waiting for the master to feed them. Same architecture in syzkaller (one orchestrator, many VM workers). At some point you saturate the orchestrator.

**Halvar:** For libfuzzer / AFL the bottleneck is different — each fork is independent, no master serialization. Throughput scales near-linearly with cores. But libfuzzer can't do the complex stateful generation FUZZILLI does. Trade-off: simple per-process fuzzers scale better, complex generation fuzzers hit master serialization ceilings.

**Maddie:** For variant-hunting on N-day work, throughput is less important than DIRECTED-ness. 5 execs/sec on a focused variant probe will find bugs in 8 hours that a 500 exec/sec random fuzzer misses in a month. The strategy choice changes what throughput we even need.

**Wei:** Right. For our v0.3 mapinf profile, we WANT slow programs because each program does Maglev compilation. Fast programs don't trigger the bug. The 30 execs/sec floor isn't a bug, it's a feature. We're trading raw execs for guaranteed-tiered execs.

**Noor:** From operations side: throughput planning needs to start with "how many directed CVE-pattern attempts do we need to expect 1 finding?" If literature says CVE-2025-2135 was found after ~3M FUZZILLI iterations of similar shape, we need 3M+ attempts. At 30 execs/sec, that's 100K seconds = 28 hours. Plan around the budget, not the rate.

### Consensus

- **Throughput is a derived metric, not a target.** The right question is "how many directed attempts at the bug-pattern do we need," then derive runtime from execs/sec.
- **Don't add workers past master saturation.** For FUZZILLI: ~12 jobs ceiling on a 12-core box.
- **For complex generators, accept lower exec/sec as the price of triggering the bug class.**
- **Multi-master distributed mode is the ONLY real scaling lever once master is saturated.** Defer to when single-machine no longer meets the target-attempt count.

### AILA Replay Protocol — "Will my throughput be enough?"

1. Identify the target attempt count: how many program executions does literature suggest are needed for this bug class?
   - JIT type confusion: ~1-5M attempts in directed mode
   - Heap UAF: ~10-50M attempts in random mode
   - Logic bugs: ~10K-100K (often human-curated, not random)
2. Measure or estimate execs/sec for the proposed strategy on the target hardware.
3. Divide: `expected_runtime_hours = target_attempts / (execs_sec * 3600)`.
4. If <72h: single-machine campaign is fine.
5. If 72h-7d: multi-master scaling needed.
6. If >7d: re-evaluate strategy (too speculative or too unfocused).

---

## Topic 6: Production Architecture — Where Does the Fuzzer Actually Run?

**Halvar:** WSL2 is dev-environment fine but it's not production. Production = a dedicated Linux box. Real hardware, no Windows-side overhead, no virtualization layer eating cycles. Most importantly: separable from operator workstations so a campaign that crashes the OS doesn't take down the operator's terminal.

**Yuki:** Standard fleet setup: 1-N dedicated Linux machines, accessed via SSH from the orchestrator. Each machine runs the fuzzer + some local state. Orchestrator (AILA) sends commands ("start campaign X," "stop campaign Y," "fetch findings"), pulls back results. Machines are fungible — campaigns can migrate if hardware fails.

**Wei:** For V8 fuzzing specifically: dedicated boxes with consistent CPU (no thermal throttling under sustained load) and ECC RAM. JIT bugs are sensitive to memory pressure and timing; running on a laptop with thermal throttling creates non-reproducible state.

**Maddie:** Storage layout for distributed fuzzing setup matters: corpus shared via shared FS or sync'd by orchestrator? Crashes flushed to durable storage immediately or batched? My experience: sync corpus once per hour (cheap), flush crashes immediately (rare, important), keep logs on local SSD for fast tail-following.

**Renzo:** Auth model: SSH key per orchestrator-to-fuzzer pair, no shared credentials, rotate quarterly. Don't reuse the operator's SSH key for the orchestrator — separate identities.

**Noor:** Hardening of fuzzing machines themselves: they're processing untrusted JS. Some crashes WILL include attacker-controlled bytes. Run as non-root user, isolate fuzz processes via cgroups, log access. If a real escape happens IN our environment, contain blast radius.

### Consensus

- **Production = dedicated Linux fuzzing workstations, accessed via SSH.** Same model as v0.1's `tools/poc_runner.py` execution layer.
- **WSL2 is dev-environment only.** Operators can dev on WSL but production campaigns run on dedicated boxes.
- **Per-machine state: corpus + crashes + logs on local SSD.** Sync corpus periodically to orchestrator. Flush crashes immediately.
- **Per-orchestrator SSH key.** No shared credentials. Rotation quarterly.
- **Fuzz processes run as non-root user, cgroup-isolated.** Crashes can contain attacker bytes.

### AILA Replay Protocol — "Provisioning a new fuzzing workstation"

1. Bare-metal or VM with ≥12 cores, ≥32GB RAM (V8 builds need it during gn gen), ≥500GB SSD.
2. Ubuntu 24.04 LTS or equivalent. No GUI.
3. Install depot_tools, Swift 6.2+, FUZZILLI fork (pinned commit), build target binary.
4. Create AILA service user (e.g. `aila-fuzz`) with no shell, cgroup limits.
5. SSH key from AILA orchestrator → workstation. Add to `~aila-fuzz/.ssh/authorized_keys` with `command=` restriction.
6. AILA's `services/ssh.py` (already exists in platform/) gets a workstation registration entry.
7. Smoke test: AILA dispatches a 5-min campaign, expects ≥10 corpus entries back, classification correct.

---

## Topic 7: Strategy Authoring Workflow — Who Writes Custom Generators?

**Wei:** Custom generators are Swift code in the FUZZILLI fork. Authoring requires understanding Swift, the FUZZILLI IL builders, AND the target's IR. Not a non-engineer task.

**Maddie:** But the JUDGMENT of which pattern to encode is research, not engineering. Researchers see the pattern from CVE patches; engineers translate to Swift. Separate roles.

**Halvar:** I've worked on teams where the pipeline is: researcher writes a one-page CVE pattern doc (the four sections: trigger, root cause, IR shape, replication). Engineer implements the generator from the doc. PR review by both. Works well.

**Yuki:** Add a research-engineer hybrid role for AILA: someone who can BOTH read patches AND write generators. Solo researchers without engineering skill get bottlenecked at implementation. Solo engineers without research skill write wrong patterns.

**Renzo:** Important for AILA UI: there must be a flow where a researcher can describe a pattern in natural language, an LLM agent drafts the Swift generator, an engineer reviews, the generator gets merged. The LLM-in-the-middle reduces the engineer-bottleneck without removing review.

**Noor:** And test coverage: every new generator MUST come with a synthetic test program that exercises it AT LEAST ONCE in the FUZZILLI startup test suite. Without that, generators that throw exceptions silently break the campaign.

### Consensus

- **Authoring workflow:**
  1. Researcher writes CVE pattern doc (template: trigger, root cause, IR shape, replication code).
  2. LLM agent (or researcher with Swift skill) drafts a generator.
  3. Engineer reviews. Tests merge in FUZZILLI fork's `aila-strategies` branch.
  4. Strategy JSON updated in AILA's `data/strategies/`.
  5. FUZZILLI fork rebuilt; AILA's V8 engine picks up new commit hash.
- **Required artifacts per generator:**
  - CVE pattern doc (markdown)
  - Generator Swift source
  - Startup test program ensuring the generator can build a valid program
  - Strategy JSON entry referencing it
- **No "free-form" generators.** Must lineage to ≥1 CVE.

### AILA Replay Protocol — "Adding a new generator for a new CVE pattern"

1. Researcher identifies a CVE matching the novelty criteria (Topic 3 + 4).
2. Researcher writes pattern doc in `docs/cve_patterns/<CVE-ID>.md` with sections:
   - Trigger (JS code that hits the bug)
   - Root cause (compiler IR or C++ source citation)
   - IR shape (what tree/graph the JIT sees)
   - Replication code (minimal JS reproducer)
3. Engineer drafts Swift generator under `~/fuzzilli/Sources/Fuzzilli/Profiles/<ProfileName>.swift`.
4. PR against `aila-strategies` branch. Review checks:
   - Generator matches pattern doc
   - Startup test program exists
   - CVE reference cited
5. Merge, rebuild FUZZILLI, push image to fuzzer workstations.
6. Update strategy JSON in AILA to reference new commit.
7. Run smoke campaign (1h) to confirm generator produces valid programs and integrates with existing mutators.
8. Promote to production weight.

---

## Topic 8: Interrupt Points — How Do We Change Our Mind Mid-Investigation?

**Halvar:** Most investigation processes assume linear progress: gather data → analyze → decide. Real research is iterative: you start, find something unexpected, pivot. The PROCESS must support pivots, not punish them.

**Yuki:** In a session like 2026-05-15, we pivoted ~6 times. Each pivot was triggered by ONE of:
- Empirical evidence contradicting an assumption ("L2 forge doesn't escape because of sandbox geometry")
- User pushback ("you didn't check CVEs, stop speculating")
- Source code reading contradicting a claim ("FUZZILLI already has ProtoAssignSeqOptFuzzer")
- New data appearing (CVE-2026-3910 details web search)

Each of these is an INTERRUPT POINT — a moment where the agent's plan should pause and re-evaluate.

**Maddie:** Programmatically: AILA's discussion engine should treat any of these events as triggers to re-enter the discussion protocol at the appropriate topic:
- Empirical contradiction → re-enter Topic 2 ("Is my primitive really an attack?")
- "You didn't check X" pushback → re-enter Topic 4 ("Avoid speculation; gather data on X")
- Source code reading discovery → re-enter Topic 3 ("Is this still novel?")
- New CVE/research → re-enter Topic 1 ("Should I rebuild the cluster analysis?")

**Wei:** Two failure modes to avoid:
- **Sunk-cost lock-in:** Continuing a strategy because you've invested time, despite evidence against it. The session showed this: I had Python wrapper code half-written when the user pushed back, and the right answer was throw it away. Cost of throwing away < cost of finishing a wrong direction.
- **Pivot-paralysis:** Pivoting on every doubt without ever committing. Pivots need EVIDENCE behind them. "I have a feeling" isn't enough. "I read this CVE patch and it changes my prior" is enough.

**Renzo:** Operator side: AILA should LOG every pivot with reason. Future analysis can ask "what triggered our pivots? are they EARNING us improvements or just adding latency?" If a session pivots 10 times and lands on a marginally better strategy, that's process waste. If a session pivots 3 times and lands on a categorically better strategy, that's healthy.

**Noor:** Make pivots first-class in the project artifacts. Each strategy file has a `pivot_history: []` field. When we pivot away from a strategy, we mark WHY in that field. Later, when AILA evaluates whether to retry an old strategy, it sees the pivot history and knows the reason it was abandoned (so it can check if the reason still holds).

### Consensus

- **Recognize 4 interrupt triggers:** empirical contradiction, user pushback demanding evidence, source code revealing assumption is wrong, new CVE/research data.
- **Each interrupt should re-enter the discussion protocol at the appropriate topic.** Don't continue the prior plan as if the evidence didn't arrive.
- **Log pivots with reasons.** Strategy files include `pivot_history`.
- **Apply sunk-cost heuristic:** if pivot is justified, throw away half-finished work. The cost is bounded; carrying a wrong direction is unbounded.

### AILA Replay Protocol — "An interrupt has fired"

1. Identify the trigger:
   - "Tool output contradicts my prior claim" → empirical
   - "User said 'how do you KNOW'" → speculation challenge
   - "Source code grep showed feature exists already" → novelty challenge
   - "New CVE just dropped in target component" → data update
2. Don't argue against the trigger. Re-enter the topic it maps to.
3. Re-run the protocol for that topic. Gather fresh data if needed.
4. Record the pivot in the active strategy doc:
   ```yaml
   pivot_history:
     - at: "2026-05-15T15:42:00Z"
       from_strategy: "python_l2_forge_wrapper"
       to_strategy: "fuzzilli_v8MapInference"
       trigger: "user_pushback_speculation"
       reason: "Did not check FUZZILLI source for existing generators or read CVE patches before claiming novelty"
   ```
5. If pivot count for this campaign >5, flag for operator: investigation may be in pivot-paralysis mode.

---

## Topic 9: Triage Hand-Off — What Happens When We Actually Find a Crash?

**Halvar:** This was barely discussed in the session because we have no crashes yet. But the FIRST real finding will reveal whether the whole pipeline works. If triage takes 4 hours of manual work, the system isn't shipping value.

**Yuki:** From triage at fleet scale: 95% of crashes are duplicates. 4% are known bug classes. 1% are new. The triage pipeline MUST: (1) auto-dedup, (2) auto-classify against known classes (CHECK/DCHECK/SBXCHECK/sandbox-violation), (3) flag the 1% for human review with all evidence pre-collected.

**Wei:** For V8 specifically: classification is by stderr marker:
- `## V8 sandbox violation detected!` → CRITICAL (real escape candidate)
- `Check failed:` → CHECK failure, defended
- `SBXCHECK failed:` → sandbox check fired, defended
- `AddressSanitizer:` → with ASan build, real memory error
- `Caught harmless signal` → in-sandbox fault, ignore
- `CSA check failure` → CSA invariant, ignore
- (no marker, exit 0) → not a crash

This classification fits in a YAML rules file. AILA's triage worker applies it deterministically.

**Maddie:** Dedup signature: stack-hash on the top 5 stack frames after stripping ASLR-randomized addresses. Two crashes with same stack-hash = one finding. Per CVE-2025-2135 writeup, the Zellic team's mutation engine found multiple programs hitting the same root cause — dedup is essential.

**Renzo:** For findings the triage marks as new/CRITICAL, the immediate next step is variant hunt. Per `VR_V03_FUZZING_PLAN.md` M3.10: auto-queue a variant hunt worker. Mutate the reproducer 10 ways. Test each. New variants link to the parent finding.

**Noor:** And advisory generation: a confirmed sandbox violation should auto-promote to a `vr_findings` row (the v0.1 N-day finding model). From there, v0.1's advisory generator can produce the CVSS, write-up, etc. The fuzzing pipeline FEEDS the N-day pipeline — they're not separate.

### Consensus

- **Triage worker applies YAML rules** (`data/triage/rules/v8_d8.yaml`) to classify by stderr marker.
- **Dedup by stack-hash** after ASLR stripping.
- **CRITICAL findings auto-queue variant hunt.**
- **Confirmed escape findings promote to `vr_findings` for v0.1 advisory generation.** Fuzzing → N-day pipeline is a single chain.
- **All triage logic is data + workers, not LLM inference.** Speed and consistency matter more than judgment at this stage.

### AILA Replay Protocol — "A crash file appeared in the storage path"

1. Triage worker picks up crash file.
2. Parse stderr, apply rules to classify.
3. Compute stack hash, check against existing findings.
4. If duplicate: increment `instance_count`, link to canonical, continue.
5. If new and not CRITICAL: create new finding, store reproducer, log.
6. If new and CRITICAL: create finding, store reproducer, AUTO-QUEUE variant hunt + minimization, NOTIFY operator immediately (SSE push + email if configured).
7. After minimization done, promote to `vr_findings` for advisory generation.
8. Track time from crash-found to advisory-generated as the pipeline's primary SLO.

---

## The Strategy Discovery Protocol — Distilled Loop

This is the meta-protocol AILA executes to discover strategies for a new target. It iterates through the topics above, supporting interruption at each step.

```
Loop start:
  
  Topic 1 — Stock or custom?
    ↓ if data says custom, continue
    ↓ if data says stock, configure stock + skip to Topic 5
  
  Topic 2 — Is my primitive an attack?
    ↓ if yes, continue
    ↓ if no, redefine primitive (loop back to Topic 1)
  
  Topic 3 — Is my proposed pattern novel?
    ↓ if yes, continue
    ↓ if no, drop or downgrade strategy (loop back to Topic 1)
  
  Topic 4 — Is my "underexplored" claim grounded?
    ↓ if yes, continue
    ↓ if no, drop strategy or gather more data (loop back to Topic 1)
  
  Topic 5 — Will throughput be sufficient?
    ↓ if yes, continue
    ↓ if no, simplify strategy or scale architecture (loop back to Topic 1)
  
  Topic 6 — Provision/connect production fuzzing workstation
    
  Topic 7 — Implement generator(s), build fork, deploy
  
  Run campaign for budgeted time.
  
  Topic 9 — Triage findings as they appear.
  
  At ANY point, an interrupt can fire (Topic 8). Pause, re-enter relevant topic.

Loop continues until: 72h elapsed OR finding promoted OR pivot count >5.
```

## How AILA Consumes This Document

When operator says "find me a new fuzzing strategy for target X":

1. AILA loads this doc as planning context.
2. AILA loads `data/strategies/_evidence/<target>_cve_cluster_<latest>.md` (or generates it via Topic 1 protocol).
3. AILA executes the discovery loop above, stopping at each topic for either:
   - Data lookup (web_search, source grep, CVE DB)
   - User confirmation (when judgment is required)
   - Implementation step (when handoff to engineer is needed)
4. Output of the loop is one or more strategy JSON entries in `data/strategies/<target>/<strategy_name>.json`.

## How AILA Discovers MORE Strategies After This One

The same protocol runs in parallel for adjacent targets:
- Same target, different bug class (after first strategy stabilizes)
- Different target, same bug class (e.g., SpiderMonkey JIT typer after V8 JIT typer)
- Hybrid (e.g., V8 + WebAssembly cross-boundary, which Topic 1 might re-cluster as worth a custom strategy)

When operator runs `gsd-explore` or similar with prompt "what fuzzing strategies should we run NEXT," AILA:
1. Pulls latest CVE data (Topic 1 redo)
2. Identifies clusters that didn't exist when last protocol ran
3. Proposes 2-3 strategy candidates
4. Operator picks one, AILA runs full loop to produce ready-to-deploy strategy

## Decisions Promoted to VR_MODULE_DECISIONS.md

These decisions emerged from this session and should land in `VR_MODULE_DECISIONS.md`:

- **D-30:** V8MapInferenceProfile is the v0.3 reference strategy. (Result of Topics 1-4)
- **D-31:** FUZZILLI is the primary v0.3 fuzz engine; AILA never replicates its generators in-house. (Result of Topic 7)
- **D-32:** Storage layout: separate `fuzz-storage/` and `fuzz-logs/` directories so `--overwrite` doesn't wipe logs. (Result of empirical bug)
- **D-33:** Production = dedicated Linux fuzzing workstations via SSH, NOT WSL2. (Result of Topic 6)
- **D-34:** Default minimization stays ON; throughput-vs-quality favors quality at v0.3. (Result of Topic 5 trade-off discussion)
- **D-35:** Strategy files include `novelty_evidence` and `pivot_history` blocks for traceability. (Result of Topics 3 + 8)

---

## Open Questions for Operator

1. **Bug bounty intake:** When a real sandbox violation lands, do we file to Google VRP immediately or do internal validation first? Internal validation has cost (operator time) but reduces risk of public-disclosure mistakes.
2. **Strategy retirement criteria:** When does a custom strategy get retired? Suggested: after 30 days of zero new findings OR when stock catches up. Need operator confirmation.
3. **Multi-target prioritization:** With finite workstations, when do we shift fuzzing capacity from V8 to (say) SpiderMonkey or WebKit? Suggested: rotation every 90 days with overlap.
4. **Researcher onboarding:** Topic 7 assumes Swift-capable engineers exist. For solo-operator deployments, what's the path? Suggested: LLM-drafted generator + extensive automated tests.
5. **Pivot history retention:** How long do we retain `pivot_history` entries before pruning? Affects strategy-evolution analysis but bloats files long-term.

---

## How to Run This Document

```bash
# AILA's gsd-explore can consume this directly:
gsd-explore --planning-context docs/VR_FUZZING_STRATEGY_DISCOVERY_DISCUSSION.md \
            "Find a new fuzzing strategy for SpiderMonkey JIT typer bugs"

# To extend the discussion with a new topic:
# Edit this file with a new Topic N+1 section following the same format
# Reuse personas; add new ones only when a genuinely new viewpoint is needed
```

---

## References

- VR_V01_PLAN.md — current N-day workflow that consumes fuzzing findings
- VR_V03_FUZZING_PLAN.md — milestone plan for fuzzing pipeline
- VR_MODULE_DECISIONS.md — locked architectural decisions (D-1 through D-35)
- VR_STAFF_RESEARCHER_DISCUSSION.md — original 5-persona discussion these continue from
- Zellic CVE-2025-2135 writeup: <https://www.zellic.io/blog/pwning-v8ctf/>
- CVE-2026-3910 details: <https://cvereports.com/reports/CVE-2026-3910>
