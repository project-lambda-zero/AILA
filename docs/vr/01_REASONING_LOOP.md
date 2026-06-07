# VR Module — The Reasoning Loop

Reference on the turn-by-turn reasoning loop. This is the engine of the module: how the LLM thinks about finding bugs, what it sees each turn, what it produces, and how the platform keeps it honest. Brainstorm-grade exploration — every gray area I can find, surfaced and named.

Cross-references:
- `docs/VR_MODULE_DECISIONS.md` (D-01 .. D-06) — closed scope
- `docs/VR_MODULE_METIS_INSPIRATIONS.md` — evidence obligations, bounded packs, adjudication
- `docs/VR_MODULE_TRAILMARK_INSPIRATIONS.md` — code graph, taint, entrypoints
- `docs/VR_MODULE_PHAROS_INSPIRATIONS.md` — angr, OOAnalyzer, function hashing
- `docs/VR_MODULE_TOOLCHAIN.md` — full tool matrix
- `src/aila/platform/services/reasoning.py` — the existing `CyberReasoningEngine`
- `src/aila/platform/contracts/reasoning.py` — `ReasoningTurnDecision` / `ReasoningCaseState`

---

## 0. Preamble: Why the Loop Is the Module

The platform already has a reasoning engine. Forensics already proves that hypothesis -> action -> observe -> refine works at production scale. The temptation is to drop in a few new strategy families ("fuzzing", "exploit_development") and call the loop done.

That is wrong. Forensics asks "what happened on this disk?" — a question with a single ground truth waiting to be discovered. VR asks "is there a bug here, and can I weaponize it?" — a question whose answer is *constructed*, not found. The loop has to support:

- Open-ended hypothesis generation (forensics has questions; VR has *targets*)
- Long-running side effects (a fuzzing campaign runs for hours and produces evidence asynchronously)
- Cumulative artefact creation (harnesses, scripts, PoCs are first-class outputs, not just observables)
- Adversarial reasoning under partial information (mitigations not yet fingerprinted, allocator unknown)
- Creative leaps (combining two unremarkable observations into one exploitable primitive)

So the loop has to extend the existing one, not just reuse it.

---

## 1. Turn Anatomy

One turn is one round-trip: the engine builds a prompt, the LLM emits a `ReasoningTurnDecision`, the platform validates and dispatches it, the resulting observation is folded into case state, and the next turn begins.

### 1.1 What the LLM receives

A single user-message payload composed of:

| Section | Source | Bounded? |
|---|---|---|
| Turn header | engine | one line |
| Question | project + workflow phase | small |
| Strategy family | router (keyword or LLM) | one token |
| Operator steering | `ReasoningOperatorSteering` | small |
| Target context | `VRTargetContext` (arch, mitigations, target class, source/binary) | small |
| Evidence pack | bounded pack of decompiled functions, source snippets, ASAN reports, traces | hard cap — sections + chars per section |
| Case model | rendered `ReasoningCaseState` (contract, hypotheses, rejected, observables) | small |
| Artefact index | one-line summary per artefact already produced (harness path, campaign id, crash id, PoC id) | small |
| Recent transcript | last N turns compressed (action, expected_observation, one-line outcome) | bounded |
| New evidence | output from the previous turn's action (truncated if needed, dropped count surfaced) | hard cap |
| Tool catalogue | available actions and their parameter schemas | static, small |

The bounded sections are critical. A binary has thousands of functions. A fuzzing campaign produces gigabytes of crashes. The LLM context cannot hold everything, and **the LLM must always be told what was excluded**, so it can request expansion.

### 1.2 What the LLM produces

Existing `ReasoningTurnDecision` fields stay. New VR-specific fields extend it:

```python
class VRTurnDecision(ReasoningTurnDecision):
    # existing: reasoning, action, expected_observation, contract,
    # hypotheses, rejected, observables, script_content, command,
    # answer, confidence, provenance

    # new
    vr_action: VRAction | None = None         # discriminated union (decompile, fuzz, ...)
    pack_requests: list[PackRequest] = []     # "give me decompilation of func @ 0x401af0"
    obligations: list[EvidenceObligation] = []  # what must be proved before submit
    artefact_writes: list[ArtefactWrite] = []   # files the LLM wants to persist (harness.c, exploit.py)
    pivot: PivotIntent | None = None          # explicit "I am abandoning H3 and starting H7"
```

The discriminated `vr_action` replaces the generic `script_execute`/`tool_run` slot for VR-domain operations. Generic `tool_run` is still there as a safety hatch (e.g. `file`, `strings`, `checksec`).

`pack_requests` are crucial — see §3 for the example.

### 1.3 What it gets back

Each `vr_action` produces a typed observation. The engine attaches:

- `latency_ms` — wall clock for the action
- `truncated` — bool, if the result was clipped
- `dropped_evidence_count` — how many sections didn't fit
- `artefact_id` — where the full output lives (filesystem on the workstation, or a row in `vr_artefacts`)
- `obligation_satisfied: list[str]` — which prior obligations this evidence proves
- `obligation_invalidated: list[str]` — which prior conclusions this evidence contradicts

The next turn's evidence pack is built from artefacts referenced by the current case state plus whatever fresh observation the previous action produced.

### 1.4 The dispatch layer

Pseudocode for one turn:

```python
async def run_turn(state: VRCaseState, project: VRProject) -> VRCaseState:
    context = build_prompt_context(state, project)
    pack   = build_evidence_pack(state, project, max_sections=20, max_chars=4000)
    sys_prompt = build_system_prompt(project, state)
    user_prompt = render_user_prompt(context, pack)

    decision = await engine.decide_next_turn(
        task_type="vulnerability_research",
        system_prompt=sys_prompt,
        user_prompt=user_prompt,
    )

    decision = adjudicate(decision, state, pack)   # may downgrade / reject

    if decision.action == "submit":
        return await handle_submit(decision, state, project)

    observation = await dispatch(decision.vr_action, project, budget=state.budget)
    state = engine.absorb(state, decision)
    state = fold_observation(state, observation)
    return state
```

`adjudicate` is the deterministic gate (Metis-style). It runs *before* dispatch — there is no point burning a 6-hour fuzzer run on a hypothesis whose stated obligations are already unmet.

---

## 2. System Prompt Design

The persona has to be: a research engineer who breaks software for a living, is paid to find new bugs, treats every claim as a hypothesis until evidence lands, and refuses to bullshit. Not a helpful assistant. Not a CTF player ("just spray and pray").

### 2.1 Sections of the system prompt

1. **Role & posture** — adversarial researcher, evidence-bound, refuses uncertainty laundering.
2. **The closed-loop protocol** — same as forensics: turn budget, JSON-only response, contract.
3. **Action vocabulary** — the typed `vr_action` schema with every action and its parameters.
4. **Evidence rules** — never claim what isn't in the evidence pack; mark inferences explicitly; request expansion if the pack is insufficient.
5. **Mitigation discipline** — claims of exploitability MUST address the binary's actual mitigations (ASLR, NX, stack canary, RELRO, CFI, CET, MTE, KASLR, SMEP/SMAP).
6. **Strategy menu and pivot rules** — when to fuzz vs audit vs diff; when to abandon a hypothesis.
7. **Target context** — class (native userspace / kernel / hypervisor / Java / Python / JS / PHP / Go / Rust), arch, OS, source availability, build system.
8. **Operator steering** — confirmed facts, disproved hypotheses, pinned strategy, supplied techniques.
9. **Anti-patterns** — every hallucination shape we've seen in dev: phantom bounds checks, wishful integer math, "exploitable in theory", fabricated stack traces.
10. **Submission contract** — what must be true before `action="submit"` is permitted.

### 2.2 Example system prompt

This is meant to be representative, not the final canonical text.

```
You are a senior vulnerability researcher. You break software professionally.
Your job is to find new exploitable defects in the target and prove them with
working artefacts (crashing inputs, reproducer scripts, working PoCs).

You operate inside a strict closed-loop protocol. Each turn you receive:
  - the research question and target context
  - a bounded evidence pack (with a count of what was excluded)
  - the cumulative case model (contract, hypotheses, rejected, observables)
  - a transcript of recent turns
  - the new evidence produced by your last action

You return ONE JSON object matching the response contract below. No prose.

Response contract (top-level JSON):
{
  "reasoning": "what you decided and why, terse, evidence-anchored",
  "contract": { "answer_type": "...", "answer_format": "...",
                "evidence_domain": "binary|source|kernel|...", "depends_on": [] },
  "hypotheses": [ {"id":"H1","claim":"...","why_plausible":"...","kill_criterion":"..."} ],
  "rejected":   [ {"id":"H?","claim":"...","reason":"..."} ],
  "observables": { "arch":"x86_64", "mitigations":"NX,RELRO,canary,no-PIE", ... },
  "vr_action": {
    "kind": "decompile|fuzz|trace|debug|analyze_crash|search_code|diff_versions
            |write_harness|write_exploit|query_graph|run_angr|submit|reasoning",
    "params": { ... action-specific ... }
  },
  "pack_requests": [ {"kind":"decompile","name":"parse_extension"},
                     {"kind":"xrefs","to":"memcpy"} ],
  "obligations": [ {"id":"O1","claim":"tcache poisoning viable",
                    "required_evidence":"glibc version + tcache present" } ],
  "artefact_writes": [ {"path":"harness.c","kind":"libfuzzer_harness"} ],
  "expected_observation": "what success looks like AND how it narrows hypotheses",
  "pivot": null,
  "answer": null, "confidence": null,
  "provenance": { "primary_artifact":"...", "corroboration":[],
                  "rejected_alternatives":[] }
}

Hard rules:
- You may not claim a property of the target that is not visible in the
  current or prior evidence pack. If you need to see code you haven't seen,
  emit a "pack_requests" entry instead of inventing the contents.
- Exploitability claims MUST address the target's actual mitigations.
  Say "ASLR + canary + partial RELRO → I need an info leak first; H4 is the
  candidate leak". Do not say "exploitable assuming no mitigations".
- "might be possible", "could potentially", "in theory" → use action="reasoning"
  to gather evidence first, never use them in a submit.
- Never re-propose a rejected hypothesis. If new evidence overturns a rejection,
  state the new evidence explicitly in `reasoning` and create a NEW hypothesis id.
- A rejected_hypothesis cannot be upgraded to submitted in the same turn it
  was first rejected. New evidence required.
- The ONLY way to finalise is action="submit" with a non-null answer, a
  non-null confidence in {exact, strong, medium, caveated}, AND a non-empty
  provenance.primary_artifact that points to a real artefact_id you produced.

Strategy menu (pick the cheapest action that maximally narrows hypotheses):
  fuzz       — when target has a clear input boundary and source/QEMU coverage
  decompile  — when you need to read code you haven't seen
  trace      — when behaviour at runtime is the cheapest way to confirm a guess
  debug      — when you need register/memory state at a specific point
  search_code — when you suspect a pattern across many functions
  diff_versions — when you have two versions and want the silent fix
  query_graph — when Trailmark / call-graph relationships are the shortcut
  run_angr   — when path feasibility / constraint solving is faster than fuzz
  write_harness — when no existing harness reaches the target function
  write_exploit — only after the bug is confirmed and primitives are clear
  analyze_crash — only on a real crash artefact you can name
  reasoning  — when you need to think without burning a tool budget

Pivot rules:
- If a hypothesis has produced 0 progress over 3 consecutive turns AND no
  evidence has been newly observed for it, REJECT it explicitly with reason.
- If two hypotheses now reduce to the same root, merge them and reject one.
- If operator steering disproves a hypothesis, REJECT it this turn.

Target context (filled per project):
  class           = native_userspace
  arch            = x86_64
  os              = linux
  source          = available (https://...)
  binary          = /artefacts/<sha>/libfoo.so.1.2.3
  mitigations     = NX, RELRO=full, canary=on, PIE=on, CFI=off, CET=off, MTE=n/a
  allocator       = glibc-2.35 ptmalloc (tcache present)
  build_system    = autotools, debug symbols stripped from release
  test_corpus     = ./fuzz/corpus/*

Operator steering (filled live):
  pinned_strategy_family = vulnerability_research
  confirmed_facts = ["product ships with -fno-stack-protector on libfoo only"]
  disproved_hypotheses = ["H2: heap overflow in tile decoder"]
  guidance = ["focus on extension parser; the changelog mentions a silent fix in 1.2.4"]
  required_artifacts = ["working PoC against 1.2.3", "clean run on 1.2.4"]

Anti-patterns (do NOT do these, you will be downgraded to inconclusive):
- Phantom guard: claiming a bounds check exists without citing the line.
- Mitigation amnesia: claiming RCE without addressing canary/CFI/etc.
- Wishful integer math: "size will overflow" without computing the actual
  values from the input domain.
- Fabricated trace: describing a stack frame you didn't observe.
- "Exploitable in theory": the only acceptable outputs are crash, code-exec,
  info-leak, DoS, or "not exploitable on this build" with a kill_criterion
  that was actually tested.
```

The prompt is long. That's fine — it's static across turns and (modulo target context and operator steering) does not consume new tokens per turn beyond the first. With prompt caching it's effectively free after turn 1.

### 2.3 Per-target-class addenda

The system prompt has a per-class block appended. Examples:

- **kernel**: address SMEP/SMAP/KPTI/KASLR/PAN; primitives are "arbitrary kernel R/W via X" not "code exec via Y"; testing requires QEMU+KASAN, not native.
- **java**: deserialization gadget chains; classpath introspection; JNDI/RMI surfaces; no shellcode talk.
- **python**: pickle, eval/exec sinks, SSTI; no ROP talk.
- **rust**: focus is unsafe blocks, FFI, and unsoundness — not memory corruption in the abstract.

Branching the prompt body is preferable to a single monster prompt that lists every class, because most rules are class-specific anti-patterns and the LLM does worse with a long list of "ignore this section if your target is X".

---

## 3. User Prompt per Turn

The per-turn payload. Concrete example for **turn 3 of an open-ended research session against a hypothetical `libfoo` MQTT parser**.

```
Turn 3/40. Time budget remaining: 6h12m. Tool budget remaining: 18 actions.

Question:
Find one or more exploitable defects in libfoo 1.2.3 reachable from network-
delivered MQTT messages. Produce a crashing input, a root-cause writeup, and
(if possible) a working PoC against the default build on Ubuntu 22.04.

Reasoning domain: vulnerability_research
Strategy family: vulnerability_research (pinned by operator)

OPERATOR STEERING:
  pinned_strategy_family = vulnerability_research
  confirmed_fact = "product ships with -fno-stack-protector on libfoo only"
  guidance       = "focus on extension parser; changelog mentions silent fix in 1.2.4"
  required_artifact = "working PoC against 1.2.3"
  required_artifact = "clean run on 1.2.4"

Target context:
  class       = native_userspace
  arch        = x86_64
  os          = linux
  source      = available (./targets/libfoo/)
  binary      = ./targets/libfoo/build-release/libfoo.so.1.2.3
  mitigations = NX, RELRO=full, canary=on (default), PIE=on
                NOTE: libfoo built with -fno-stack-protector (operator confirmed)
  allocator   = glibc-2.35 ptmalloc (tcache present, single-threaded)

Case model so far:
  Contract:
    answer_type   = vulnerability_finding
    answer_format = (crash_input_id, root_cause_text, poc_artefact_id?)
    evidence      = binary+source
  Observables:
    - arch = x86_64
    - parser_entry = parse_mqtt_message @ 0x401af0
    - extension_parser = parse_extension @ 0x402310
    - dangerous_calls = memcpy@0x4023a8, memcpy@0x402520, memmove@0x402611
    - changelog_signal = "fix length validation in extension parser" (1.2.4 changelog)
  Live hypotheses:
    - H1: integer overflow in parse_extension's ext_length computation leads
          to undersized allocation followed by oversized memcpy
          kill: bounds check found between length read and memcpy
    - H3: state-machine confusion lets a crafted CONNECT packet reach
          parse_extension with a partially initialised ctx, causing UAF
          kill: ctx fully initialised on every path that reaches the parser
  Rejected (do not re-propose):
    - H2: heap overflow in tile decoder (operator-confirmed unrelated module)

Artefacts already produced (3 records):
  == artefact:fz-c01 ==
    kind: fuzzing_corpus_seed
    path: /research/libfoo/seeds/
    summary: 14 MQTT control packets harvested from the test suite
  == artefact:dc-001 ==
    kind: decompilation
    func: parse_mqtt_message
    summary: dispatches by type byte; calls parse_extension for type 0x0b
  == artefact:dc-002 ==
    kind: decompilation
    func: parse_extension
    summary: reads u16 ext_length, mallocs ext_length, memcpys ext_length+4
             from caller buffer — see §observation below

Transcript (last 2 turns):
  Turn 1 — action=decompile parse_mqtt_message
    expected: identify how extension parser is reached
    outcome:  observable parser_entry @ 0x401af0; H1 proposed
  Turn 2 — action=decompile parse_extension
    expected: spot the length-validation gap that the changelog hinted at
    outcome:  ext_length read as u16; memcpy size = ext_length + 4;
              malloc size = ext_length. dangerous_calls observed.

New evidence from last action (turn 2):
  artefact:dc-002 — parse_extension decompilation, 78 lines:
  ```c
  int parse_extension(mqtt_ctx_t *ctx, const uint8_t *buf, size_t len) {
      if (len < 2) return -1;
      uint16_t ext_length = (buf[0] << 8) | buf[1];
      uint8_t *out = malloc(ext_length);          // <-- allocation
      if (!out) return -2;
      if (len < ext_length + 4) return -3;        // <-- length check, but on input
      memcpy(out, buf + 2, ext_length + 4);       // <-- writes ext_length+4 bytes
      ctx->ext = out;
      ctx->ext_size = ext_length;
      return 0;
  }
  ```
  Pack drop count: 2 (xrefs to parse_extension and the wrapper that supplies
  `len` were excluded — request via pack_requests if needed).

Evidence pack budget: 20 sections / 4000 chars per section.
Sections used: 6/20. Chars used in current section: 2811/4000.

Tool catalogue (action="vr_action"):
  decompile { name|address }                    -> decompilation artefact
  fuzz      { harness, time, cores, sanitizers } -> campaign id, async
  trace     { script, attach_target, duration }  -> trace artefact
  debug     { script, target, breakpoints }      -> debug session artefact
  analyze_crash { crash_id }                     -> crash report
  search_code { pattern, scope }                 -> hits[]
  diff_versions { v1, v2, scope }                -> diff artefact
  write_harness { target_func, format }          -> harness artefact (no run)
  write_exploit { crash_id, technique }          -> exploit artefact (no run)
  query_graph { query }                          -> graph result
  run_angr  { entry, target, constraints }       -> path/sat result
  submit    {}                                   -> finalise
  reasoning {}                                   -> no tool, just thinking

Return one JSON object matching the response contract.
```

### 3.1 Notes on this concrete example

A reasonable model response on turn 3 here would be: confirm H1 by computing the actual integer arithmetic (`ext_length+4` overflows when `ext_length == 0xFFFC`, leading to `malloc(0xFFFC)` followed by `memcpy(out, src, 0)` — *not* an overflow), recognize the bug is actually different (overread on `buf` if `len` lies, but `len` is checked against `ext_length+4` first), and either propose a tighter hypothesis or request the wrapper that supplies `len` via `pack_requests`. The interesting design point: a careful LLM should *not* submit here. The deterministic adjudicator must enforce that — see §5.

A careless LLM would say "obvious heap overflow, exploitable" and submit. We must have machinery to catch this. That's §8.

### 3.2 Compression of older turns

Turns older than the last 2-3 are summarised to one line each (`Turn N — action=X expected=Y outcome=Z`). The full transcript lives in the durable workflow record. The LLM never sees raw old turns again unless it requests a specific artefact via `pack_requests`. This is what keeps long campaigns inside the context window.

The summarisation is itself a small LLM call done by the engine, *not* by the research LLM. It's a different task, different prompt, smaller model — there is no need to burn the research model's context on transcript compression.

---

## 4. Action Types

The full catalogue. Each entry: parameters, output, expected latency, failure modes.

### 4.1 `decompile`

Get IDA Pro pseudocode (or Ghidra fallback) for one function.

```
params: { name?: str, address?: hex_str, depth?: int = 0 }
output: { func: str, address: hex, pseudocode: str (truncated to 4000 chars),
          callers: [name], callees: [name], xrefs_strings: [str],
          truncated: bool, dropped_lines: int }
latency: 1-15s typical (cached after first call per function)
```

Failure modes: function not found, decompilation failed (bad CFG), IDA license unavailable. On license failure the dispatcher silently falls back to Ghidra and surfaces `decompiler="ghidra"` in the observation so the LLM doesn't trust pseudocode that looks weirdly different.

`depth` lets the LLM say "and decompile every direct callee inline". Capped at 3 to prevent context blow-up.

### 4.2 `fuzz`

Launch or extend a fuzzing campaign. Async — returns a campaign id, the LLM polls or moves on.

```
params: {
  harness_artefact_id: str,
  fuzzer: "afl++" | "libfuzzer" | "honggfuzz" | "winafl" | "syzkaller"
        | "jazzer" | "atheris" | "go-fuzz" | "cargo-fuzz",
  cores: int,
  duration_minutes: int (max from project budget),
  sanitizers: ["asan", "ubsan", "msan", "tsan"],
  corpus_seed: artefact_id?,
  dictionary: artefact_id?,
  intel_pt: bool = false,
}
output: { campaign_id, status: "starting"|"running"|"queued",
          telemetry_endpoint: artefact_id }
latency: returns immediately (200ms); campaign runs hours/days
```

Crucially, the LLM does not block on a campaign. The next turn can be a `decompile` while AFL++ runs. Campaigns surface progress as observables (`fuzz/c01/edges=8123 crashes=0 plateau_for=1h12m`) on every subsequent turn until the LLM either calls `analyze_crash` on a crash, calls `fuzz` again to extend, or marks the campaign rejected.

Failure modes: harness won't compile, target deadlocks during init, no coverage feedback (binary stripped of instrumentation), corpus seed empty.

### 4.3 `trace`

Write and run a Frida or DynamoRIO script. Attach to a running process or instrument a binary launch.

```
params: {
  framework: "frida" | "dynamorio" | "pin",
  script_content: str,
  target: { binary: path, args: [str] } | { pid: int },
  duration_seconds: int,
  data_to_capture: ["function_args"|"call_traces"|"memory_writes"|"branches"],
}
output: { trace_artefact_id, summary: str, truncated: bool, events_dropped: int }
latency: duration_seconds + ~5s overhead
```

Failure modes: target detects Frida (anti-debug), permissions missing, script syntax error, output exceeds artefact size limits.

### 4.4 `debug`

Write and run a GDB / LLDB / WinDbg script. Synchronous, time-boxed.

```
params: {
  debugger: "gdb" | "lldb" | "windbg" | "pwndbg",
  script_content: str,    # e.g. "b parse_extension\n r < poc.bin\n bt\n p ext_length\n c"
  target: { binary, args: [str], stdin?: artefact_id },
  timeout_seconds: int,
}
output: { transcript: str, exit_status, crash: { signal, pc, registers }? }
latency: 5-60s typical; capped by timeout
```

Failure modes: timeout, target needs interactive input, stripped binary (no symbols), debugger refuses to attach.

### 4.5 `analyze_crash`

Triage a single crash from a campaign. Distinct from `debug` because it produces a structured `CrashReport`, not a transcript.

```
params: { crash_artefact_id: str, mode: "auto" | { custom_script } }
output: CrashReport {
  bucket_hash: str,         # for dedup
  classification: "heap-overflow"|"stack-overflow"|"uaf"|"double-free"|"null-deref"
                | "type-confusion"|"int-overflow"|"oom"|"timeout"|"unknown",
  asan_report?: str,
  reproducer_artefact_id: str,
  exploitability_signals: { controlled_pc: bool, controlled_write: bool,
                            partial_pc_control: bool, oob_read_only: bool },
  notes: str,
}
latency: 10-90s
```

Important: `analyze_crash` itself does not claim exploitability. It collects *signals*. The LLM (gated by the adjudicator) reasons about exploitability separately. Otherwise we are asking the same model two questions in one and hiding the chain of reasoning.

### 4.6 `search_code`

Pattern search across source or decompiled output. Cheap, fast, high information density.

```
params: {
  pattern: str | regex | semgrep_rule | tree_sitter_query,
  scope: "source" | "decompiled" | "both",
  filter: { language?, dir_glob?, function_filter? },
  max_hits: int = 50,
}
output: { hits: [{ file, line, snippet }], truncated: bool, dropped_count: int }
latency: <2s typical
```

Failure modes: pattern too broad (10k hits — engine forces truncate + warns), no source available (only binary).

### 4.7 `diff_versions`

Compare two builds or two source revisions.

```
params: {
  v_old: { binary?: path, source?: rev },
  v_new: { binary?: path, source?: rev },
  scope: "function" | "file" | "module" | "all",
  tool: "bindiff" | "diaphora" | "trailmark_diff" | "git_diff",
}
output: { diff_artefact_id, summary, changed_functions: [name],
          security_signals: [{ pattern, locations }] }
latency: 30s - 10min depending on size
```

`security_signals` is heuristic (added bounds checks, replaced `memcpy` with `memcpy_s`, added length argument, changed signed→unsigned, added null check). The LLM reasons about whether each signal is the actual silent fix.

### 4.8 `write_harness`

Generate a fuzzing harness. Does not run it.

```
params: {
  target_func: { name, signature?: str },
  format: "libfuzzer" | "afl++_persistent" | "winafl_dr" | "jazzer" | "atheris",
  setup_steps: [str],   # operator/LLM-supplied init (e.g. "init mqtt_ctx_t to defaults")
}
output: { harness_artefact_id, language, source_path, build_status,
          build_log_artefact_id?, suggested_seed_corpus: [artefact_id] }
latency: 5-30s (compilation included)
```

The harness is *built* on the workstation. If build fails, `build_status="failed"` and the LLM sees the build log. The model can then iterate on the harness in subsequent turns. This is one place where the loop has to gracefully tolerate multiple compilation failures — common case, not failure mode.

### 4.9 `write_exploit`

Generate an exploit. Does not run it (running is `debug` or a dedicated `run_poc` action — see §11 open question).

```
params: {
  crash_artefact_id: str,
  technique: "rop" | "tcache_poison" | "house_of_*" | "stack_pivot"
           | "info_leak_chain" | "deserialization_chain" | "ssti_payload" | ...,
  target_primitive: "rce" | "info_leak" | "arbitrary_write" | "egid0",
  notes_from_operator: str?,
}
output: { exploit_artefact_id, language, source_path, dependencies: [str],
          assumptions: [str], reliability_estimate: "deterministic"|"probabilistic"|"unknown" }
latency: 10-60s (no execution)
```

`assumptions` is critical: the LLM must enumerate every assumption ("glibc tcache present", "specific libc version", "no ASLR randomisation between runs of single process", "stdin EOF triggers cleanup path"). Each assumption maps to an evidence obligation. If the project's evidence does not satisfy an assumption, the adjudicator forces `confidence ≤ caveated`.

### 4.10 `query_graph`

Query the Trailmark code graph. The shape of queries is open-ended; canonical kinds:

```
params: { query: str, kind: "trailmark_dsl" | "neo4j" | "cypher" }

# examples (LLM-generated):
"all functions reachable from MQTT entrypoints that call any of {memcpy,strcpy}"
"all callers of parse_extension within 3 hops"
"all functions that write to ctx->ext_size"
"all source-to-sink paths from getenv to system"
```

Output: list of nodes/edges or paths, capped, with dropped count surfaced. Hugely high signal-to-token ratio compared to decompiling 30 functions one by one.

### 4.11 `run_angr`

Symbolic execution / constraint solving. The model uses this when path feasibility or solver-based input crafting is faster than fuzzing.

```
params: {
  entry: { addr | name },
  target: { addr | name | constraint: str },
  initial_state: { stdin?: artefact_id, registers?, memory? },
  timeout_seconds: int,
  exploration: "dfs"|"bfs"|"directed",
}
output: { sat: bool, model?: { stdin: bytes, registers: {...} },
          paths_explored: int, timed_out: bool }
latency: 10s - timeout (often the timeout)
```

angr is great when used surgically (single function, small input space) and a tarpit when used naively. The system prompt should explicitly say: "do not call run_angr on a whole binary; constrain to a single function or a known prefix path."

### 4.12 `submit`

Finalise. The single way to produce a finding.

```
params: {
  finding: {
    title, target, affected_versions, fixed_versions?,
    bug_class, root_cause: str, trigger: str,
    impact: "rce"|"info_leak"|"dos"|"priv_esc"|"...",
    cvss_vector?: str,
    advisory_artefact_id, poc_artefact_id?,
    crash_artefact_id?, harness_artefact_id?,
  },
  confidence: "exact"|"strong"|"medium"|"caveated",
  provenance: { primary_artifact, corroboration: [...], rejected_alternatives: [...] }
}
```

The adjudicator runs *before* the finding is persisted. It can downgrade `confidence`, force `inconclusive`, or block the submit entirely (e.g. obligations unmet, contradiction signals in `reasoning`, claim of RCE without addressing CFI on a CFI-on target).

### 4.13 `reasoning`

No tool. The LLM thinks "out loud" and emits new hypotheses, observables, rejections, or pivot intents. Cheap. Useful for: synthesising across recent observations, restructuring the case model, deciding to pivot.

Latency: zero (no dispatch). One model call.

### 4.14 Ungranted actions (intentional)

The following are *not* in the catalogue and the system prompt names them:

- raw `shell` execution as a first-class action
- `network` (no fetching from the internet)
- `git_clone` of arbitrary repos
- `pip_install` / `apt_install` of arbitrary packages

If the LLM needs a shell command, it goes through `tool_run` from the existing reasoning protocol with a strict allowlist (file inspection, hashing, `checksec`, `objdump`, `readelf`, etc.). Anything that mutates the workstation is blocked.

---

## 5. Strategy Selection

How does the LLM decide what to do this turn? Two layers.

### 5.1 The current keyword heuristic

`CyberReasoningEngine.select_strategy_family` is a list of `if any(token in joined for token in ...)` checks. For VR specifically, only `vulnerability_research` ever triggers, on tokens like `cve`, `cvss`, `advisory`, `exploitability`, `kev`, `epss`. Effectively the strategy family is pinned for VR projects.

This is **fine for the strategy family** (which is a coarse routing decision) but **insufficient for tactical strategy selection** (which function to analyse, fuzz vs audit vs diff, when to pivot). The keyword heuristic was designed for the multi-domain reasoning engine, not for VR's fine-grained per-turn choices.

### 5.2 Tactical selection — LLM-driven

Tactical choice happens inside the LLM each turn. The system prompt's "Strategy menu" is the menu; the case model is the state; the LLM picks. The deterministic layer does *not* pick the strategy — it only validates that the chosen strategy is consistent with the case state.

That said, we can scaffold the LLM with deterministic scoring:

```python
def suggest_actions(state: VRCaseState, project: VRProject) -> list[ActionSuggestion]:
    suggestions = []

    # Cheap: a hypothesis is referenced but its target function isn't in the pack
    for h in state.hypotheses:
        for ref in h.target_refs:
            if ref not in state.evidence_index:
                suggestions.append(ActionSuggestion(
                    kind="decompile",
                    rationale=f"H{h.id} references {ref}; no decomp yet",
                    information_gain="high", cost="low"))

    # Variant analysis: a confirmed bug pattern + similar untouched functions
    for confirmed in state.confirmed_findings:
        for sibling in code_graph.semantic_siblings(confirmed.func, k=5):
            if sibling not in state.audited:
                suggestions.append(ActionSuggestion(
                    kind="search_code",
                    rationale=f"variant of confirmed pattern in {sibling}",
                    information_gain="medium", cost="low"))

    # Patch diff signal not yet investigated
    for sig in state.diff_signals_unprocessed:
        suggestions.append(ActionSuggestion(
            kind="decompile",
            rationale=f"silent-fix signal in {sig.func}; not yet decompiled",
            information_gain="high", cost="low"))

    return rank(suggestions)
```

These suggestions are surfaced to the LLM as a *hint section* in the user prompt:

```
Suggested actions (engine-derived; not binding):
  - decompile parse_wrapper @ 0x401a00 — H1 cites this caller; not in pack yet
  - search_code "uint16_t.*_length\s*=" — variant search for length-truncation pattern
  - diff_versions 1.2.3 vs 1.2.4 scope=parse_extension — operator hint about silent fix
```

The LLM is free to ignore them. But suggestion quality is testable separately from LLM quality, which is good for evals.

### 5.3 Pivot decisions

When to abandon a hypothesis is the hardest tactical call. Three signals, all of them deterministic-detectable:

1. **No new observable touched the hypothesis in N turns.** Engine sets a stale flag.
2. **Coverage plateau** on a fuzzing campaign tied to a hypothesis. Engine surfaces `plateau_for=Xh` on the campaign.
3. **Operator disproved** the hypothesis via steering. Engine forces it into `rejected` next turn.

When two of these are true, the engine refuses to accept the next turn unless the LLM either:
- explicitly addresses the hypothesis (proposing new evidence collection), or
- moves it to `rejected`.

This is enforced in the adjudicator. Without it, LLMs loop on dead hypotheses.

### 5.4 Going deeper

When the LLM finds something promising, it should *not* immediately submit. The system prompt and the adjudicator collaborate to enforce a "depth ladder":

```
crash observed
  -> classify (analyze_crash)
  -> reproduce reliably (debug, run_poc)
  -> determine controlled primitive (debug, write_exploit skeleton)
  -> address mitigations (write_exploit, debug)
  -> reliability estimate
  -> submit
```

Skipping a rung is a downgrade. "Crash observed" with `confidence=strong` and `impact=rce` is rejected; the adjudicator forces `confidence=caveated` until the controlled primitive is shown.

### 5.5 Strategy choice across workflows

The two top-level workflows have different default strategies:

| Workflow | Default first action | Tactical bias |
|---|---|---|
| Open-ended research | `query_graph` (entrypoints + complexity) on source-available; `decompile` of likely entrypoint on binary-only | Breadth-first, cheap actions, build a hypothesis bank |
| N-day PoC writer | `diff_versions` between fixed and unfixed builds | Depth-first, target the patched function, write trigger then PoC |

These are bias settings on the adjudicator, not hard rules. The LLM can override with explicit reasoning.

---

## 6. Creative Bug Hunting

"Creativity" is the buzzword that gets LLM marketing into trouble. Concretely, what we want the loop to support:

### 6.1 Combination bugs

Two non-bugs in isolation that compose into an exploitable primitive. Example:

> `parse_header` allocates `total_size = header_size + payload_size` without overflow check.
> `decode_payload` later memcpys `payload_size` bytes into `buffer + header_size` where `buffer` is the allocation.
> Neither is wrong on its own (`parse_header` doesn't memcpy; `decode_payload` writes within "what was allocated").
> Together: pick `header_size = 0xFFFFFFF0`, `payload_size = 0x20`. Allocation is `0x10` bytes. Memcpy writes `0x20` bytes at `+0xFFFFFFF0`. Heap overflow.

The loop supports this only if the hypothesis structure encourages multi-source combination. We add a `derived_from: list[hypothesis_id]` field to `Hypothesis` so the LLM can explicitly synthesise:

```json
{ "id": "H7", "derived_from": ["H3", "H5"],
  "claim": "H3's allocation under-sizes H5's memcpy when total_size overflows",
  "kill_criterion": "overflow check found in parse_header before allocation" }
```

The system prompt names this as a first-class move. Without that prompt instruction, models tend to enumerate flat lists of independent hypotheses and miss cross-products.

### 6.2 Variant analysis

"Same bug class as CVE-XXXX in a different parser." The loop supports this via `query_graph` and `search_code` calls keyed off a confirmed-finding pattern:

```
Confirmed: H1 — uint16_t length read, memcpy of length+4
Variant query: search_code pattern for "uint(8|16|32)_t .*length.*=" near memcpy
Result: 4 functions in libfoo, 2 in dependencies
```

Then each variant is decompiled and evaluated. This is mechanical *given* a confirmed finding. The creative step is *recognising* a confirmed finding as a generalisable pattern, which the LLM is good at. The system prompt explicitly tells the LLM: "after submit, propose 3 variants worth investigating in adjacent code."

### 6.3 Unconventional strategy

Examples we've seen elsewhere and want to support:

- "Fuzz the error handler, not the happy path" — error recovery code is less-tested.
- "Fuzz with the binary's own test corpus, not random bytes" — gets past gating quickly.
- "Differential fuzz two versions of the same parser" — find divergences.
- "Fuzz with `setlocale` set to a weird locale" — locale-dependent integer parsing.
- "Replay protocol traces with one byte mutated at each offset" — surgical mutation.

The loop supports these because the harness format is open-ended and the LLM writes the harness. The system prompt names them as legitimate moves under "Strategy menu".

### 6.4 Inferring from absence

The most underused move. "I searched the entire length-processing chain for a bounds check and found none" is a *finding*, not a non-finding. The loop supports this by encouraging the LLM to express absence as an observable:

```json
"observables": {
  "parse_extension.bounds_check": "absent",
  "parse_extension.bounds_check.searched_via": "search_code regex + decompilation of all 3 callers"
}
```

The adjudicator treats `absent` observables as evidence (not nothing). The model is allowed to claim "no validation exists" only when an `absent` observable with explicit search method is recorded.

### 6.5 The risk of "creativity"

The danger is the LLM dressing up a guess as a creative leap. Mitigations:

- Every hypothesis has a `kill_criterion` — a falsifiable test. If the kill criterion isn't testable with available tools, the hypothesis is malformed.
- Every claim with `confidence ≥ strong` requires obligation evidence (Metis pattern).
- The deterministic adjudicator catches uncertainty laundering ("might", "could", "in theory").

Creativity that survives these gates is creativity worth keeping. Creativity that doesn't is hallucination.

---

## 7. Convergence and Termination

The loop is finite. Five distinct termination conditions; each maps to a concrete state.

| Trigger | Detector | Outcome |
|---|---|---|
| Time budget exhausted | wall-clock since project start vs `project.time_budget_minutes` | partial_results — emit current case state as a research log |
| Tool budget exhausted | sum of action costs vs `project.tool_budget` | partial_results |
| LLM proposes `submit` and adjudicator accepts | adjudicator | finding emitted, workflow transitions to advisory |
| LLM proposes `submit` repeatedly and adjudicator rejects | repeat counter ≥ 3 | escalated to operator; workflow pauses for steering |
| All hypotheses confirmed or rejected, no unsubmitted finding | case state inspector | depleted — emit "no exploitable defect found, here's why" report with rejected hypotheses as evidence-of-absence |
| Coverage plateau across all active campaigns ≥ Xh AND no new hypotheses ≥ Y turns | engine watchdog | depleted with hint to operator |
| Operator says stop | UI signal | workflow aborts, evidence preserved |

A few things I want to flag:

- "Depleted" is not failure. A documented "I tried these 14 hypotheses, here's why each was rejected, here's the campaign coverage data" is a legitimate, valuable VR output. The advisory pipeline must support `outcome="no_finding"`.
- The LLM does not decide termination — the engine does. The LLM only proposes `submit`. Letting the LLM also decide when to give up creates an out — "this is too hard, terminating" — which is exactly what we don't want.
- Operator stop is not an emergency. It happens — the operator sees the transcript and intervenes ("stop, you're going down a rathole, here's the right pivot"). The workflow handles this with the existing operator-steering machinery; the LLM resumes with new context.

### 7.1 Convergence detection

A useful signal: `hypothesis_velocity` = (new hypotheses + rejections) per turn over the last 5 turns. When velocity drops below 0.5 *and* no new observables for ≥3 turns, the LLM is spinning. The watchdog injects a "you appear stuck; either pivot or escalate to operator" instruction next turn.

This is a *prompt-time injection*, not a tool — it pressures the model without removing its agency.

---

## 8. Failure Modes

Where this goes wrong, how to detect, how to recover. Ordered by frequency I expect in development.

### 8.1 The LLM loops on a rejected hypothesis

**Shape:** turn N rejects H3. Turn N+2 proposes H7 with the same claim and a different id. Turn N+5 proposes H11.

**Detect:** semantic similarity between new hypothesis claims and existing rejections (embedding cosine ≥ 0.85) plus operator-side fuzzy text matching.

**Recover:** the engine catches the duplicate and folds H7's id into the existing H3 rejection record, surfacing in the next user prompt: "you proposed H7 which is a restatement of H3 (rejected turn N). H7 dropped." The LLM then either provides new evidence justifying revival or moves on.

If this happens 3+ times in the same case, the watchdog surfaces it to the operator: "model is looping on a dead hypothesis; consider pinning a different strategy or supplying a kill argument."

### 8.2 The LLM confabulates

**Shape:** "the crash at 0x4140 confirms a controlled write" — but no crash artefact exists. Or "the bounds check at line 87 prevents the overflow" — but line 87 does not contain a bounds check.

**Detect:** the adjudicator's evidence-obligation check. Every claim with `confidence ≥ medium` derives a list of required evidence pieces. If a claim references an artefact id that doesn't exist, the adjudicator catches it (cheap). If it references content within an artefact, the engine grep-validates the citation against the artefact body (medium cost).

**Recover:** force `confidence=inconclusive`; surface `confabulation_signal` in the next user prompt with the specific unsupported claim quoted; require the LLM to either retract or substantiate. Three confabulations in a session escalates to operator.

### 8.3 Tool output too large for context

**Shape:** decompilation of a 10K-line function. Crash log of 200K lines from ASAN. Strings dump of a 500MB binary.

**Detect:** tool wrappers always know their output size before returning; if the `truncate` flag is needed they set it.

**Recover:** truncate at the byte cap, set `truncated=true` and `dropped_lines=N` (or `dropped_chars=N`). The full output is persisted as an artefact; the LLM can request a slice via `pack_requests`. For pseudocode specifically, we slice by basic block / line range. For ASAN reports, we keep the top frame and summary; the LLM requests inner frames if needed.

This is not graceful degradation — it is the design. The LLM never sees full output. The model adapts to slicing.

### 8.4 The LLM picks the wrong strategy repeatedly

**Shape:** target is binary-only with anti-debug. LLM keeps trying to attach Frida; Frida keeps detecting. Frida is the wrong tool. The right tool is Intel PT.

**Detect:** action failure clustering. The engine groups recent action failures by (action_kind, failure_class). If the same cluster has ≥3 failures in 5 turns, the engine raises a `strategy_misfit` signal.

**Recover:** the next user prompt prefixes with "the last 3 `trace` actions failed with `frida_detected`. Consider switching framework or strategy." The LLM is free to escalate to the operator (`pivot=request_steering`) instead of guessing. The operator sees the strategy misfit explicitly and steers.

### 8.5 The LLM submits prematurely

**Shape:** action="submit" at turn 3 with `confidence=strong` and a finding that has no PoC artefact, just a hypothesis.

**Detect:** the adjudicator's submission rules. `confidence ≥ strong` requires `poc_artefact_id` (or `crash_artefact_id` for partial findings). `impact=rce` requires mitigation analysis in the reasoning text. `affected_versions` requires evidence of having tested at least one version.

**Recover:** the submit is rejected. The engine returns the failed adjudication record to the LLM next turn: "submit rejected: missing PoC artefact, mitigation analysis incomplete (CFI on target not addressed)." The LLM continues working.

### 8.6 The adjudicator is too aggressive

**Shape:** the LLM has a legitimate finding but the adjudicator keeps downgrading it because of a rule ("RCE claim requires CFI bypass" — but this target has no CFI).

**Detect:** persistent submit rejections with the same rule firing.

**Recover:** the adjudicator's rules must be data-driven, not hardcoded. The CFI rule reads `project.target_context.mitigations` and only fires when CFI is on. This pattern applies to every rule — the adjudicator validates against *the actual target*, not a generic checklist. When new rule cases emerge in development, the rule is patched, not the LLM's wording.

### 8.7 Asynchronous campaigns leak state

**Shape:** a fuzzing campaign launched at turn 5 finishes between turn 12 and 13. Turn 13's user prompt doesn't reflect the new crashes.

**Detect:** the workflow's evidence-snapshot logic must integrate campaign telemetry on every turn. The campaign service publishes events; the workflow subscribes and merges into observables.

**Recover:** belt-and-suspenders — every turn does a "campaigns delta since last turn" pull as part of building the user prompt. New crashes appear as observables. Stale state is impossible by construction.

### 8.8 The LLM produces unsafe artefacts

**Shape:** `write_exploit` produces shellcode that includes a real outbound network connection. `trace` script does `os.system("rm -rf /tmp/...")`.

**Detect:** static scan of artefact contents before persistence. Allowlist of imports, syscalls, and operations. Pattern detection for outbound network in shellcode (any `connect`, `socket(AF_INET)`, common LHOST/LPORT patterns).

**Recover:** artefact write is rejected, the LLM gets a structured rejection ("shellcode contains `connect` to external IP — disallowed"), the LLM must produce a localhost or no-connect variant. Persistent attempts escalate to operator.

This is more a containment concern than a reasoning concern, but it touches the loop because rejected artefacts must propagate back as observations the LLM can react to.


---

## 8.bis What shipped — corrections to the brainstorm

The sections above are the original design exploration. The module that shipped narrows several of them in ways worth recording in this doc so a new reader doesn't take the brainstorm as the API.

### 8.bis.1 Six personas, not three

Section 9 used to file a single-vs-split-LLM question as open. It's settled — see the persona table in §9.2. The reasoning loop ALWAYS runs through `HonestVulnResearcher.run_turn()` in `src/aila/modules/vr/agents/vuln_researcher.py`, parameterised by the per-branch `persona_voice`. Six branches deliberate in parallel; `claim_verifier.py` plus a synthesis agent reduce their outcomes to one finding.

### 8.bis.2 Auto-steering (in addition to the watchdog)

`src/aila/modules/vr/agents/auto_steering.py` runs after every tool dispatch. When a tool result matches a known dead-end pattern (`read_lines` past EOF; `read_function` returning a file header because the indexer faulted on the requested symbol; xref tool returning 0 hits despite the symbol existing), the dispatcher POSTs an operator-style message to the investigation with the corrective info — the exact same DB write the UI's chat composer makes. The agent sees it next turn under `*** OPERATOR STEERING — MANDATORY OVERRIDE ***` and cannot tell human steering apart from auto steering; that is intentional. De-dupe is keyed on `(rule, target_file, target_symbol)`. Auto-steering rules ship as `_detect_X` / `_derive_X_correction` pairs and are appended without prompt changes.

### 8.bis.3 Sibling-consensus rejection

Each branch's case state is private. Without intervention, persona Halvar keeps H1 alive forever even after Maddie + Renzo reject it. The renderer in `vuln_researcher._render_sibling_consensus` injects a `_directive.sibling_consensus_rejection` observable when two or more siblings have rejected an id that this branch still treats as live. The directive lands at PROMPT POSITION 2 alongside operator steering and is hard to ignore.

### 8.bis.4 Operator-message ACK

Operator messages persist with a per-investigation wall-clock TTL (24h). Without acknowledgement, the same message would re-render at the top of every turn within the TTL window. The agent emits `observables: {"_acked_operator_messages": "<id1>,<id2>"}` to confirm receipt; absorbed messages stop re-rendering. ACK is one of the few pieces of state the agent itself controls.

### 8.bis.5 Three submission-time gates (commit `2328b4e`)

Three correctness fixes layered onto the loop's `submit` path:

1. **Pre-submit draft-pending gate** (`vuln_researcher._maybe_reject_submit_when_draft_pending`). A branch may not submit a new outcome while it still has draft outcomes pending sibling review. The gate rejects the submit, stamps `_directive.draft_pending_submit_blocked` on case state, and forces the agent to vote on the pending drafts (`submit_outcome_review`) before the next submit attempt is admitted.
2. **Auto-approve fallback in `evaluate_quorum`** (`services/outcome_review.py`). The sibling review workflow halts a single-branch investigation indefinitely when there is no sibling to read the review request. `evaluate_quorum` now treats "no active siblings can vote" as approve-and-dispatch, with the absence logged so the operator can grep for outcomes that shipped without sibling corroboration. The pre-submit draft-pending gate is the primary mitigation; this is the safety net for investigations that predate the gate.
3. **Tightened empty-tool_run STOP threshold** (`tool_executor` handling of malformed `tool_run`). Previously the STOP message fired only after three consecutive empty / malformed commands, because the counter saw only the most recent run on the branch. The threshold now fires after the second consecutive malformed command; the STOP message names the three legal next actions (`tool_run` with valid JSON; `submit`; `observe`) and recommends `observe` when the agent is unsure.

---

## 9. Open Questions

1. **Per-turn vs per-action tool budget.** Is the budget "you have 18 turns left" or "you have 40 tool-action units, decompile=1, fuzz=8, run_angr=4"? Per-action better reflects actual cost (a 6-hour fuzz is not the same as a decompilation), but it is harder for the LLM to reason about and risks the model gaming the cost function. Leaning per-action with the costs surfaced in the user prompt — but not yet decided.

2. **Single LLM vs split-roles — settled, six personas.** Open at brainstorm time; settled in shipping code. The module ships SIX personas, three role buckets, one model task type per role:

   | Persona | Role | Routed task type |
   |---|---|---|
   | `halvar`, `noor` | researcher | `vulnerability_research.researcher` |
   | `maddie`, `yuki` | critic | `vulnerability_research.critic` |
   | `renzo`, `wei` | implementer | `vulnerability_research.implementer` |

   Source of truth: `src/aila/modules/vr/agents/persona_router.py` + `src/aila/modules/vr/agents/prompts/persona_*.md`. Auto-spawning the 5 sibling personas alongside a primary is toggled by `VR_AUTO_PERSONA_DELIBERATION` (default `1`). Synthesis + claim-verifier + PoC-writer have their own task types (`vulnerability_research.synthesizer`, `vulnerability_research.poc_writer`).

3. **Adjudicator rule maintenance.** The adjudicator's rules are the truth-keeper. Hardcoded rules will rot as target classes shift. Should adjudicator rules be expressed as a small DSL with hot-reload, so security engineers can add rules without redeploying? Or are they Python? Hardcoded Python is simpler now; a DSL becomes worth it once we have ≥30 rules.

4. **How long should the system prompt be.** The example in §2.2 is ~70 lines. Each per-class addendum is another 20-40. We can either ship one monster prompt (full menu always) or compose per-target-class. Composition is cleaner but adds another moving part (the prompt builder). Open: which scales better to 9 target classes? If composition, where does the test for "prompt was assembled correctly for target X" live?

5. **Pack_requests vs auto-expansion.** Currently the LLM asks for more context via `pack_requests`, and the next turn's pack honours it. Alternative: the engine auto-expands when it detects an unresolved reference (function name in `reasoning` but not in pack). Auto-expansion is convenient but hides what the LLM was missing. Manual is better for evals — explicit pack misses are signal. Leaning manual; revisit if it becomes a usability tax.

6. **Per-hypothesis case state vs single global state.** Right now `ReasoningCaseState` is a single object per project. For a target with 8 hypotheses across 4 sub-targets, is one big state model the right shape? Or do we partition: each hypothesis has its own evidence set, and the global state is a thin index? Partitioning helps focus per-turn evidence packs but complicates merging when two hypotheses combine into a third.

7. **N-day PoC writer reuses the same loop?** D-01 says yes — same hypothesis-action-observe shape. But the N-day workflow has a much narrower goal (crash on version X, clean on Y) and might benefit from a dedicated, simpler loop with fewer action types. The cost of a separate loop is divergent code; the cost of one shared loop is N-day prompts that have to disable half the action menu. Default: one loop, action-menu trimmed via target context. Revisit if the N-day workflow's success rate is poor under the unified loop.

8. **When does the watchdog become annoying.** The watchdog injects "you appear stuck", "you have looped on H3", "your last 3 `trace` actions failed". Too many of these and the user prompt becomes a wall of meta-feedback that crowds out evidence. We need a clear precedence: when watchdog signals are loud, real evidence may need to be moved to a separate slot or referenced by id only. Open: what is the budget for watchdog text in the user prompt?

---

## 10. Summary

The reasoning loop for VR is the forensics loop with four upgrades:

1. **Typed VR actions** replace generic `script_execute`/`tool_run` to give the LLM a concrete menu and the platform a chance to validate parameters before dispatch.
2. **Bounded evidence packs with explicit drop counts and `pack_requests`** to keep the model honest about what it has and hasn't seen.
3. **A deterministic adjudicator** that gates submissions, downgrades confabulation, blocks dead-state transitions, and adapts to per-target mitigation context.
4. **A watchdog** that detects looping, plateau, strategy misfit, and stale hypotheses, and either pressures the LLM or escalates to the operator.

Every other piece — the multi-turn structure, hypothesis bookkeeping, operator steering, durable workflow — already exists in the platform. The work is in the four upgrades and in proving they hold up against a creative-but-careless model.
