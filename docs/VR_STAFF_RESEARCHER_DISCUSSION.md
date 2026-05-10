# VR Module Deep Review — 5 Staff Vulnerability Researchers

## Personas

### S1: "Halvar" — Staff Exploit Engineer, 15yr
**Track record:** Wrote the first reliable ASLR bypass for iOS. Discovered 40+ kernel vulns. Built internal exploit development pipelines at two vendors. Thinks in terms of primitives, constraints, and reliability. Hates hand-wavy "the attacker could theoretically..." statements. Either you have a PoC or you have nothing.

### S2: "Maddie" — Staff Security Researcher, Binary Analysis Lead
**Track record:** Built the binary diffing pipeline at a major MSRC-class org. Ships patch Tuesday analysis within 4 hours of release. Has seen every pattern of vendor patch — the incomplete ones, the accidentally-introduced-new-bugs ones, the "fix the symptom not the cause" ones. Thinks about what the DIFF tells you vs what it hides.

### S3: "Yuki" — Staff Fuzzing Engineer, Kernel
**Track record:** Maintains a syzkaller fleet finding 200+ kernel bugs/year. Expert at crash triage at scale. Has opinions about what "exploitable" means (most crashes aren't). Cares about the pipeline from "crash" to "root cause" to "is this worth writing up." Thinks most automated tools produce garbage without human curation.

### S4: "Renzo" — Staff Vulnerability Researcher, Web/App Security
**Track record:** Found critical logic bugs in OAuth implementations, payment systems, and cloud IAM. Never touches a debugger — works at source level. Thinks the binary analysis community overestimates how many real-world vulns are memory corruption. Most impactful vulns in 2024 are logic bugs, auth bypasses, and SSRF chains.

### S5: "Noor" — Staff Security Engineer, Exploit Mitigation & Defense
**Track record:** Designed CFI and shadow stack implementations at a silicon vendor. Knows every mitigation by its failure modes. Evaluates exploit feasibility against real-world deployments — not academic "assume ASLR is disabled" scenarios. Thinks most PoCs are demo-ware that wouldn't work against a hardened target.

---

## Topic 1: Is the 30-Turn N-day Agent Loop the Right Architecture?

**Halvar:** 30 turns is arbitrary and wrong for different classes of bugs. A heap overflow in sudo where the patch is a one-line bounds check? 5 turns max — diff, decompile the function, read the bounds, classify, done. A type confusion in nf_tables where you need to understand the netlink protocol, the set element lifecycle, and the race condition? 30 turns isn't enough. The budget should be adaptive — start with 10, extend on evidence of progress.

**Maddie:** The turn count isn't the real issue. The issue is what the agent DOES in each turn. I've watched automated systems burn 25 turns decompiling irrelevant functions because they don't know where to look. The diff is ALWAYS the first action for N-day work. If you have the patch, you know EXACTLY which function changed. The agent should enforce: turn 1 = diff. Always. No "reasoning about where to start." That's wasted inference.

**Yuki:** For MY use case (crash triage from fuzzing), there's no patch to diff. The input is a crash report + the binary. The agent needs to: (1) parse the ASAN report, (2) decompile the crashing function, (3) trace the corrupted pointer back to its allocation, (4) determine if the corruption is controllable. That's 4 actions, not 30. The overhead of the LLM reasoning about "what should I do next" is wasted when the protocol is fixed.

**Renzo:** For source-level bugs — SSTI, SQLI, auth bypass — you don't decompile anything. You read source code. You trace data flow from user input to dangerous sink. The 30-turn loop with IDA bridge actions is wrong for my entire domain. Source audit needs: `grep`, `read_file`, `trace_call_graph` (static, not IDA), and `reason_about_logic`. Completely different action set.

**Noor:** The obligation system is the right idea — don't let the agent claim things it hasn't proven. But 30 turns of LLM inference costs ~$5-15 at current rates. For a Tier 1 CVE that a human would analyze in 20 minutes, you're spending more on compute than the analysis is worth. The system needs a cost-aware fast path: if the diff is trivial (one function changed, one bounds check added), skip the multi-turn loop entirely and go straight to advisory generation.

### Consensus
- **Adaptive budget, not fixed.** Start at 10 turns. Extend by 5 when the agent demonstrates forward progress (new obligation met). Cap at 50.
- **Enforced first action for N-day:** `diff_versions` when patched binary is available. No reasoning about where to start.
- **Fast-path for trivial diffs:** If diff shows exactly one function with one bounds-check addition, skip the research loop — classify immediately (overflow, compute CVSS, generate advisory). 3 turns max.
- **Separate action vocabularies per workflow type:** N-day binary (IDA), crash triage (ASAN parse → decompile → trace), source audit (grep → read → trace → reason). Don't force all into one action set.
- **Cost tracking in the prompt:** Show the agent its dollar spend per turn. "You've spent $2.40 / $8.00 budget." Creates implicit pressure to be efficient.

---

## Topic 2: Is the Evidence Obligation System Strict Enough?

**Halvar:** The obligation system blocks submission without evidence. Good. But it doesn't verify the evidence is CORRECT. The agent can decompile function X, claim "the overflow is in line 42," and the obligation is "met" because it produced a decompile result. But what if line 42 is a perfectly safe operation and the bug is in line 87? The system doesn't validate SEMANTIC correctness of the agent's claims against the evidence.

**Maddie:** This is the fundamental limitation of any LLM-based system. The obligation system ensures the agent DID the work (produced the diff, decompiled the function). It cannot ensure the agent UNDERSTOOD the work correctly. That's what the adjudicator's hedge-phrase detection tries to catch — if the agent says "might be" or "could potentially," it's not confident, so downgrade. But a confidently wrong agent passes the obligations.

**Yuki:** For crash triage, you CAN validate mechanically. If the agent says crash_type=overflow_heap but the ASAN report says "use-after-free," that's a machine-checkable contradiction. Add a post-hoc validation step: compare the agent's claimed crash_type against the parsed ASAN output. If they disagree, the finding is flagged for human review rather than auto-published.

**Renzo:** For logic bugs, there's no ASAN report to validate against. The agent's claim IS the evidence. "This endpoint accepts a negative quantity, bypassing the payment check." You can't mechanically verify that without running the PoC against a live system. The obligation system for source-level work should require: (1) specific code path cited, (2) PoC script that demonstrates the issue, (3) PoC exit code confirms the claim. If the PoC doesn't trigger the bug, the finding is invalid.

**Noor:** The obligation system should have a CONFIDENCE TIER for each finding:
- **Proven:** PoC crashes the vulnerable version AND clean-exits the patched version.
- **Demonstrated:** PoC triggers the condition but doesn't achieve full exploitation (e.g., crash but not code exec).
- **Claimed:** Agent asserts the bug exists based on code analysis but has no working PoC.
- **Speculative:** Agent identifies a suspicious pattern but hasn't confirmed it's reachable.

Right now, the system treats "PoC crashes" and "agent says it's a bug" as the same confidence level. That's dangerous for automated advisory generation.

### Consensus
- **Add confidence tiers** to findings: proven (PoC verified), demonstrated (crash confirmed), claimed (code analysis only), speculative (pattern-match without confirmation).
- **Machine-checkable post-hoc validation:** Compare agent's claimed crash_type against ASAN-parsed crash_type. Flag contradictions.
- **PoC verification as obligation gate:** For the advisory to emit CVSS > 0, the PoC must have run. "Advisory without PoC" gets a DRAFT watermark and lower confidence tier.
- **Human review flag:** Any finding where the agent's reasoning contradicts the tool output gets auto-flagged. Don't suppress it — surface it to the operator with "REVIEW: agent claim vs evidence mismatch."

---

## Topic 3: How Should the System Handle Patches That Introduce New Bugs?

**Maddie:** This is my specialty. 15% of patches I analyze introduce a new variant of the same bug or a related bug. The vendor fixes the specific trigger but not the root cause. Example: they add a bounds check for `len > 256` but the actual limit should be `len > buffer_size` — and buffer_size is 128. The agent should check: does the patch fully address the root cause, or just the specific trigger?

**Halvar:** This is where the diff analysis gets interesting. The agent shouldn't just say "patch adds a check." It should say: "patch adds check X. The root cause is Y. Check X prevents the KNOWN trigger but does NOT prevent condition Z which also reaches the same vulnerable code." That's variant analysis — and it's where the real value is. An agent that just confirms the known CVE is doing journalism, not research.

**Yuki:** Variant hunting is a v0.3 capability. For v0.1, the agent should at minimum flag: "I notice the patch checks length against a constant (256) rather than the actual buffer size. This may be an incomplete fix." That's a `RECOMMENDED` obligation: `patch_completeness_assessed`. Not blocking, but surfaced.

**Renzo:** For source-level bugs, incomplete patches are EXTREMELY common in web frameworks. "We added input validation for the email field, but the same injection works via the username field." The agent should enumerate ALL paths to the same sink, not just the one the CVE describes.

**Noor:** From the defense perspective: the agent should report whether the patch's protection is sufficient even if an attacker uses a different trigger. "The patch adds a null check before the memcpy. But an attacker can reach the same memcpy via path B which doesn't go through the null check." That's the difference between "patched" and "mitigated."

### Consensus
- **Add `patch_completeness_assessed` as a RECOMMENDED obligation** for N-day work.
- **Agent prompt should include:** "After identifying the root cause, check whether the patch addresses ALL paths to the vulnerable condition, or only the specific trigger described in the CVE."
- **Variant detection prompt:** "Are there other callers of the vulnerable function that bypass the patch's validation?" — this becomes a standard question the agent asks after understanding the fix.
- **Not blocking for v0.1.** Surface it as a secondary finding if detected. "Possible incomplete fix: path B may still reach the vulnerable condition."

---

## Topic 4: The IDA Bridge — Is HTTP-to-MCP the Right Integration Pattern?

**Halvar:** HTTP adds latency. Every decompile call is a network round-trip. For 30 turns where each turn might decompile 2-3 functions, that's 60-90 HTTP calls. If the MCP server is on the same machine, Unix sockets would be 10x faster. But if it's on a different machine (dedicated analysis server with enough RAM for large IDBs), HTTP is the only option.

**Maddie:** The real question is: should the agent interact with IDA at the function level or the binary level? Right now, each action decompiles one function. But for patch analysis, I want to see the ENTIRE diff — all changed functions at once — in one call. The `diff_binary` tool does this, but the result can be huge (10+ changed functions × 200 lines each = 2000 lines). The evidence pack truncates it. You lose context.

**Yuki:** For my workflow, I don't need IDA at all for the initial triage. ASAN gives me the crash location, the corrupted address, and the stack trace. I need IDA only for deep analysis: "what code path leads to the controllable allocation?" That's a targeted query, not a full-binary scan. The agent should be able to say "I don't need IDA for this finding" and skip the expensive analysis.

**Renzo:** The IDA bridge is irrelevant for source-level work. I need a CODE SEARCH tool — grep with semantic awareness. "Find all calls to `eval()` where the argument comes from user input." That's a static analysis query, not a decompilation query. For v0.3 source audit, we need a semgrep/CodeQL integration alongside IDA.

**Noor:** The checksec output is the most underrated tool in the pipeline. Before the agent spends 25 turns understanding the bug, it should check: is this binary compiled with full RELRO, stack canary, NX, PIE, CFI, and CET? If yes, the bug might be UNEXPLOITABLE even with a perfect understanding of the vulnerability. The agent should assess exploitability AGAINST the actual mitigations, not in a vacuum.

### Consensus
- **HTTP is fine for v0.1.** Latency is acceptable (120ms per call × 60 calls = 7 seconds total — negligible vs 4-hour budget).
- **Batch decompile for diffs:** When diff_binary returns 5+ changed functions, automatically batch-decompile all of them into the evidence pack. Don't make the agent individually request each one.
- **Skip-IDA fast path:** For ASAN-based triage where the crash is already classified by the sanitizer, the agent can skip decompilation if it has enough information from the report alone.
- **Exploitability-aware reasoning:** After checksec, the agent's prompt should include: "The target has [NX, canary, ASLR, CFI]. Assess whether the vulnerability is exploitable GIVEN these mitigations. Do not assume mitigations are disabled."
- **v0.3 source tools:** Integrate semgrep or a grep-with-context tool for source-level work. IDA bridge stays for binary targets.

---

## Topic 5: What Does "Working PoC" Actually Mean? The Reliability Standard.

**Halvar:** 5/5 is a toy metric. A PoC is "reliable" when it works on the target configuration the advisory describes. If the advisory says "Ubuntu 22.04 with default packages," the PoC must work on that exact setup. If it only works on a custom debug build with ASAN enabled, it's not a PoC — it's a crash sample. Different things.

**Maddie:** The PoC has three purposes: (1) prove the bug exists (crash), (2) prove the patch fixes it (no crash on patched), (3) prove the impact (code execution, not just DoS). For v0.1, I'd accept crash-only as proof of existence. Code execution PoCs are v0.4+ (full exploit development). But the advisory MUST distinguish between "crashes the process" and "achieves code execution."

**Yuki:** Most of my fuzzer crashes are NOT exploitable. They crash, but the corrupted state can't be steered to RIP control. The PoC runner should classify: "crash = confirmed," but "exploitable = unproven" unless the agent demonstrates control. A PoC that triggers SIGSEGV on a null deref is worth much less than one that overwrites a return address. The CVSS should reflect this distinction.

**Renzo:** For logic bugs, there's no "crash." The PoC is a script that demonstrates the bypass. "Send this HTTP request → get admin access." Exit code 0 with a specific response body is "success." The PoC runner needs to support assertion-based validation, not just "did it crash?" Binary crash semantics (exit 139 = good) don't apply to web vulns.

**Noor:** The 5/5 reliability metric is misleading. If the PoC works 5/5 times on the test setup but 0/5 on a production system with ASLR entropy, it's not reliable — it's setup-dependent. The advisory should state: "PoC tested on [exact OS, exact binary version, exact kernel, ASLR state, heap layout assumptions]." Without this context, the 5/5 number means nothing.

### Consensus
- **Three-level PoC classification:**
  1. **Crash PoC** — triggers a memory error (SIGSEGV, SIGABRT, ASAN report). Proves the bug exists. Sufficient for advisory publication with CVSS reflecting DoS impact only.
  2. **Controlled PoC** — demonstrates controllable corruption (writes attacker-supplied value to attacker-chosen address, or hijacks control flow to attacker-chosen target). Proves exploitability. CVSS reflects full impact.
  3. **Exploit** — achieves a security-relevant outcome (code execution, privilege escalation, data exfiltration). Full weaponization. Out of scope for v0.1.
- **Environment specification mandatory:** Every PoC finding records: OS, target binary hash, ASLR state, kernel version. Without this, the 5/5 number is meaningless.
- **Assertion-based PoC for logic bugs:** The PoC runner needs a mode where "success" is defined by a regex match on stdout or a specific HTTP response code, not by a crash signal.
- **v0.1 scope:** Crash PoC only. Controlled PoC is v0.2. Exploit is v0.4+. The advisory MUST say "Denial of Service confirmed" not "Remote Code Execution" unless control is demonstrated.

---

## Topic 6: What About False Positives? When Should the System NOT Produce a Finding?

**Halvar:** The worst thing an automated system can do is cry wolf. If it reports 10 vulns and 3 are false positives, operators stop trusting it after the first false positive. The system should have a HIGHER BAR for reporting than for investigating. Investigate everything, report only when certain. "I analyzed this and it's not exploitable" is a valid and useful output.

**Maddie:** Patch analysis has a specific false positive pattern: the agent sees a code change and assumes it's a security fix, but it's actually a feature change or refactoring. Not every bounds check addition is a security fix. The agent needs to assess: "Is this change addressing a security condition, or is it just defensive programming?" If it can't tell, it should say "inconclusive" not "vulnerability."

**Yuki:** At fuzzing scale (200 crashes/day), 90%+ are non-security-relevant. Null derefs in error paths, assertion failures in debug builds, stack overflows from infinite recursion in malformed input (DoS, not RCE). The triage system MUST filter these. The exploitability heuristic is the filter. "null_deref" → auto-classify as LOW/unlikely. Don't waste agent turns on it.

**Renzo:** For source-level analysis, the false positive rate of pattern matching (semgrep, grep) is 60-80%. The LLM's job is to REDUCE that rate by reasoning about reachability and exploitability. "Yes, there's an eval() call, but the argument is always a hardcoded constant from the codebase." That's NOT a vulnerability. The agent must prove the taint flows from user input to the dangerous sink.

**Noor:** The system should have a "DISPROVEN" status for investigations. Not just "no finding" — but "investigated and confirmed NOT vulnerable." This is valuable for audit trails: "We analyzed CVE-2024-XXXX against our deployment and confirmed it does not affect us because [specific technical reason]." The absence of a finding is information too.

### Consensus
- **Add `DISPROVEN` as an investigation outcome** — "investigated and confirmed not vulnerable / not exploitable." Include the reason.
- **Higher reporting bar than investigating bar:** The agent investigates broadly but only reports when critical obligations are met AND the adjudicator doesn't detect hedge phrases.
- **Exploitability filter for crash triage:** `null_deref` and `info_disclosure` crash types get auto-classified as LOW and don't trigger full analysis unless the agent has specific reason to promote them.
- **"Inconclusive" is a valid output:** The system should output "investigated but could not determine exploitability" rather than guessing. This goes into a review queue, not into the advisory pipeline.
- **False-positive tracking metric:** Track the rate at which findings are later retracted or downgraded. If it exceeds 10%, tighten the obligation requirements.

---

## Topic 7: The Disclosure Tracking — Is the State Machine Correct?

**Halvar:** `undisclosed → reported → acknowledged → patch_pending → patched → public` is the IDEAL flow. In reality: you report, the vendor ghosts you for 90 days, you publish anyway. Where's the "vendor_unresponsive → forced_disclosure" path? And the "vendor disputes the severity" state?

**Maddie:** The embargo date is the critical field. When `embargo_until` passes and the status is still `reported` or `acknowledged`, the system should automatically flag: "EMBARGO EXPIRED — vendor has not provided a fix. Operator action required: publish or extend?" This is a deadline, not a suggestion.

**Yuki:** I don't do disclosure. I file kernel bugs on the public mailing list. For upstream Linux, there's no vendor relationship — it's a public tracker. The disclosure status for kernel bugs should be: `reported → patch_submitted → patch_merged → release_containing_fix`. Different lifecycle entirely.

**Renzo:** For web vulns, the disclosure timeline is compressed. You find it Monday, report Tuesday, they patch Wednesday (or they don't and you publish Friday). The 90-day embargo is a binary/OS thing. Web teams expect 7-14 day turnarounds. The system should support configurable disclosure policies per target organization.

**Noor:** From the vendor side: when I receive a report, I need to: (1) reproduce it, (2) assess severity, (3) develop a fix, (4) test the fix, (5) coordinate disclosure timing with the reporter. The system should track the VENDOR'S progress, not just the reporter's state transitions. "Vendor confirmed → fix in development → fix in QA → fix released" is the vendor's parallel state machine.

### Consensus
- **Add states:** `vendor_unresponsive` (no reply after configurable timeout, default 30 days), `disputed` (vendor disagrees with severity/exploitability).
- **Embargo enforcement:** When `embargo_until < now()` AND status NOT in (`patched`, `public`), auto-flag with "EMBARGO EXPIRED" banner in UI.
- **Configurable disclosure policy:** Per-project setting: standard (90 days), accelerated (30 days), immediate (0 days for actively exploited), kernel (public-first).
- **Vendor progress tracking** is v0.2 — parallel state machine for the vendor side. v0.1 tracks only the researcher's perspective.
- **Auto-escalation:** If status stays at `reported` for > 14 days with no `vendor_contact` response, auto-transition to `vendor_unresponsive` and notify the operator.

---

## Final Recommendations for v0.2 Roadmap

| Priority | Item | Owner Persona | Effort |
|---|---|---|---|
| P0 | Adaptive budget (start 10, extend on progress) | Halvar | 2 days |
| P0 | Confidence tiers on findings (proven/demonstrated/claimed/speculative) | Noor | 1 day |
| P0 | Enforced diff-first for N-day + fast-path for trivial patches | Maddie | 2 days |
| P1 | Assertion-based PoC runner for logic bugs | Renzo | 3 days |
| P1 | Post-hoc validation (agent claim vs ASAN-parsed type) | Yuki | 1 day |
| P1 | Environment specification on PoC findings | Halvar | 1 day |
| P1 | DISPROVEN outcome + inconclusive handling | Yuki | 1 day |
| P1 | Embargo enforcement + auto-escalation | Maddie | 2 days |
| P2 | Batch decompile on multi-function diffs | Maddie | 1 day |
| P2 | Exploitability-aware prompting (mitigations in context) | Noor | 1 day |
| P2 | patch_completeness_assessed obligation | Maddie | 1 day |
| P2 | Source audit action vocabulary (grep, read_file, trace) | Renzo | 5 days |
| P2 | Configurable disclosure policy per project | All | 1 day |
| P3 | Vendor-side state machine | Noor | 3 days |
| P3 | Variant hunting (enumeration of paths bypassing patch) | Halvar | 5 days |
| P3 | Controlled PoC (demonstrate RIP control, not just crash) | Halvar | 5 days |
