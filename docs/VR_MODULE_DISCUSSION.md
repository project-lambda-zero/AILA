# VR Module Discussion — Five Senior Personas

Five senior vulnerability researchers challenge the brainstorm. Each has a different background and cares about different things. They disagree.

---

## The Panel

| Name | Background | Bias |
|---|---|---|
| **Raven** | 15yr exploit dev. Chrome, iOS, hypervisors. CTF legend. | Everything should be about exploitation. If you can't pop a shell, you didn't find a real bug. |
| **Mika** | 10yr fuzzing infrastructure. Built fuzzing pipelines at scale (Google OSS-Fuzz style). | Fuzzing is the only strategy that scales. Everything else is artisanal. Automate or die. |
| **Dex** | 12yr reverse engineer. Firmware, embedded, ICS/SCADA. No source code ever. | Source code is a luxury. The module must work with nothing but a binary. If it needs source, it's a toy. |
| **Sol** | 8yr offensive security consultant. Pentests, red team, client-facing advisories. | Output quality matters more than finding quality. A bug with a garbage advisory is worthless. Clients pay for reports, not crashes. |
| **Kira** | 11yr kernel/driver researcher. Linux, Windows, hypervisor escape. | The module will fail on anything complex unless it understands execution context — privilege levels, address spaces, kernel vs user, driver IOCTL dispatch. Flat binary analysis is baby mode. |

---

## Round 1: What's the actual hard problem?

**Raven:** The hard problem isn't finding bugs. AFL++ finds bugs. The hard problem is *knowing what to do with a crash.* I've seen a thousand ASAN reports. 90% are NULL derefs that go nowhere. The module needs to answer "is this exploitable and how" — that's where all the value is. If it just dumps crashes on my desk, it's a worse version of `afl-tmin`.

**Mika:** Disagree. The hard problem is *target selection and harness generation.* Writing a good harness is 80% of fuzzing work. The binary has 500 functions. Which 3 should you fuzz? And once you pick one, you need to set up state correctly — initialize the library, create context objects, configure options. An LLM that can read decompiled code and generate a working harness would save me weeks per target.

**Dex:** You're both assuming the binary cooperates. The hard problem is *understanding the target in the first place.* Stripped binary, no symbols, custom calling conventions, obfuscated control flow. Before you fuzz anything, you need to understand the architecture. What's the input format? Where's the parser? What allocator does it use? The LLM needs to do real RE work — not just "decompile function X" but "trace the data flow from `recv()` through 14 function calls to the heap allocation that's going to overflow."

**Sol:** You're all missing the point. The hard problem is *communicating what you found.* I've seen exploit devs who find incredible bugs and then write a one-paragraph advisory that nobody understands. The module needs to produce output that a vendor can act on. Root cause, affected versions, CVSS justification, remediation guidance, and a PoC that reliably demonstrates the issue without being weaponized. That's harder than finding the bug.

**Kira:** The hard problem is *context.* A heap overflow in a userspace parser is different from a heap overflow in a kernel driver. The exploit strategy, the mitigations, the impact — everything changes. If the module doesn't understand privilege boundaries, it'll misclassify severity constantly. "Critical remote code execution" vs "low-severity local DoS requiring admin privileges" — the module needs to know which one it's looking at.

---

## Round 2: What will the LLM actually be bad at?

**Raven:** Exploit creativity. ROP chain construction requires understanding the specific binary's gadget landscape. The LLM will generate textbook ROP chains that don't work because the real binary has different gadgets, different alignment, different stack layout. It'll waste time generating plausible-looking exploit code that crashes on the first `ret`. The human needs to drive exploitation. The LLM assists.

**Mika:** Corpus quality. The LLM can generate a harness, but it can't generate *good seed inputs.* Fuzzing with random bytes is 100x slower than fuzzing with valid protocol messages. The module needs a way to feed real-world inputs as seeds — pcap captures, sample files, protocol recordings. The LLM can't conjure those from decompiled code alone.

**Dex:** Type recovery. Decompiled code is full of `void *`, `int64_t`, and wrong struct layouts. The LLM will hallucinate struct definitions that look right but have wrong field sizes or alignment. When it generates a harness using those types, it'll feed garbage to the target and get meaningless crashes. IDA's type recovery is already mediocre; the LLM layered on top will be confidently wrong.

**Sol:** Severity assessment. LLMs are terrible at CVSS. They'll say "9.8 CRITICAL" for every buffer overflow because that's what the training data looks like. Real CVSS scoring requires understanding the attack vector (network vs local), privileges required (none vs admin), user interaction (none vs click), scope change, and the specific deployment context. The module needs to *calculate* CVSS, not have the LLM *guess* it.

**Kira:** Mitigation awareness. The LLM will say "heap overflow, exploitable" without checking ASLR entropy, CFI enforcement, shadow stack, MTE (on ARM), CET (on Intel). Modern binaries have layers of mitigations. A crash that's trivially exploitable on a 2015 binary might be impossible on a 2025 binary with full hardening. The module needs to *check* mitigations, not assume they're absent.

---

## Round 3: What's missing from the brainstorm?

**Raven:** *Debugging infrastructure.* The brainstorm mentions GDB but doesn't treat it as a first-class tool. Exploit development is 90% debugging. The module needs to:
- Set breakpoints
- Inspect heap state (tcache bins, unsorted bin, chunk metadata)
- Track allocations (who allocated, who freed, what size)
- Single-step through the vulnerable path
- Examine register state at the crash point

Without this, it can find bugs but can't develop exploits. GDB scripting via the SSH connection is mandatory.

**Mika:** *Campaign parallelism.* One fuzzing campaign is cute. Real fuzzing runs 100 instances in parallel with shared corpus synchronization. The module needs to:
- Launch N AFL++ instances on different cores
- Sync corpus between instances
- Aggregate coverage metrics across instances
- Handle instance crashes/restarts
- Scale up/down based on coverage plateau

Also missing: *persistent mode harnesses.* In-process fuzzing (`__AFL_LOOP`) is 10-50x faster than fork mode. The harness generator should produce persistent-mode harnesses by default.

**Dex:** *Binary unpacking and deobfuscation.* Real targets aren't clean ELFs. They're:
- UPX packed
- Custom packed (malware)
- Virtualized (Themida, VMProtect)
- Go/Rust binaries with stripped symbols and massive statically-linked stdlib
- Firmware blobs with no file format headers

The module needs a pre-analysis phase that identifies and handles these. IDA alone won't cut it for packed binaries.

**Sol:** *Responsible disclosure workflow.* When you find a real bug in a real product, you don't just dump the exploit. You need:
- Vendor contact information lookup
- Disclosure timeline tracking (90 days standard)
- Embargo management (don't leak before patch)
- CVE reservation (MITRE, CNA)
- Coordinated release of advisory + PoC

This is out of scope for v1, but the data model should support it. A finding should have a `disclosure_status` field from day one.

**Kira:** *Execution environment simulation.* To know if a kernel bug is exploitable, you sometimes need to run the exploit in a VM with the exact kernel version. The module should be able to:
- Spin up a QEMU/KVM instance with a specific kernel
- Deploy the PoC
- Observe the result (crash, privilege escalation, no effect)
- Report back

This is heavy infrastructure. Maybe v2. But the architecture should anticipate it — don't bake in assumptions that the target runs on the research workstation itself.

---

## Round 4: What should v0.1 actually do?

**Raven:** N-day PoC writer. Input: CVE + patch commit. Output: working crash PoC. Skip exploitation for v0.1 — just demonstrate the bug triggers. This proves IDA integration, patch diffing, and PoC generation work. One workflow, tight scope, clear pass/fail.

**Mika:** Disagree. Automated harness generation + single fuzzing campaign. Input: binary + function name. Output: harness + 8-hour campaign + triaged crashes. This proves the fuzzing pipeline works end-to-end. A crash you found yourself is worth more than a PoC for a known bug.

**Dex:** Binary recon only. Input: stripped binary. Output: attack surface map, function classification (parser/handler/allocator/crypto), ranked targets for further research. No fuzzing, no exploitation. Just prove the LLM can understand a binary deeply enough to guide a researcher. If it can't do this, nothing else works.

**Sol:** I'm with Raven but add the advisory output. N-day PoC + formatted advisory. The advisory generation is trivial compared to the PoC, and it proves the full value chain: bug understanding -> PoC -> communication. Ship something a researcher would actually email to a vendor.

**Kira:** Binary recon + mitigation analysis. Input: binary. Output: architecture, protections (checksec-style but deeper — CFI? MTE? ASAN? Fortify?), attack surface, complexity per function, and a ranked target list with exploitation difficulty estimates considering the actual mitigations. This is what I check first on every engagement. If the module can do this accurately, I'll use it.

---

## Round 5: Where does human-in-the-loop actually matter?

**All agree on these:**

1. **Strategy pivots.** The LLM fuzzes a target for 4 hours with no crashes. Should it continue or pivot? The LLM should recommend, the human should decide. Premature pivots waste the warm-up; late pivots waste hours.

2. **Exploitability judgment.** "This heap overflow is 2 bytes past the allocation boundary. Exploitable?" — this is a judgment call that depends on allocator internals, heap layout, and what objects are adjacent. The LLM should analyze, the human should confirm.

3. **Scope expansion.** The module finds a bug in `libfoo`. Should it look for the same pattern in `libbar`? The LLM should suggest variant analysis, the human should approve scope creep.

4. **External context injection.** "FYI, this vendor shipped a silent fix in 2.3.1 but didn't issue a CVE. Diff against 2.3.0." — only the human knows this.

5. **Go/no-go on exploit development.** Finding a bug is one thing. Spending 3 days developing a reliable exploit is another. The human decides if it's worth the investment.

**Disagreements:**

**Raven:** The human should drive exploitation entirely. The LLM assists with "find me gadgets matching X" or "what's the offset to RIP" but doesn't generate the full exploit chain.

**Mika:** The human should curate the seed corpus. The LLM generates harnesses; the human provides real-world inputs. A protocol researcher has sample captures that are gold for fuzzing — the LLM can't generate those.

**Kira:** The human validates the module's understanding of the target. "The module thinks this is a userspace parser. Actually it's a kernel module loaded via ioctl. That changes everything." Misclassification of execution context is the highest-impact LLM error.

---

## Emerging Consensus

1. **v0.1 = N-day PoC writer** (Raven + Sol win). Tightest scope, clearest success metric, exercises IDA + diffing + PoC generation. Add advisory output.

2. **v0.2 = Binary recon + target ranking** (Dex + Kira). Attack surface mapping, mitigation analysis, function classification. Foundation for everything else.

3. **v0.3 = Fuzzing pipeline** (Mika). Harness generation, campaign management, crash triage. Builds on recon (v0.2 tells you what to fuzz).

4. **v0.4 = Full research workflow** (all). Combines all pieces. Hypothesis-driven, multi-strategy, human-in-the-loop.

5. **Data model must support all four from day one.** Don't paint yourself into a per-CVE corner. Project -> Target -> Work Item (N-day task OR research hypothesis).

6. **Mitigation checking is non-negotiable from v0.1.** Even the N-day PoC writer needs to know "this binary has full RELRO + PIE + stack canary + ASLR" before claiming a PoC works.

7. **The LLM is the researcher, not the toolsmith.** It reasons about *what to investigate and why.* It delegates execution to tools (IDA, AFL++, GDB, compiler). The human steers the research direction and validates findings.

8. **Advisory quality is a first-class concern.** Not an afterthought. The output must be vendor-ready from v0.1.

---

## Gray Areas Still Open

1. **How does the module handle targets it doesn't understand?** Obfuscated binaries, custom architectures, firmware blobs without standard headers. Fail loudly? Attempt best-effort? Ask the human?

2. **How long is a fuzzing campaign?** Minutes for a smoke test, hours for real coverage, days for thorough research. Who decides? LLM recommends based on coverage trajectory, human approves?

3. **What happens when the research workstation runs out of disk/RAM?** Fuzzing generates GB of corpus and crash inputs. Campaign monitoring needs resource awareness.

4. **Should the module re-use findings across projects?** "I found this heap allocator pattern is vulnerable in project A. Project B uses the same allocator." Cross-project knowledge is valuable but raises scope/confidentiality questions.

5. **How does the module handle anti-analysis?** Targets that detect debugging, refuse to run under ASAN, or have integrity checks. Real-world targets do this. The module needs anti-anti-analysis strategies.

6. **When the LLM is wrong about exploitability, how does the module recover?** It says "exploitable," the human spends 2 days, and it turns out the overflow is 1 byte and not controllable. The evidence graph should capture the failed attempt so the same mistake isn't repeated.

7. **What about network-reachable targets?** The brainstorm assumes local binary analysis. But many vulnerabilities are in network services. Should the module support remote fuzzing (network protocol fuzzing against a running service)?

8. **Collaboration between the VR module and the forensics module.** "Forensics found a suspicious binary during an investigation. Hand it to VR for analysis." Should there be a formal handoff workflow?

9. **How does the module handle closed-source dependencies?** The target binary calls `libcrypto.so`. The bug is in the target's usage of the library, not the library itself. The module needs to understand API contracts without having library source.

10. **What about hardware-specific bugs?** Side channels, speculative execution, DMA attacks. These can't be found by fuzzing or static analysis. Out of scope? Or should the module at least identify *potential* side-channel exposure?
