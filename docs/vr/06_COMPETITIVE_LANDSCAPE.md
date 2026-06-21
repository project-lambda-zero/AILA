# VR Module — Competitive Landscape: Where We Fit

Honest assessment of what's actually shipping in LLM-driven vulnerability research as of mid-2026, what each system does well, what each is silent about, and where the AILA VR module's design carves out a defensible position. No marketing claims, no head-to-head benchmarks we haven't run, no "we're better than X" without a concrete axis.

The framing this document defends: **we are not building a frontier model and not building a SaaS platform. We are building the orchestration layer between a frontier model and a research workstation.** Everything below either supports or stress-tests that framing.

---

## 1. OpenAI Aardvark

### What it actually does

Aardvark is positioned as an autonomous security researcher agent. Its public scope is well-defined and narrower than the marketing implies:

- Source-code ingestion, AST-aware indexing, repo-scale.
- Vulnerability *detection* across a fixed taxonomy: classic injection sinks, deserialization, path traversal, SSRF, authn/authz misuses, common memory-safety smells in C/C++ source, plus a model-driven "novel pattern" tier that tries to flag things the catalog misses.
- Severity assessment with a CVSS-style rubric, plus reachability annotations from a static call graph.
- Patch *proposals*: concrete diffs that the human reviews and merges.

### The 92% number, in context

The published 92% detection rate is on a "golden repos" benchmark — a curated set of repositories with known vulnerabilities, source available, and annotation ground truth. That is a meaningful signal about ceiling, not floor:

- The benchmark has labels. Production code has none. The model's precision on labeled corpora and recall on unlabeled corpora are different distributions.
- The benchmark is source. Aardvark does not consume binaries, decompiled output, or stripped artifacts. A vendor shipping `vendor.so` with no source gets nothing from Aardvark.
- The benchmark assumes the bug is reachable from a known entry point. Many real bugs sit in dead code or behind feature flags; Aardvark's reachability heuristic is whole-program but not interprocedural across dynamic dispatch.

### What Aardvark explicitly does not do

- **No binary analysis.** No IDA, no Ghidra, no decompilation pipeline. Stripped consumer firmware is out of scope.
- **No exploitation.** A vulnerability claim is a static finding plus optional patch. No PoC generation, no crash reproducer, no exploit primitive.
- **No fuzzing.** No harness generation, no campaign management, no coverage feedback.
- **No multi-target campaigns.** One repo at a time. There is no concept of cross-binary chains, shared library blast radius, or product-level posture.
- **No human-in-the-loop steering during reasoning.** Aardvark runs to completion and presents results. The operator does not interrupt mid-investigation to inject context.

### How we differ

| Axis | Aardvark | AILA VR |
|---|---|---|
| Inputs | Source repos | Source repos + binaries + firmware images + live processes |
| Output | Findings + patches | Findings + crash reproducers + exploit PoCs + chains + posture report |
| Coverage | Static analysis on AST | Static + dynamic (fuzzing) + symbolic (angr) + live debugging |
| Unit of work | One repo | Project = N targets in a dependency graph (see §4 in `04_MULTI_TARGET.md`) |
| Reasoning persistence | Per-run | Persistent across sessions, evidence graph survives operator handoff |
| Operator role | Reviewer of completed report | Steering at every turn (see §6 in `01_REASONING_LOOP.md`) |

The honest summary: Aardvark and the VR module are not the same product. Aardvark is closer to "Snyk + an LLM that writes patches." The VR module is closer to "a research lab in a box that uses a frontier LLM as its primary investigator." We could ingest Aardvark's findings as one signal among many; we cannot replace it with our pipeline because we don't index source repositories at the scale they do.

### Where Aardvark would beat us

- Fast triage of a large monorepo with source. Aardvark's indexing infra is purpose-built; ours is not.
- Patch generation for catalog bugs. Their tight feedback loop on patch acceptance gives them training signal we don't have.
- Compliance use cases (run nightly on `main`, file findings in Jira). That's a fundamentally different workflow than research.

---

## 2. Anthropic Glasswing / Claude Mythos / Opus

### What this actually is

Glasswing is Anthropic's frontier security research stack. It is not one product; it's at least three things bundled in messaging:

1. **Opus 4.6**, a general-purpose frontier model that happens to be unusually capable at security reasoning.
2. **Mythos Preview**, a domain-specialized variant tuned for vulnerability research and exploit development.
3. **An internal harness** Anthropic uses to drive these models against real targets. The harness is not a public product as of mid-2026.

The published numbers, which are real and verified by external researchers:

- **Opus 4.6 on Firefox**: 22 distinct vulnerabilities, 2 working JS engine exploits out of hundreds of attempts.
- **Opus 4.6 on open source at large**: 500+ vulnerabilities across the corpus, mostly memory-safety and logic bugs in C/C++ projects with available source.
- **Mythos Preview on FreeBSD kernel**: 181 working exploits derived from previously-disclosed bugs, plus register control on 29 additional bugs without proceeding to full exploitation. Thousands of high-severity findings in adjacent kernel codebases.

### What it is and what it isn't

Mythos is a **model capability**, not a tool. It does not come with:

- A reasoning loop with state machine and turn budget.
- A workstation it runs on.
- A tool registry with IDA, angr, AFL++, GDB.
- Evidence tracking, obligation system, adjudication.
- Persistent project state, evidence graph, session resume.
- A UI a non-Anthropic operator can drive.
- Multi-target scheduling, fuzzing campaign management, disclosure tracking.

The 181 FreeBSD exploits did not come from "ask Mythos to find FreeBSD bugs." They came from Anthropic researchers hand-driving a harness — selecting candidate bugs from the public CVE list, feeding the model patches and crash reproducers, iterating until exploits worked. The intelligence is in the model; the workflow is humans plus glue code.

This is the most important framing in this document: **Mythos's published results are achieved with a scaffold whose properties closely resemble the AILA VR module's design.** Anthropic's scaffold is not public. Ours is the bet that an open scaffold optimized for operator productivity can reach a substantial fraction of those results on operator-defined targets.

### How we differ

We are not competing with the model. We are designed to *consume* it.

- The VR module's reasoning loop calls Anthropic's API (or OpenAI's, or a local model — see D-08 for routing) and treats the response as one signal in a larger workflow.
- Operator steering (§6 in `01_REASONING_LOOP.md`) is the explicit mechanism for "Anthropic researcher hand-driving the harness," generalized to any operator.
- The obligation system (§3 in `03_EXPLOIT_AUTOMATION.md`) is the explicit discipline that prevents Mythos's known failure mode — confident-sounding exploits that don't reproduce — from showing up in our findings.

When a customer asks "why use AILA when Anthropic has Mythos?" the honest answer is:

1. Mythos isn't a product you can buy. It's a capability inside Anthropic.
2. Even if it were, you'd need a harness around it, infrastructure to run targets, evidence tracking, and the ability to direct it at *your* targets, not the labs' chosen ones.
3. We are that harness. We will use Mythos (or its successor) when it becomes API-accessible, the way we use Opus today.

### The strategic risk

If Anthropic releases their internal harness as a product, the VR module's value proposition narrows. The scenarios:

- **They release a SaaS harness.** Self-hosted requirements (defense, regulated industries, classified targets) still need our deployment model. Our integration with on-prem tooling (IDA license, internal source mirrors, air-gapped fuzzing) survives.
- **They release a self-hosted harness.** This is the existential threat. Mitigations: we ship multi-model routing (a customer can use any frontier provider), tighter integration with reverse-engineering tooling than a model lab is likely to invest in, and module-level customization (forensics, vulnerability sharing infra and operator habits).
- **They release neither, ever.** Most likely. Frontier labs sell models, not workflows. Workflows are where the operator economics live, and that's our market.

We design as if scenario 2 is plausible and we lose if we depend on it not happening.

---

## 3. AISLE

### What it actually is

AISLE is an academic and government-research-funded autonomous cyber reasoning system. The lineage runs through DARPA's Cyber Grand Challenge era systems (Mayhem, ForAllSecure, Pharos) into modern LLM-augmented variants. AISLE specifically came out of a multi-institution collaboration.

Public results:

- **12 of 12 OpenSSL CVEs** with verified PoCs in the January 2026 coordinated disclosure. OpenSSL is one of the most-audited C codebases in existence; finding 12 verified bugs in it via an automated system is significant.
- Historical vulnerability rediscovery on the OpenSSL repo back to ~2018-era code.
- Published methodology emphasizing the combination of formal techniques (symbolic execution, abstract interpretation) with LLM-driven hypothesis generation.

### What AISLE represents

AISLE is the answer to "what happens when a domain-specialized loop with a curated tool stack and dedicated researchers focuses on one well-known target?" The answer is: very high recall on that target. 100% detection on a 12-CVE coordinated release is not normal; it suggests the system has converged hard on OpenSSL's idioms.

This is calibration data, not a product comparison. AISLE is not sold as a platform. It does not have:

- An operator UI for non-researchers.
- Multi-customer deployment.
- A persistent evidence graph for a customer's portfolio.
- Disclosure workflow integration.
- Self-hosted, on-prem, air-gapped operation.

### How we differ

| Axis | AISLE | AILA VR |
|---|---|---|
| Form factor | Research system | Production platform |
| Targets | Curated, primarily OpenSSL family | Operator-defined, arbitrary |
| Persistence | Per-experiment | Persistent project graph, multi-session |
| Operator | The researchers who built it | Any qualified VR operator |
| Disclosure | Coordinated by the research consortium | Per-engagement, customer-driven |
| Tool stack | Custom, tightly integrated | Standard tools (IDA, angr, AFL++) the operator already knows |

The honest read: AISLE proves the *capability ceiling*. A specialized loop on a known target can reach near-100%. The VR module's job is not to match that ceiling on OpenSSL — it's to deliver useful results on *whatever target an operator points at*, including ones AISLE has never seen.

### What we should learn from AISLE

- Domain specialization works. We should be willing to ship target-class-specific subsystems (kernel, hypervisor, web, embedded) with their own tool registries and prompt scaffolds rather than pretending one loop fits all.
- Combination of formal and probabilistic methods works. Our angr/Trailmark/Semgrep integration mirrors this. We should not treat the LLM as a replacement for symbolic execution; we should treat it as the *director* of when and how to use it.
- Coordinated disclosure is a force multiplier. AISLE got 12 CVEs published simultaneously because the research consortium coordinated with OpenSSL maintainers. The VR module's disclosure tracking (D-04) should support the same workflow when an engagement produces multiple findings against one upstream.

---

## 4. Dr.Binary

### What it actually is

Dr.Binary is a SaaS platform for binary analysis, public-facing as of 2025. Funded by NSF/DARPA/ONR/DHS lineage grants. The product:

- Browser-based UI, upload binaries, get analysis.
- 30+ tools integrated under one interface: disassembly (Ghidra, BinaryNinja, possibly licensed IDA), decompilation, symbolic execution, malware analysis (signatures, behavioral), firmware unpacking, type recovery, function similarity.
- Zero local setup. No license management, no install, no IDA licenses to procure. The customer's binary is uploaded; the analysis runs in their cloud.

It is closer to "VirusTotal for static binary analysis" than to a research workbench, but with much deeper analysis depth than VirusTotal offers.

### How we differ

The two products live in different deployment modalities, and the deployment modality drives almost everything else:

| Axis | Dr.Binary | AILA VR |
|---|---|---|
| Deployment | SaaS, cloud-hosted | Self-hosted, SSH to operator's workstation |
| Data residency | Binary uploaded to vendor cloud | Binary never leaves operator infrastructure |
| Tool licensing | Vendor handles | Operator's own IDA license, own AFL++ build |
| Customization | Vendor-controlled | Operator-controlled (custom plugins, custom IDA scripts, custom Trailmark queries) |
| Audit trail | Vendor logs | Operator's own logging, evidence in operator DB |
| Reasoning | Mostly tool orchestration | LLM reasoning loop + tool orchestration + evidence + obligations |
| Multi-target campaigns | Single binary at a time | Project-level dependency graph |
| Air-gapped environments | Not supported | Supported by design (D-13) |

Dr.Binary is a strong fit for: triaging an unknown binary fast, university courses, malware research labs, individual researchers without an IDA license. It is a poor fit for: regulated environments, classified work, vendor engagements where customer code cannot leave the operator's network, multi-month engagements that need persistent state, anything where the binary cannot be uploaded for legal or contractual reasons.

The VR module's customers are precisely the ones Dr.Binary cannot serve. There is no head-to-head; there is a market split along data residency.

### What Dr.Binary does that we should consider

- **Tool-as-a-service abstraction.** Their UI hides "is this Ghidra or IDA or BinaryNinja answering this question?" That's a useful abstraction for operators who don't care which decompiler ran. We do something similar with the IDA-headless MCP (`02_IDA_HEADLESS_MCP.md`) but only for IDA. A unified `decompile(binary, address) -> pseudocode` interface that picks the best available tool would be a useful generalization.
- **Function similarity at scale.** Their library of pre-analyzed binaries enables fast function-similarity queries (BinDiff-style). We have nothing equivalent. This matters for variant search across firmware versions.

We will not match their function-similarity corpus without a corpus. But we should expose a similarity-search hook so operators with internal corpora can plug them in.

---

## 5. Binarly VulHunt

### What it actually is

Binarly is a firmware security company; their VulHunt product is the LLM-augmented research arm. As of 2026:

- Firmware-focused: UEFI, BIOS, embedded device images.
- Their scanners detect known-bad patterns (CVE matches, vulnerable component versions, signed-but-vulnerable binaries) and unknown-bad patterns (LLM-driven anomaly detection on firmware blobs).
- Notable: they ship an MCP server that exposes their analysis tools to Claude. An external operator can drive their tooling from a Claude session, which is the same architectural pattern we use for IDA-headless-MCP.

### What this means

Binarly's MCP integration is a strong validation of the architectural pattern that underlies our `02_IDA_HEADLESS_MCP.md`: **tool-as-MCP-server, model-as-orchestrator.** They reached the same conclusion independently.

Their scope is narrower than ours by design:

- Firmware only. UEFI, embedded Linux, RTOS images. No desktop binaries, no web apps, no kernel of a non-firmware OS.
- Vulnerability detection with strong CVE-mapping; weaker on novel exploit development.
- SaaS-first deployment (with on-prem available for enterprise).

### How we differ

| Axis | Binarly VulHunt | AILA VR |
|---|---|---|
| Target scope | Firmware (UEFI, embedded) | Native binary, kernel, hypervisor, source, scripts (D-03 target classes) |
| MCP integration | Their tools, their MCP | Generic MCP layer, operator brings tools |
| Fuzzing | Limited, mostly pattern detection | First-class campaign management |
| Exploit development | Triage and PoC for known CVEs | Full chain construction (`03_EXPLOIT_AUTOMATION.md`, `04_MULTI_TARGET.md`) |
| Disclosure | Their advisories | Operator-coordinated |

A real-world workflow where both could coexist: customer ships routers with a Binarly-flagged "uses vulnerable libfoo 1.2.3" report. Operator imports the report, the VR module decomposes the firmware (`04_MULTI_TARGET.md`), analyzes the libfoo consumers (`mqttd`, `vpnd`, `httpd`), and discovers a chain that elevates the libfoo bug from "library has CVE" to "pre-auth root via MQTT." Binarly answered "is the bug present?"; we answered "what can the attacker actually achieve?"

### What we should learn

- **Ship an MCP layer.** Binarly's API isn't open to plug into; ours should be. An operator who already has a Binarly account should be able to point our reasoning loop at Binarly's MCP and use it as one tool source among many. Generalizing the MCP integration beyond IDA is on the roadmap implicit in D-12.
- **Firmware unpacking matters.** We rely on binwalk and friends; Binarly clearly invests heavily in firmware-format coverage. We should not try to outdo them at firmware extraction; we should accept their (or another vendor's) extracted output as a project import format.

---

## 6. Google OSS-Fuzz-Gen

### What it actually is

Google's project to use LLMs for fuzzing harness generation, ongoing since 2023, with strong public results by 2026:

- 160+ projects covered.
- ~30% line-coverage increase across covered projects relative to human-written harnesses or baseline OSS-Fuzz harnesses.
- 30+ confirmed real bugs found via the LLM-generated harnesses (i.e., bugs that no prior OSS-Fuzz coverage had found).

The methodology, in brief:

1. Pick a project's exported API surface.
2. Ask an LLM to generate a libFuzzer harness that exercises a specific function.
3. Compile and run the harness.
4. Measure coverage; iterate the prompt with feedback if coverage is low.
5. If coverage is acceptable, run the fuzz campaign on Google's existing OSS-Fuzz infrastructure.

It is a focused, narrow, well-engineered solution to one problem: **harness generation for fuzzing campaigns on open-source C/C++ projects.**

### What it is not

- Not a research platform. It does not reason about exploitability, write PoCs, or analyze chains.
- Not multi-language beyond C/C++ at the harness layer.
- Not portable off Google's infrastructure. The published results depend on OSS-Fuzz's existing build/run/coverage stack.
- Not a workflow. It generates harnesses; campaign management, crash triage, deduplication, and disclosure are separate problems handled by separate OSS-Fuzz machinery.

### How we differ — and why we want to copy them

OSS-Fuzz-Gen does *one step* of our workflow extremely well. That step is harness generation — an LLM task that today eats a non-trivial fraction of an operator's time when fuzzing a binary-only library (see "Fuzzing the library directly" in `04_MULTI_TARGET.md`).

Our position: we do not compete with OSS-Fuzz-Gen on their step. We adopt their approach. Specifically:

- The reasoning loop has a `propose_harness` action (§3 in `01_REASONING_LOOP.md`) that already uses the same pattern — generate harness, compile, measure coverage, iterate.
- Where OSS-Fuzz-Gen has access to the project's build system, we have access to the operator's full toolchain over SSH.
- Where OSS-Fuzz-Gen targets C/C++ open source with build files, we additionally target binary-only libraries (using consumer-driven API recovery — see §2 of `04_MULTI_TARGET.md`) and non-C/C++ targets.

The integration story:

- For projects covered by OSS-Fuzz, we should be able to import their harnesses rather than regenerating them. There is no reason to redo work the open ecosystem already published.
- For projects not covered (closed-source, binary-only, internal codebases), our harness-generation step replicates the OSS-Fuzz-Gen approach with binary-aware prompts.

### How we differ at the workflow level

| Step | OSS-Fuzz-Gen | AILA VR |
|---|---|---|
| Harness generation | Core competency | One step in the loop |
| Build system handling | Required (uses project's CMake/configure) | Optional (we drive the toolchain explicitly) |
| Binary-only targets | Out of scope | Supported with API recovery |
| Crash triage | OSS-Fuzz machinery | Our reasoning loop with adjudication |
| Exploitability analysis | None | Per-consumer reachability + obligation system |
| Disclosure | Project-by-project, varies | Operator-coordinated |

OSS-Fuzz-Gen is a tool we want to use; their team is a community we want to be net contributors to (improvements to harness templates, novel harness patterns surfaced by our operators) rather than a competitor.

---

## 7. The Honest Gap Map

A consolidated view. Marked as: **Y** = first-class capability, **P** = partial / via integration, **N** = not in scope.

| Capability | Aardvark | Mythos (raw) | AISLE | Dr.Binary | Binarly | OSS-Fuzz-Gen | AILA VR |
|---|---|---|---|---|---|---|---|
| Source vuln detection | Y | Y | Y | P | P | N | Y |
| Binary vuln detection | N | Y | Y | Y | Y | N | Y |
| Decompilation pipeline | N | N | Y | Y | Y | N | Y |
| Symbolic execution | P | N | Y | Y | P | N | Y (via angr) |
| Fuzzing harness generation | N | N | Y | N | N | Y | Y |
| Fuzzing campaign management | N | N | Y | N | P | P | Y |
| Crash reproducer generation | N | Y | Y | P | P | Y | Y |
| Exploit PoC | N | Y | Y | N | N | N | Y (tier-bounded) |
| Mitigation bypass reasoning | N | Y | Y | N | N | N | P (operator-assisted) |
| Cross-binary chain analysis | N | N | N | N | N | N | Y |
| Multi-target project graph | N | N | N | N | N | N | Y |
| Persistent evidence graph | N | N | P | N | N | N | Y |
| Operator steering mid-loop | N | N | P | N | N | N | Y |
| Self-hosted | N | N/A | N/A | P | P | N | Y |
| Air-gapped operation | N | N | P | N | N | N | Y |
| Multi-model routing | N | N | N | N | N | N | Y (D-08) |
| Disclosure tracking | P | N | P | N | Y | N | Y (D-04) |
| Posture report (product-level) | N | N | N | N | P | N | Y |

The pattern in the rightmost column: we are wide, not deep. We have first-class support for almost every capability, but on any given capability another product is more specialized. **That is the deliberate position.** Operators who need depth on one axis (firmware unpacking → Binarly; OpenSSL → AISLE; harness gen on OSS → OSS-Fuzz-Gen) should use those tools. We are the workflow that integrates them, the reasoning loop that drives them, and the evidence layer that turns their outputs into a defensible report.

---

## 8. Where the AILA VR Module Fits

### The single sentence

We are the **scaffold** that makes a frontier LLM useful for end-to-end vulnerability research on operator-defined targets in operator-controlled environments.

### What that decomposes to

1. **Not competing with frontier models.** We use them. Anthropic's Opus, OpenAI's GPT-5, and any successor are inputs to our loop. Multi-model routing (D-08) is the explicit hedge: if a model lab raises prices, deprecates a model, or restricts API access, we re-route. The reasoning loop is model-aware but not model-locked.

2. **Not competing with SaaS analysis platforms.** We are self-hosted by design. Our customers are the ones who *cannot* upload binaries — defense contractors, regulated industries, vendors doing third-party engagements under NDA. The deployment model is constraint-driven (D-13).

3. **Not competing with academic research systems.** AISLE-class systems publish results; we ship a platform an operator runs every day. Different success metrics: AISLE optimizes for novel disclosures, we optimize for operator productivity over hundreds of engagements.

4. **Competing with the status quo of "operator + IDA + sticky notes."** This is the actual incumbent. Most VR work today is one researcher with IDA, GDB, an AFL++ instance on a workstation, and a Markdown file with notes. The VR module's bet is that an LLM-driven reasoning loop with persistent evidence and obligation enforcement is better than that workflow even before we add cross-binary or multi-target features. The competitors above raise the ceiling; the status quo is the floor we have to clear.

### The stack diagram

```
[ Operator UI, project state, dashboards ]
              |
              v
[ AILA VR module: reasoning loop, evidence graph,    ]
[ obligation system, target/finding/chain models     ]   <-- AILA scope
              |
              v
[ Tool registry: IDA-MCP, Ghidra-MCP, angr, AFL++,   ]
[ Trailmark, Semgrep, GDB, pwntools, Frida, ...      ]
              |
              v
[ SSH workstation: actual binaries, actual processes ]
              |
              v
[ Frontier LLM API: Anthropic, OpenAI, local         ]   <-- not us
```

We are the second box. The first box is operator-facing UI we build; the third box is third-party tooling we orchestrate; the fourth box is operator infrastructure we drive over SSH; the fifth box is third-party services we consume.

### Why the second box is the right place to live

- **Below it (frontier models, tooling)** is a market that consolidates around scale. Frontier model capex is in the billions; we are not a model lab. IDA is a 30-year codebase; we are not a disassembler vendor.
- **Above it (operator UI, dashboards)** is non-defensible without the second box. A pretty dashboard over someone else's reasoning is a thin moat.
- **The second box itself** is where domain expertise compounds. Every engagement teaches us something about how operators actually work, what evidence patterns hold up under scrutiny, what obligation contracts catch real LLM hallucinations. None of that compounding shows up in the model weights or the disassembler.

### Adjacent integrations we plan to support

To make the framing concrete, the integrations we expect to ship or document:

- **Anthropic Claude API and Mythos when available.** Already in. Multi-turn with caching.
- **OpenAI GPT-5 / Aardvark output ingest.** Aardvark's findings as one signal; GPT-5 as alternative reasoning model.
- **Local Llama / open weights** for air-gapped sites that cannot call out. Lower capability, accepted tradeoff.
- **Binarly MCP** for firmware engagements where customer is already a Binarly user.
- **OSS-Fuzz-Gen harnesses** for upstream open-source projects. Import rather than regenerate.
- **AISLE-style symbolic execution** via angr/Trailmark, with the LLM directing when to invoke.
- **IDA-headless MCP, Ghidra-MCP** for the decompile/xref/symbol layer.
- **Customer-supplied tooling** via a generic MCP plug-in slot, so operators with internal in-house tools can register them without a code change.

Every one of these is an integration story, not a competitive story. The VR module wins by having more of these wired correctly, not by re-implementing any of them.

---

## 9. Strategic Risks to This Position

The framing in §8 only holds if certain bets hold. Listed honestly:

### Risk 1 — A frontier lab ships an end-to-end research harness as a product

Most likely to come from Anthropic given their disclosed Mythos work. If they ship a harness that drives binaries on customer infrastructure, they have a model + scaffold offering we can't match on model quality.

Mitigation surface:
- Multi-model routing reduces lock-in if the harness is model-bound.
- Self-hosted, on-prem, air-gapped use cases are unlikely to be a model lab's priority.
- Module-level integration (forensics, vulnerability sharing infra) is broader than VR alone.

If we lose VR-only customers to a hypothetical Anthropic harness, we still win the platform play if the rest of AILA's modules are valued.

### Risk 2 — Aardvark expands into binary and exploitation

OpenAI has the resources to extend Aardvark beyond source. If they do, the gap in §1 narrows.

Mitigation surface:
- Self-hosted constraint persists.
- Their SaaS form factor remains unsuitable for regulated environments.
- Our multi-target / cross-binary / chain analysis is structurally harder than per-repo analysis; not a six-month pivot for them.

### Risk 3 — A SaaS competitor offers self-hosted

Dr.Binary or Binarly could offer enterprise on-prem deployments that close the data residency gap.

Mitigation surface:
- The operator's tool stack (their IDA license, their AFL++ build, their custom plugins) is sticky. A SaaS-converted-to-on-prem product still has its own preferred tools.
- Our LLM-driven reasoning loop with obligation enforcement is qualitatively different from a tool-orchestration product, and the difference is hard to copy without rebuilding the evidence layer.

### Risk 4 — Frontier model capability plateaus

If LLM capability stops improving rapidly, the calibration baselines in §1 (Mythos's 181 exploits, Opus's 22 Firefox bugs) become a ceiling rather than a milestone. The VR module's value compresses to "good operator tooling" rather than "amplifies a continuously improving operator brain."

Mitigation surface:
- Even at current capability, the workflow productivity gain is real (D-01 calibration: hours of work per finding goes from 40+ to 5–10 on Tier 1 bugs).
- Module-level utility (forensics) is independent of frontier-model improvements.

### Risk 5 — Open-source scaffolds emerge and commoditize the orchestration layer

Plausible from the academic community. Already starting (CRS systems from CGC alumni, various PhD projects).

Mitigation surface:
- Open-source scaffolds tend to be research-focused; we are operations-focused. Different code quality bar, different SLA expectations, different UI investment.
- Integration breadth (every tool, every model, every disclosure workflow) takes years of accumulated work that academic scaffolds typically don't fund.
- Commercial support is a real product feature in regulated environments.

### Risk 6 — Regulatory and export-control changes

LLM-driven exploit generation is the kind of capability that governments notice. Export controls or use-case restrictions could limit deployment.

Mitigation surface:
- Self-hosted deployment is *more* defensible under export controls than SaaS.
- Modular target-class gating (D-03): we can disable hypervisor or kernel exploitation for certain customer classes if required.
- The module is built for legitimate VR work; the safety policies (D-09) reflect that.

This is a real risk, not a hypothetical one. Tracked separately in the security-policy doc track.

---

## 10. The Pitch, Without Marketing

When an operator asks "why should I use this instead of [X]?" the answer is some subset of:

- **"You can't run X on this target."** Air-gapped, classified, customer-NDA-bound, no-upload-allowed.
- **"X doesn't reason at this depth on this target."** Source-only, single-binary, no chains, no multi-target.
- **"X gives you findings; we give you evidence."** Reproducer + obligation-backed exploit + per-consumer reachability + posture report.
- **"X is one step of your workflow; we are the workflow."** Aardvark, OSS-Fuzz-Gen, individual MCP-served tools all become inputs to the VR module's loop.
- **"You already have an operator and tooling; we make them more productive."** Not a research lab in a bottle, an amplifier on the operator you already have.

When an operator asks "where shouldn't I use this?":

- **"If you only need source-level vuln scanning at scale, use Aardvark or Snyk."** We are overkill.
- **"If you need fast malware triage on uploaded samples, use Dr.Binary or VirusTotal."** We are not optimized for one-shot triage.
- **"If you need to fuzz an open-source C project that's already in OSS-Fuzz, just use OSS-Fuzz."** Their infrastructure is free, ours isn't.
- **"If the engagement is six hours of binary triage with no exploitation, the LLM overhead may not pay back."** Honest answer, said up front.

That last bullet is the test of whether we are an honest product or a hype product. A platform that says "use us for everything" is selling a marketing claim. The VR module's design says "use us where the persistent evidence graph, obligation system, and operator-steered reasoning loop earn their cost." That covers the majority of professional VR work but not all of it.

---

## Open Questions

1. **How do we benchmark ourselves without a benchmark?** Aardvark has golden repos; AISLE has the OpenSSL release; Mythos has the Firefox campaign. The VR module's value is workflow productivity on operator-defined targets, which is structurally hard to benchmark. Do we publish per-engagement case studies? Recruit a friendly customer to run a public bake-off? Build our own internal benchmark suite of N retired CTFs and N retired CVEs? Each option has biases we'd have to disclose.

2. **What's the right multi-model fallback policy when one provider deprecates a model mid-engagement?** Anthropic has shipped breaking model deprecations on weeks of notice. If a long-running project depends on Opus's reasoning style and Anthropic ships Sonnet-only, do we (a) freeze the project on the deprecated model until the operator reviews, (b) auto-migrate and risk evidence drift, (c) flag every finding produced before/after migration as a separately-graded cohort? Tested only in dry-runs so far.

3. **How do we share findings across engagements without leaking customer data?** A bug found in `libfoo.so` for customer A is informative for customer B if they also use `libfoo.so`. The naive "share patterns" approach exfiltrates customer-specific signal. Differential-privacy-style aggregation, federated pattern learning, or operator-managed pattern libraries — all on the design table; none mature.

4. **When should we recommend Aardvark or OSS-Fuzz-Gen over ourselves?** A customer with 200 open-source repos under audit is better served by Aardvark for the first sweep, with the VR module engaged only on the high-priority subset. We need a "is this the right tool for this job" decision aid, ideally surfaced in the project setup wizard rather than discovered after the wrong tool has been engaged for a week.

5. **What do we do when a frontier lab releases a competing harness?** The contingency in §9 is hand-waved. The actual playbook — open-source the reasoning loop, focus on integrations the lab can't ship, double down on regulated verticals, partner with the lab — is undecided. Probably depends on which lab and what they ship.

6. **How do we handle the credentialing problem?** Operators using the VR module will produce CVEs. Coordinated disclosure typically credits a researcher and an organization. Is the credited organization "AILA," the operator's employer, the customer, or the customer's vendor under audit? The disclosure tracking (D-04) records the chain, but the public credit-string convention is unsettled.

7. **What's the threshold for shipping target-class-specific subsystems?** AISLE's success on OpenSSL suggests domain specialization works. Do we ship a "kernel research" mode with a curated tool stack and prompt scaffolds, separate from "userspace native" mode? If so, where do we cut: per OS family (Linux kernel, Windows kernel, macOS kernel), per CPU architecture, per subsystem (filesystem, network stack)? The combinatorial space is large; the maintenance cost of N subsystems is real.

8. **How do we measure the "operator amplification" claim?** We say the VR module makes operators more productive. The honest measurement is hours-per-finding compared to the same operator without the module. Running that A/B is hard: operators are scarce, retired engagements aren't comparable, and operators learn the tool over time. Industry-standard answer: don't measure it, just sell the tool. Better answer: instrument turn counts, tool calls, time-to-first-finding, time-to-confirmed-finding, and publish the distribution honestly.

9. **What's the support model for "the LLM was wrong"?** When Aardvark misses a bug, it's a recall failure on a labeled benchmark. When the VR module's reasoning loop spends three turns hallucinating an exploit primitive, the customer is paying for those turns. Do we refund? Re-route to a different model? Auto-detect and abort? The cost-aware-LLM-pipeline patterns from D-08 give us hooks but not policy.

10. **How does this competitive landscape look in 18 months?** The honest answer is "we don't know." Frontier model capability is on a steep curve, AISLE-class systems are proliferating, Anthropic could ship a harness, OpenAI could open-source one. The VR module's design is meant to be robust to most of these moves, but "robust" means "we still have a viable position," not "we still have the same position." The strategic doc track should re-walk this landscape every six months, not annually.
