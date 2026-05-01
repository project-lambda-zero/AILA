# VR Module — Lessons from ARM Metis

What Metis does well, what doesn't apply to us, and what we should steal.

---

## What Metis Actually Is

Metis is a **static code review tool**, not a vulnerability research platform. It:

1. **Indexes a codebase** into a vector store (ChromaDB or pgvector)
2. **Reviews code** file-by-file using LLM + RAG context from the index
3. **Triages findings** from SARIF (its own or external tools like CodeQL) using deterministic evidence collection + LLM judgment + deterministic guardrails

It does NOT fuzz, does NOT exploit, does NOT reverse engineer binaries, does NOT do dynamic analysis. It's a souped-up code review bot with good static analysis scaffolding.

But its **triage architecture** is genuinely clever and we should learn from it.

---

## Idea 1: Evidence Obligation System

**What Metis does:** Before accepting an LLM's verdict on a finding, it computes "evidence obligations" — specific pieces of evidence that MUST be present for a given verdict to be trustworthy. If obligations are unmet, the verdict is forcibly downgraded to `inconclusive`.

Example: LLM says "this buffer overflow is invalid because the size is validated." Metis checks: did the evidence pack actually contain the validation function? If not, the LLM is hallucinating a guard that wasn't shown — force `inconclusive`.

**What we steal for VR:**

Our CyberReasoningEngine has `validate_submission()` which checks if the answer cites real evidence. But we don't have obligation-based gating on *intermediate* reasoning steps.

Apply this to exploit development:
- LLM says "exploitable via tcache poisoning." Obligation: evidence must contain heap allocator identification (glibc version, tcache presence). If the module never checked the allocator, force the LLM to investigate before accepting the exploitation strategy.
- LLM says "ASLR bypassed via info leak in function X." Obligation: evidence must contain decompiled output of function X showing a pointer leak. If not shown, the LLM is guessing.
- LLM says "not exploitable, bounds check prevents overflow." Obligation: evidence must contain the actual bounds check code. The LLM might be inventing a guard that doesn't exist.

**Implementation:**

```python
@dataclass
class EvidenceObligation:
    """Something that must be proven before a conclusion is accepted."""
    id: str                      # "heap_allocator_identified"
    claim: str                   # "tcache poisoning is viable"
    required_evidence: str       # "allocator type and version"
    satisfied: bool = False
    evidence_ref: str | None = None  # artifact_id or file:line that satisfies it

def derive_obligations(conclusion: str, evidence_graph: EvidenceGraph) -> list[EvidenceObligation]:
    """Given a conclusion the LLM wants to make, what evidence must exist?"""
    ...

def gate_conclusion(conclusion: str, obligations: list[EvidenceObligation]) -> str:
    """Force 'inconclusive' if critical obligations are unmet."""
    unmet = [o for o in obligations if not o.satisfied]
    if any(o.id in CRITICAL_OBLIGATIONS for o in unmet):
        return "inconclusive"
    return conclusion
```

This is the single most valuable pattern from Metis. It prevents the LLM from making confident claims that aren't grounded in collected evidence.

---

## Idea 2: Deterministic Adjudication Layer

**What Metis does:** The LLM produces a structured verdict (valid/invalid/inconclusive). Then a DETERMINISTIC rules engine runs over the verdict + evidence and can override the LLM:
- Contradiction signals in the reasoning ("cannot reproduce", "false positive") -> force `invalid`
- Uncertainty signals ("cannot determine", "insufficient evidence") -> force `inconclusive`
- Missing evidence obligations -> downgrade verdict
- Certain state transitions blocked entirely (can't go from `invalid` to `valid` without new evidence)

The LLM proposes, the deterministic layer disposes.

**What we steal for VR:**

Apply to exploitability assessment:
- LLM says "exploitable" but the reasoning contains "might be possible" / "could potentially" -> force `inconclusive` (uncertainty language)
- LLM says "not exploitable" but the evidence shows a controlled write primitive -> contradiction signal, force re-analysis
- LLM says "RCE" but target has CFI + shadow stack + MTE and the reasoning doesn't address them -> missing obligation, downgrade to `inconclusive`
- LLM previously said "not exploitable," now says "exploitable" with no new evidence collected between turns -> blocked state transition

```python
CONTRADICTION_SIGNALS = (
    "might be possible",
    "could potentially",
    "theoretically",
    "in some configurations",
    "under certain conditions",
    "if ASLR is disabled",     # ASLR is not disabled in real targets
    "assuming no mitigations",  # there are always mitigations
)

BLOCK_TRANSITIONS = {
    # Can't upgrade without new evidence
    ("not_exploitable", "exploitable"): "requires_new_evidence",
    ("inconclusive", "exploitable"): "requires_new_evidence",
    # Can't claim RCE without addressing mitigations
    ("any", "rce"): "requires_mitigation_analysis",
}
```

---

## Idea 3: Bounded Evidence Packs

**What Metis does:** Evidence is collected into a bounded pack with a maximum size. This prevents the LLM context from exploding when following cross-file references. Each evidence section has a line limit. The pack has a section count limit. When limits are hit, sections are dropped (with a count of what was dropped).

**What we steal for VR:**

Our working set problem. A binary has 5000 functions. The LLM can't see all decompiled code. Metis solves this with bounded evidence packs per finding.

For VR, the equivalent is a bounded evidence pack per hypothesis:

```python
@dataclass
class EvidencePack:
    """Bounded context for one reasoning turn."""
    hypothesis: str
    sections: list[EvidenceSection]  # decompiled functions, crash reports, traces
    max_sections: int = 20
    max_chars_per_section: int = 4000
    dropped_count: int = 0
    
    def add(self, section: EvidenceSection) -> bool:
        """Add section if within bounds. Returns False if dropped."""
        if len(self.sections) >= self.max_sections:
            self.dropped_count += 1
            return False
        if len(section.content) > self.max_chars_per_section:
            section = section.truncate(self.max_chars_per_section)
        self.sections.append(section)
        return True
```

The key insight: **tell the LLM what was dropped.** "12 additional functions reference this symbol but were excluded from this evidence pack. Request expansion if needed." This lets the LLM ask for more context when it needs it, rather than silently working with incomplete information.

---

## Idea 4: Tree-sitter for Source Targets

**What Metis does:** Uses Tree-sitter to parse source code and extract:
- Function/scope boundaries around a finding
- Symbol definitions and references
- Call-like identifiers near the target line
- Flow analysis (source -> guard -> sink chains for C/C++)

This is language-agnostic (Tree-sitter supports 100+ languages) and fast (no compilation needed).

**What we steal for VR:**

For interpreted language targets (Python, Java, JS, PHP, Go, Rust), we need source-level analysis. Instead of building per-language parsers, use Tree-sitter:

- **Attack surface mapping:** Parse all source files, find functions that process external input (parameters from HTTP handlers, deserialization entry points, file parsers). Tree-sitter gives us the AST; the LLM classifies which functions are security-relevant.
- **Data flow sketching:** For a suspected sink (e.g., `subprocess.call`), walk the AST backward to find where the arguments come from. Not full taint analysis (that's CodeQL's job) but enough to give the LLM a starting point.
- **Scope extraction:** When the LLM wants to analyze a specific function, extract the function + its immediate callees + its callers using Tree-sitter. This is the evidence pack for source-level targets.

We already have Tree-sitter in the frontend build chain (Tailwind, syntax highlighting). The Python `tree-sitter` package can parse C, C++, Java, Python, JS, Go, Rust, PHP out of the box.

**For binary targets, IDA/Ghidra replaces Tree-sitter.** Same concept (extract scope, find references, build evidence pack) but via decompiler output instead of source AST.

---

## Idea 5: RAG-Indexed Codebase

**What Metis does:** Indexes the entire codebase into a vector store (pgvector or ChromaDB). When reviewing a specific file/function, retrieves semantically related code chunks for context.

**What we steal for VR:**

We already have pgvector and an embedding service in the platform. For source-available targets:

1. **Index the target codebase** at project creation (split into chunks, embed, store in pgvector)
2. **Retrieve related code** when the LLM generates a hypothesis ("functions similar to this vulnerable pattern")
3. **Variant search** becomes a vector similarity query ("find code chunks semantically similar to this vulnerability pattern")

For binary targets, index decompiled pseudocode from IDA/Ghidra the same way. The chunks are decompiled functions instead of source files.

This turns variant analysis from "grep for the same function name" to "find code that does the same thing regardless of naming."

---

## Idea 6: Macro/Include Resolution (C/C++ specific)

**What Metis does:** For C/C++ findings, resolves macros to their definitions. A finding on `ALLOC(size)` is useless if the reviewer doesn't know that `ALLOC` expands to `malloc`. Metis traces `#define` chains and includes to surface the actual semantics.

**What we steal for VR:**

Critical for binary analysis too. IDA's decompiler often shows macro-expanded code that obscures the real logic. But on the source side:
- A bug in `CHECK_LENGTH(x)` might be invisible if the reviewer doesn't know `CHECK_LENGTH` is `if (x > MAX) abort()` vs `if (x > MAX) return -1` (one exits, one continues with bad state).
- Custom allocator macros (`POOL_ALLOC`, `SLAB_GET`) need resolution to understand the allocator being used (affects exploitation strategy).

For our module: when analyzing C/C++ source targets, resolve macros before feeding code to the LLM. For binary targets, IDA handles this at the decompiler level (macros are already expanded in decompiled output).

---

## What Metis Does That We DON'T Need

| Metis Feature | Why we skip it |
|---|---|
| SARIF input/output | We're not triaging tool output. We're finding bugs ourselves. |
| File-by-file review mode | We do hypothesis-driven research, not file-by-file scanning. |
| Plugin YAML for prompts | Our prompts are built by CyberReasoningEngine dynamically per turn. |
| ChromaDB support | We already have pgvector in PostgreSQL. |
| Language-specific review prompts | We branch on target class (native/interpreted/kernel), not language. |
| Validation review (second LLM pass) | We have the adjudication layer instead (deterministic, not a second LLM call). |

---

## What Metis Does That We DO BETTER

| Area | Metis | AILA VR Module |
|---|---|---|
| Analysis scope | Static only | Static + dynamic (fuzzing, debugging, exploitation) |
| Reasoning | Single-pass LLM review | Multi-turn hypothesis-driven reasoning with CyberReasoningEngine |
| Target types | Source code only | Source + binary + kernel + hypervisor + interpreted |
| Human interaction | None (batch tool) | Human-in-the-loop (operator steering, context injection) |
| Evidence tracking | Per-finding, discarded after triage | Persistent evidence graph across entire research engagement |
| Output | SARIF annotations | PoCs, exploits, advisories, campaign reports |
| State persistence | None (stateless runs) | Durable workflow with crash recovery |

---

## Summary: What to Build

From Metis, integrate these four patterns into the VR module's reasoning engine:

1. **Evidence obligations** — before accepting any exploitability claim, verify required evidence was actually collected
2. **Deterministic adjudication** — LLM proposes, rules engine validates, uncertainty forces re-investigation
3. **Bounded evidence packs** — limit context per turn, tell the LLM what was excluded, let it request expansion
4. **Tree-sitter source indexing** — for interpreted language targets, use Tree-sitter for fast scope extraction and data flow sketching

These patterns make the LLM's reasoning *auditable and bounded* — it can't claim things it hasn't proven, can't see more than it should per turn, and can't make state transitions that the evidence doesn't support.
