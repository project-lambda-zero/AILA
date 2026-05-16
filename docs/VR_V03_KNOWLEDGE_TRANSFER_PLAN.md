# VR Module v0.3 — Knowledge Transfer Plan (Pattern Catalog + RAG)

## What this plan covers

Audit memos (`VR_V03_REASONING_PLAN.md` GA-25) capture **negative findings** — "I audited this region, no bug exists." Without a counterpart system, every positive finding's hard-won technique is lost when the investigation closes.

This plan adds the **Pattern Catalog**: when an investigation succeeds, the techniques, fuzzing strategies, search heuristics, tool recipes, and triage rules used along the way are extracted into reusable patterns. Operator reviews and promotes patterns to local/workspace/global scope. Future investigations retrieve applicable patterns at start via semantic search and inject them as evidence.

Five pattern types tracked:

| Pattern type | Example |
|---|---|
| `exploitation_technique` | "V8 type confusion triggers reliably by passing aliased args after distinct-warmup runs (CVE-2025-2135 family)" |
| `fuzzing_strategy` | "V8MapInferenceProfile.swift caught CVE-X; reusable for JIT engines with map-inference" |
| `search_heuristic` | "Grep `InferMaps` callsites without aliasing precondition; high-yield for the CVE family" |
| `tool_recipe` | "IDA Headless `find_similar_functions` + `decompile` + `value_ranges` is the 3-step combo for catching missing bounds checks" |
| `triage_rule` | "SBXCHECK + Wasm frames in stack ⇒ in-sandbox amplifier (not VRP-eligible)" |

**Reuses existing infrastructure**: The platform's `KnowledgeService` (`src/aila/platform/services/knowledge.py`) already provides pgvector + HNSW + tsvector FTS via `KnowledgeEntryRecord` (`src/aila/storage/db_models.py:520`). The Pattern Catalog is a thin specialization on top — not a new vector store.

## Position in the VR roadmap

Companion plan to `VR_V03_REASONING_PLAN.md`, `VR_V03_FUZZING_PLAN.md`, and `VR_V03_DISCLOSURE_LIFECYCLE_PLAN.md`. Where:
- Reasoning produces investigations with successful outcomes
- This plan extracts patterns from those investigations and feeds them into future ones

Out of scope:
- ML-trained pattern classifiers (v0.4+)
- Auto-generated pattern descriptions from raw code (v0.4+; v0.3 is LLM-extraction + human review)
- Cross-team pattern sharing marketplace (v0.5+)

---

## Gray Area Resolutions

### GA-41: Pattern storage — separate table or KnowledgeEntryRecord namespace?

**Decision:** Hybrid. Structured fields in `vr_patterns` (queryable schema). Mirror entry in `KnowledgeEntryRecord` for embedding + FTS (reused infra). The PatternStore service writes to both; updates propagate via a single transaction.

Rationale:
- `KnowledgeEntryRecord` is great for "find by semantic similarity" — content + embedding + FTS
- It's bad for "filter by applicability constraints, sort by usage success rate, scope to workspace"
- Splitting into two stores avoids cramming structured fields into `entry_metadata` JSON

Namespace mapping in `KnowledgeEntryRecord`:
- `vr.pattern.local.<investigation_id>` — patterns extracted but not yet promoted (operator-only visibility)
- `vr.pattern.workspace.<workspace_id>` — promoted to workspace scope
- `vr.pattern.team.<team_id>` — promoted to team scope (cross-workspace within team)
- `vr.pattern.global` — globally promoted (cross-team; admin-gated)

Embeddings reuse the platform's MiniLM 384-dim setup; no new model.

### GA-42: Auto-extraction at investigation completion

**Decision:** When an investigation emits a successful outcome (`DirectFinding`, `CrashTriageReport`, `VariantHuntOrder`, `ProfileSpecDraft`), an ARQ task `pattern_extractor_worker` runs. It re-prompts the LLM with the full investigation transcript + outcome, asking: "Extract reusable patterns. For each, give: type, summary, applicability, evidence."

Extraction prompt template (`reasoning/agents/prompts/pattern_extraction.md`):

```
You are extracting reusable patterns from a successful vulnerability research investigation.

The investigation reached this outcome: {outcome_summary}

The reasoning transcript follows. Extract patterns that would help future investigations.

For each pattern:
- type: one of {exploitation_technique, fuzzing_strategy, search_heuristic, tool_recipe, triage_rule}
- summary: one sentence the operator will recognize
- body: full description with example code/queries
- applicability: which target_kinds, languages, bug_classes this applies to
- confidence: exact|strong|medium|caveated|unknown
- evidence_refs: which AgentStepRecord IDs demonstrate the pattern

Only extract patterns you can defend. If nothing reusable was learned, return an empty list.
DO NOT invent patterns to fill quota.

Output JSON list.

[transcript follows]
```

Extracted patterns enter status `draft`. Operator reviews via UI. Default scope on extraction = `local` (investigation-only); operator promotes during review.

### GA-43: Operator review + promotion workflow

**Decision:** Patterns require operator review before any scope above `local`. Promotion is a one-way operation (operator can demote to `archived` but not silently revert). Operator can edit pattern body / applicability during review.

Promotion levels (each step requires explicit operator action):

```
draft (auto-extracted, local only, invisible outside investigation)
  ↓ operator reviews + approves
local (visible only in originating investigation, used for self-reference)
  ↓ operator promotes
workspace (visible across investigations in same workspace; default-applied on retrieval)
  ↓ operator promotes
team (visible across workspaces; cross-target reuse within team)
  ↓ platform_admin promotes
global (cross-team; very high bar; admin-gated)
```

Demotion path:
- `archived` — not retrieved by engine; still visible in UI as history. Reversible by operator.
- Patterns deprecated/archived because of false-positive use or replacement by better pattern.

### GA-44: Application — when does the engine retrieve patterns?

**Decision:** At investigation start AND at each branch fork AND when operator messages contain keywords matching pattern summaries. Top-K (default 5) injected into evidence pack at priority 60 (just above audit memos at 70).

Retrieval algorithm (`services/pattern_retriever.py`):

```python
async def retrieve_patterns_for_context(
    target: VRTarget,
    question: str,
    workspace_id: str,
    team_id: str,
    k: int = 5,
) -> list[Pattern]:
    """Multi-stage retrieval: applicability filter → semantic + FTS → re-rank."""
    
    # Stage 1: applicability filter (cheap structured query)
    candidates = await pattern_store.list_applicable(
        target_kind=target.kind,
        languages=target.languages,
        bug_classes=question_to_bug_classes(question),  # LLM classification (cheap)
        scope_chain=[workspace_id, team_id, "global"],   # widening scope
        status="active",
        min_confidence="medium",
    )
    
    # Stage 2: semantic + FTS over candidate pool
    namespaces = [
        f"vr.pattern.workspace.{workspace_id}",
        f"vr.pattern.team.{team_id}",
        "vr.pattern.global",
    ]
    semantic_hits = await knowledge_service.hybrid_search(
        namespaces=namespaces,
        query=f"{target.descriptor} {question}",
        k=k * 4,
    )
    
    # Stage 3: re-rank by success rate + recency + applicability match
    candidates_by_id = {c.id: c for c in candidates}
    scored = []
    for hit in semantic_hits:
        if hit.entry_metadata.get("pattern_id") in candidates_by_id:
            pattern = candidates_by_id[hit.entry_metadata["pattern_id"]]
            score = (
                hit.similarity_score * 0.5
                + pattern.success_rate * 0.3
                + recency_decay(pattern.last_used_at) * 0.2
            )
            scored.append((score, pattern))
    
    return [p for _, p in sorted(scored, reverse=True)[:k]]
```

### GA-45: Success / failure tracking

**Decision:** Every retrieved pattern's usage is logged. When an investigation closes, operator (or engine, if confidence allows) marks which patterns were actually useful.

`vr_pattern_usages` table tracks:
- `pattern_id`, `investigation_id`, `retrieved_at`
- `was_referenced` (bool) — did the engine reference this pattern in any turn?
- `was_useful` (bool, nullable) — did the operator/engine confirm usefulness?
- `outcome_correlation` (enum) — did the investigation outcome correlate with the pattern?

Success rate computed periodically:
```
success_rate = sum(was_useful=true) / count(was_referenced=true)
```

Patterns with success_rate < 0.2 after 10+ uses get flagged for review. Patterns with success_rate > 0.7 after 5+ uses get a "high quality" badge in UI.

### GA-46: Cross-investigation positive feedback

**Decision:** When pattern P from investigation A is used successfully in investigation B, an internal `pattern_chain` link is recorded. Aggregated chain length = signal of pattern's reach.

Operator UI: pattern detail page shows lineage — "Used successfully in 7 investigations across 3 workspaces over 4 months."

Search heuristics with high chain length surface in `Recommended for this target` UI prompts when starting new investigations.

### GA-47: Conflict resolution between patterns

**Decision:** Patterns can contradict (one says "always check X first"; another says "X is a false-friend, check Y first"). System does not resolve — both patterns retrieved, presented to engine, engine reasons explicitly about which applies.

If operator notices a contradiction in UI, can flag a pattern for review or mark one as superseded by another. `superseded_by` field on `vr_patterns`.

### GA-48: Lifecycle of failed extraction

**Decision:** If the LLM returns no patterns (or only low-confidence ones), the investigation simply doesn't contribute to the catalog. No empty patterns persisted. Logged for tuning the extraction prompt.

A weekly task `pattern_extraction_quality_report` produces aggregate stats: investigations completed, patterns extracted per investigation (median/mean/distribution), promotion rate, usage rate. Drift detection lets the team know if extraction quality regresses (model change, prompt drift).

---

## File Layout

```
src/aila/modules/vr/
├── ... (existing files unchanged) ...
├── knowledge/                              # NEW v0.3 subpackage
│   ├── __init__.py
│   ├── contracts/
│   │   ├── __init__.py
│   │   ├── pattern.py                      # Pattern, PatternKind, PatternScope, ApplicabilityConstraint
│   │   ├── usage.py                        # PatternUsage, OutcomeCorrelation
│   │   ├── retrieval.py                    # RetrievalRequest, RetrievalResult
│   │   └── extraction.py                   # ExtractionRequest, ExtractedPatternDraft
│   ├── services/
│   │   ├── __init__.py
│   │   ├── pattern_store.py                # CRUD + structured queries
│   │   ├── pattern_retriever.py            # GA-44 retrieval pipeline
│   │   ├── pattern_extractor.py            # GA-42 LLM-driven extraction
│   │   ├── pattern_promoter.py             # GA-43 scope promotion + demotion
│   │   ├── pattern_usage_tracker.py        # GA-45 success/failure tracking
│   │   ├── knowledge_mirror.py             # GA-41 mirror to KnowledgeEntryRecord
│   │   └── bug_class_classifier.py         # cheap LLM call: question → bug_class enum
│   ├── workers/
│   │   ├── __init__.py
│   │   ├── pattern_extractor_worker.py     # ARQ: extract patterns at investigation close
│   │   ├── pattern_embedder_worker.py      # ARQ: compute embeddings + mirror to Knowledge
│   │   ├── pattern_usage_aggregator.py     # ARQ: recompute success_rate periodically
│   │   ├── pattern_quality_reporter.py     # ARQ: weekly extraction-quality report
│   │   └── pattern_archiver.py             # ARQ: archive low-success patterns
│   ├── data/
│   │   ├── bug_class_taxonomy.json         # bug_class enum + mapping to keywords
│   │   ├── target_kind_mapping.json        # target_kind → relevant pattern applicability defaults
│   │   └── extraction_prompts/
│   │       ├── pattern_extraction.md       # GA-42 prompt template
│   │       └── extraction_examples.md      # few-shot examples
│   └── api_router.py                       # pattern catalog API
├── db_models/
│   └── pattern.py                          # PatternRecord, PatternUsageRecord
└── alembic/versions/
    └── 032_vr_pattern_catalog.py
```

Existing infrastructure reused (not modified):
- `src/aila/platform/services/knowledge.py` — `KnowledgeService` for embedding/FTS/storage
- `src/aila/storage/db_models.py:520` — `KnowledgeEntryRecord` (the mirror target)
- `src/aila/modules/vr/reasoning/services/cost_tracker.py` — for LLM extraction cost accounting

---

## DB Schema (additions)

### vr_patterns
```sql
CREATE TABLE vr_patterns (
    id                          TEXT PRIMARY KEY,
    team_id                     TEXT,                    -- nullable for global patterns
    workspace_id                TEXT,                    -- nullable for team/global
    origin_investigation_id     TEXT REFERENCES vr_investigations(id),
    pattern_kind                TEXT NOT NULL,
                                                         -- exploitation_technique | fuzzing_strategy
                                                         -- | search_heuristic | tool_recipe | triage_rule
    scope                       TEXT NOT NULL DEFAULT 'local',
                                                         -- local | workspace | team | global
    status                      TEXT NOT NULL DEFAULT 'draft',
                                                         -- draft | active | archived | superseded
    summary                     TEXT NOT NULL,           -- one-line operator-facing summary
    body                        TEXT NOT NULL,           -- full description with examples
    -- Applicability constraints (queried as JSON, not relational)
    applicability_json          TEXT NOT NULL DEFAULT '{}',
                                                         -- {target_kinds: [...], languages: [...], bug_classes: [...]}
    -- Confidence + quality
    confidence                  TEXT NOT NULL,           -- exact|strong|medium|caveated|unknown
    extraction_model            TEXT,                    -- which model extracted this
    extraction_prompt_version   TEXT,                    -- for tracking prompt drift
    evidence_refs_json          TEXT DEFAULT '[]',       -- AgentStepRecord IDs
    -- Mirror tracking (GA-41)
    knowledge_entry_id          INTEGER REFERENCES knowledgeentryrecord(id),
    -- Usage statistics (GA-45)
    times_retrieved             INTEGER NOT NULL DEFAULT 0,
    times_referenced            INTEGER NOT NULL DEFAULT 0,
    times_useful                INTEGER NOT NULL DEFAULT 0,
    success_rate                REAL NOT NULL DEFAULT 0.0,
    last_used_at                TIMESTAMPTZ,
    -- Conflict resolution (GA-47)
    superseded_by_pattern_id    TEXT REFERENCES vr_patterns(id),
    superseded_at               TIMESTAMPTZ,
    superseded_reason           TEXT,
    -- Provenance
    created_by                  TEXT,                    -- 'engine' or operator user_id
    promoted_by                 TEXT,
    promoted_at                 TIMESTAMPTZ,
    created_at                  TIMESTAMPTZ NOT NULL,
    updated_at                  TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_pattern_scope_status ON vr_patterns (scope, status);
CREATE INDEX idx_pattern_workspace ON vr_patterns (workspace_id, status) WHERE workspace_id IS NOT NULL;
CREATE INDEX idx_pattern_team ON vr_patterns (team_id, status) WHERE team_id IS NOT NULL;
CREATE INDEX idx_pattern_kind ON vr_patterns (pattern_kind);
CREATE INDEX idx_pattern_origin ON vr_patterns (origin_investigation_id);
CREATE INDEX idx_pattern_success ON vr_patterns (success_rate DESC) WHERE status = 'active';
```

### vr_pattern_usages
```sql
CREATE TABLE vr_pattern_usages (
    id                  TEXT PRIMARY KEY,
    pattern_id          TEXT NOT NULL REFERENCES vr_patterns(id),
    investigation_id    TEXT NOT NULL REFERENCES vr_investigations(id),
    retrieved_at        TIMESTAMPTZ NOT NULL,
    retrieval_score     REAL NOT NULL,              -- composite score at retrieval time
    was_referenced      BOOLEAN NOT NULL DEFAULT false,    -- did any turn reference this pattern?
    referenced_at_turn  INTEGER,
    was_useful          BOOLEAN,                    -- nullable: unset until investigation closes
    usefulness_source   TEXT,                       -- 'operator' | 'engine' | 'unset'
    outcome_correlation TEXT,                       -- 'enabled' | 'helpful' | 'neutral' | 'misleading' | 'unset'
    notes               TEXT,
    UNIQUE (pattern_id, investigation_id)
);
CREATE INDEX idx_usage_pattern ON vr_pattern_usages (pattern_id);
CREATE INDEX idx_usage_inv ON vr_pattern_usages (investigation_id);
```

### vr_pattern_chains
```sql
CREATE TABLE vr_pattern_chains (
    id                  TEXT PRIMARY KEY,
    pattern_id          TEXT NOT NULL REFERENCES vr_patterns(id),
    from_investigation_id TEXT REFERENCES vr_investigations(id),
    to_investigation_id TEXT NOT NULL REFERENCES vr_investigations(id),
    chain_link_kind     TEXT NOT NULL,             -- 'extracted_from' | 'reused_in' | 'inspired_variant'
    created_at          TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_chain_pattern ON vr_pattern_chains (pattern_id);
```

Alembic migration: `src/aila/alembic/versions/032_vr_pattern_catalog.py`

---

## API Endpoints (additions)

```
# Pattern CRUD + lifecycle
GET    /api/vr/patterns                      list (filter: scope, kind, target_kind, status, success_rate_min)
POST   /api/vr/patterns                      operator-created pattern (manual entry)
GET    /api/vr/patterns/<id>                 full detail (incl. usage stats + chain)
PATCH  /api/vr/patterns/<id>                 edit summary/body/applicability/notes
POST   /api/vr/patterns/<id>/promote         scope change (draft→local→workspace→team→global)
POST   /api/vr/patterns/<id>/demote          back-scope or archive
POST   /api/vr/patterns/<id>/supersede       mark superseded_by another pattern
DELETE /api/vr/patterns/<id>                 hard delete (admin only; usually archive instead)

# Extraction + review
GET    /api/vr/investigations/<id>/extracted_patterns   list patterns extracted from this investigation
POST   /api/vr/investigations/<id>/extract_patterns     re-run extraction (operator-initiated)
POST   /api/vr/patterns/<id>/approve                    operator approves draft → active

# Retrieval (used by engine internally; exposed for debug)
POST   /api/vr/patterns/retrieve             body: {target, question, workspace_id, k} → ranked patterns
GET    /api/vr/patterns/recommended          for-target view: top patterns for current target

# Usage + chains
GET    /api/vr/patterns/<id>/usages          list usages of this pattern
GET    /api/vr/patterns/<id>/chain           lineage chain (which investigations used this)
POST   /api/vr/pattern_usages/<id>/feedback  operator marks was_useful + outcome_correlation

# Reporting + admin
GET    /api/vr/patterns/quality_report       extraction quality stats over time
GET    /api/vr/patterns/top                  top by success_rate within scope
```

---

## Build Order (Milestones)

### Milestone M3.K-1: Foundation
**Goal:** Data layer + structured pattern store.

| # | File | LOC | Depends on |
|---|---|---|---|
| 1.1 | `knowledge/contracts/pattern.py` | 150 | — |
| 1.2 | `knowledge/contracts/usage.py` | 80 | — |
| 1.3 | `knowledge/contracts/retrieval.py` | 60 | — |
| 1.4 | `knowledge/contracts/extraction.py` | 60 | — |
| 1.5 | `db_models/pattern.py` (3 tables) | 200 | 1.1, 1.2 |
| 1.6 | `alembic/versions/032_vr_pattern_catalog.py` | 200 | 1.5 |
| 1.7 | `knowledge/services/pattern_store.py` | 250 | 1.5 |
| 1.8 | `data/bug_class_taxonomy.json` | 100 | — |
| 1.9 | `data/target_kind_mapping.json` | 80 | — |

**Exit:** Migrations apply. CRUD against `vr_patterns` works. Bug class taxonomy + target kind mappings loadable.

### Milestone M3.K-2: Knowledge mirror + retrieval
**Goal:** Patterns embed into KnowledgeEntryRecord; retrieval pipeline functional.

| # | File | LOC | Depends on |
|---|---|---|---|
| 2.1 | `knowledge/services/knowledge_mirror.py` | 200 | 1.7, existing KnowledgeService |
| 2.2 | `knowledge/services/bug_class_classifier.py` | 150 | 1.8 |
| 2.3 | `knowledge/services/pattern_retriever.py` | 300 | 2.1, 2.2 |
| 2.4 | `knowledge/workers/pattern_embedder_worker.py` (ARQ) | 100 | 2.1 |

**Exit:** Create a pattern → embedding computed → mirrored to KnowledgeEntryRecord. Retrieval returns top-K with composite score for a sample target + question.

### Milestone M3.K-3: Extraction
**Goal:** Successful investigations auto-extract pattern drafts.

| # | File | LOC | Depends on |
|---|---|---|---|
| 3.1 | `knowledge/services/pattern_extractor.py` | 250 | reasoning engine |
| 3.2 | `data/extraction_prompts/pattern_extraction.md` | 200 | — |
| 3.3 | `data/extraction_prompts/extraction_examples.md` | 250 | — |
| 3.4 | `knowledge/workers/pattern_extractor_worker.py` (ARQ) | 150 | 3.1 |

**Exit:** Investigation closes with `DirectFinding` outcome → ARQ task runs → 0-N pattern drafts written to `vr_patterns` with status=draft + scope=local.

### Milestone M3.K-4: Promotion + supersession
**Goal:** Operator promotion workflow + conflict tracking.

| # | File | LOC | Depends on |
|---|---|---|---|
| 4.1 | `knowledge/services/pattern_promoter.py` | 200 | 1.7 |
| 4.2 | Promotion API endpoints | 150 | 4.1 |
| 4.3 | Pattern review + edit API endpoints | 150 | 1.7 |
| 4.4 | Supersession API endpoints | 80 | 1.7 |

**Exit:** Operator promotes a draft → status=active, scope=workspace. Future investigations in that workspace retrieve the pattern. Supersession marks old pattern superseded; retrieval skips superseded.

### Milestone M3.K-5: Usage tracking + feedback
**Goal:** Pattern success tracking informs retrieval ranking.

| # | File | LOC | Depends on |
|---|---|---|---|
| 5.1 | `knowledge/services/pattern_usage_tracker.py` | 250 | 1.7 |
| 5.2 | `knowledge/workers/pattern_usage_aggregator.py` (ARQ daily) | 100 | 5.1 |
| 5.3 | `knowledge/workers/pattern_archiver.py` (ARQ weekly) | 80 | 5.1 |
| 5.4 | Feedback API endpoints | 120 | 5.1 |

**Exit:** Pattern usage logged on retrieval + reference. Operator marks usefulness post-investigation. Success rate recomputed daily. Patterns with success_rate < 0.2 after 10+ uses auto-flagged.

### Milestone M3.K-6: Integration with reasoning engine
**Goal:** Engine retrieves patterns at investigation start + branch fork + keyword match.

| # | File | LOC | Depends on |
|---|---|---|---|
| 6.1 | `reasoning/services/investigation_runtime.py` updates: hook retrieval at start + fork | 100 | 2.3 |
| 6.2 | `reasoning/agents/vuln_researcher.py` updates: inject patterns into evidence pack | 80 | 6.1 |
| 6.3 | `reasoning/services/message_classifier.py` updates: trigger keyword-based retrieval | 60 | 6.1 |
| 6.4 | Usage logging hook in `HonestVulnResearcher._run_turn()` | 60 | 5.1 |

**Exit:** Start an investigation → engine retrieves applicable patterns → injected as priority 60 evidence section → reference in reasoning visible in turn. Usage logged automatically.

### Milestone M3.K-7: Reporting + quality
**Goal:** Extraction quality monitoring.

| # | File | LOC | Depends on |
|---|---|---|---|
| 7.1 | `knowledge/workers/pattern_quality_reporter.py` (ARQ weekly) | 150 | — |
| 7.2 | Quality report API endpoint | 80 | 7.1 |
| 7.3 | Top patterns API endpoint | 60 | 1.7 |

**Exit:** Weekly quality report shows: investigations completed, patterns extracted, promotion rate, success rate trends. Top patterns endpoint returns ranked list per scope.

### Milestone M3.K-8: Frontend
**Goal:** Operator UI for pattern review, promotion, retrieval, feedback.

| # | File | LOC | Depends on |
|---|---|---|---|
| 8.1 | `frontend/queries.ts` pattern queries | 100 | API |
| 8.2 | `frontend/mutations.ts` pattern mutations | 80 | API |
| 8.3 | `frontend/screens/PatternCatalogList.tsx` | 350 | 8.1 |
| 8.4 | `frontend/screens/PatternDetail.tsx` | 400 | 8.1, 8.2 |
| 8.5 | `frontend/screens/PatternReview.tsx` (post-investigation review screen) | 300 | 8.1, 8.2 |
| 8.6 | `frontend/components/PatternChainViz.tsx` (React Flow lineage) | 250 | 8.4 |
| 8.7 | `frontend/components/PatternUsageTimeline.tsx` | 180 | 8.4 |
| 8.8 | `frontend/components/RecommendedPatternsPanel.tsx` (sidebar at investigation start) | 200 | 8.1 |
| 8.9 | `frontend/components/PatternFeedbackModal.tsx` | 150 | 8.2 |
| 8.10 | `frontend/spec.ts` route additions | 30 | 8.3-8.5 |

**Exit:** Operator browses catalog, opens pattern, sees usage chain + usage timeline. After investigation closes, prompted to review extracted patterns + provide feedback on retrieved ones. Investigation start screen shows recommended patterns.

### Milestone M3.K-9: Tests + benchmark
**Goal:** Verify catalog correctness + retrieval quality.

| # | File | LOC | Depends on |
|---|---|---|---|
| 9.1 | `tests/vr/knowledge/test_contracts.py` | 100 | 1.x |
| 9.2 | `tests/vr/knowledge/test_pattern_store.py` | 150 | 1.7 |
| 9.3 | `tests/vr/knowledge/test_knowledge_mirror.py` | 150 | 2.1 |
| 9.4 | `tests/vr/knowledge/test_pattern_retriever.py` | 250 | 2.3 |
| 9.5 | `tests/vr/knowledge/test_pattern_extractor.py` | 200 | 3.1 |
| 9.6 | `tests/vr/knowledge/test_pattern_promoter.py` | 150 | 4.1 |
| 9.7 | `tests/vr/knowledge/test_usage_tracker.py` | 150 | 5.1 |
| 9.8 | `tests/vr/knowledge/scenarios/*.json` (5 scenarios) | 300 | — |
| 9.9 | `tests/vr/knowledge/test_retrieval_benchmark.py` | 250 | M3.K-1 to M3.K-6 |

**Exit benchmarks:**
- **Scenario K-A**: Extraction quality — given known successful investigation transcript (V8MapInference re-derivation), extractor produces ≥3 patterns including the core fuzzing strategy and at least one search heuristic.
- **Scenario K-B**: Retrieval correctness — given 100 mock patterns + a query about V8 type confusion, top-5 includes the seeded relevant pattern; precision@5 ≥ 0.6.
- **Scenario K-C**: Success-rate signal — seed 20 patterns with synthetic usage (10 high-success, 10 low-success); after aggregator runs, top-5 by score is dominated by high-success patterns.
- **Scenario K-D**: Supersession — pattern A superseded by B; retrieval skips A; B retrieved instead.
- **Scenario K-E**: Cross-workspace promotion — pattern promoted from workspace-1 to team scope; investigations in workspace-2 retrieve it.

---

## Total Estimate

| Milestone | Files | LOC | Cumulative |
|---|---|---|---|
| M3.K-1 Foundation | 9 | ~1370 | 1370 |
| M3.K-2 Mirror + retrieval | 4 | ~750 | 2120 |
| M3.K-3 Extraction | 4 | ~850 | 2970 |
| M3.K-4 Promotion + supersession | 4 | ~580 | 3550 |
| M3.K-5 Usage tracking | 4 | ~550 | 4100 |
| M3.K-6 Reasoning integration | 4 | ~300 | 4400 |
| M3.K-7 Reporting | 3 | ~290 | 4690 |
| M3.K-8 Frontend | 10 | ~2040 | 6730 |
| M3.K-9 Tests + benchmark | 9 | ~1700 | 8430 |
| **Total** | **51 files** | **~8400 LOC** | |

Cross-cutting v0.3 totals now:
- v0.3 reasoning: ~14000 LOC
- v0.3 fuzzing: ~9000 LOC
- v0.3 disclosure: ~13000 LOC
- **v0.3 knowledge: ~8400 LOC** ← this plan
- MCP fleet platform: ~1900 LOC
- MCP fleet frontend: ~700 LOC
- **Total v0.3: ~47000 LOC across ~320 files**

---

## Risks & Open Questions

### R-K1: Extraction quality drift
LLM extraction quality varies with model + prompt. Mitigation: GA-48 weekly quality report. If promotion rate drops below 30% of extracted, prompt/model gets reviewed.

### R-K2: Pattern catalog pollution
Operators may approve patterns too liberally → catalog fills with low-value entries. Mitigation: success rate gating — patterns with success_rate < 0.2 after 10+ uses auto-archived. Operator can promote back manually if archive was wrong.

### R-K3: Contradiction at retrieval
GA-47 says system doesn't resolve contradictions. This places burden on engine to handle gracefully. Mitigation: explicit `contradicts_pattern_id` field on patterns; retrieval surfaces contradiction signal so engine prompt can address it directly.

### R-K4: Semantic search recall on novel queries
Patterns extracted from one CVE may not surface for a novel-looking query even when applicable. Mitigation: FTS over `summary` + `body` complements semantic search; both contribute to composite score. Hybrid search is on by default.

### R-K5: Scope leak
A pattern promoted to global that contains workspace-specific or sensitive details. Mitigation: promotion to team/global requires platform_admin approval. Promotion modal displays full pattern body + applicability for review.

### R-K6: Cost of extraction
Every successful investigation triggers LLM extraction (one prompt). At scale this is real cost. Mitigation: only extract on outcomes producing actionable results (`DirectFinding`, `CrashTriageReport`, `VariantHuntOrder`, `ProfileSpecDraft`). Skip extraction for `AssessmentReport`, `AuditMemo`, `ConfigDelta` outcomes (those don't typically yield reusable techniques).

### R-K7: Pattern obsolescence
A technique that worked in 2024 may be neutralized by 2026 vendor mitigations. Patterns have `last_used_at`; usage_tracker downweights stale patterns. Manual `superseded_by` lets operator explicitly retire obsolete ones.

---

## Out of Scope

- ML-trained pattern classifier (v0.4+)
- Pattern-to-pattern semantic graph beyond supersession links (v0.5)
- Auto-generated pattern descriptions from raw code without LLM (v0.5)
- Pattern marketplace / inter-team sharing (v0.5+)
- Pattern versioning with semver (v0.4 considers; v0.3 uses supersession only)
- Auto-generation of test cases from pattern body (v0.4)
