# VR Module — Data Model

The complete persistent shape of the VR module: every table, every relationship, every state machine, every query the runtime is expected to run, every migration that gets us there. Brainstorm-grade — what the data should look like if all the prior docs land coherently.

Cross-references:
- prior design notes (D-01 .. D-06) — closed scope decisions
- `docs/vr/01_REASONING_LOOP.md` — what `VRCaseState` and obligations look like at runtime
- `docs/vr/03_EXPLOIT_AUTOMATION.md` — exploit tier model that drives `VRExploit` fields
- `docs/vr/04_MULTI_TARGET.md` — the project graph this data model has to materialize
- `docs/MODULE_STANDARD.md` — module ownership boundaries (the platform never imports from here)
- `docs/DATABASE_MIGRATIONS.md` — Alembic conventions (no runtime DDL, append-only versions)
- `src/aila/storage/mixins.py` — `TeamScopedMixin` that all team-owned VR tables inherit
- `src/aila/modules/forensics/db_models/` — the forensics shape we are deliberately mirroring where it makes sense

This document is data-only. It does not redesign the loop, the campaign manager, or the evidence graph — it commits them to columns.

---

## 0. Naming and Layout

All VR tables live under `src/aila/modules/vr/db_models/` (mirroring `forensics/db_models/`). Table names are prefixed `vr_*`. Every team-scoped table inherits `TeamScopedMixin` so the platform's `do_orm_execute` listener auto-injects `WHERE team_id = ?`. UUIDs are stored as `Text` (not `UUID(as_uuid=True)`) to keep the column type identical to the forensics module's existing convention and to avoid a forced cast on every join across modules. Every table has `created_at: DateTime(timezone=True)` defaulted via `utc_now`; mutable rows also have `updated_at`. All long blobs (decompilation snippets, ASAN reports, GDB transcripts, exploit scripts) are stored as `Text` columns named `*_json` or `*_content` and **not** indexed; the materialized columns alongside them carry the indexed scalars used in queries.

Module name in code: `vulnerability_research`. Module name in URLs and frontend: `vr`. Database prefix: `vr_`.

---

## 1. Entity Map

The shape, in one diagram, before any column-level discussion:

```
                     +----------------------+
                     |     VRProject        |
                     | one engagement       |
                     +----------+-----------+
                                |
            +-------------------+-------------------+
            |                   |                   |
            v                   v                   v
   +-----------------+  +----------------+  +------------------+
   |   VRTarget      |  |  VRNdayTask    |  | VROperatorSteer- |
   | binary/lib/repo |  | one CVE        |  | ing (per project)|
   +-------+---------+  +---+------------+  +------------------+
           |                |
   +-------+-------+        |
   |       |       |        |
   v       v       v        v
+--------+ +-----------+  +----------+
|VRHypo- | |VRFuzzing- |  |VRExploit |  (exploits link to either a crash
|thesis  | |Campaign   |  |          |   from a campaign OR an N-day task)
+---+----+ +----+------+  +----+-----+
    |           |              |
    |           v              |
    |       +-------+          |
    |       |VRCrash|----------+ (a confirmed exploitable crash
    |       +---+---+              becomes the basis of a VRExploit)
    |           |
    +-----------+
            |
            v
       +---------+
       |VRAdvisory|  (per-finding disclosure-ready writeup;
       +----+----+    ties together exploit + crash + hypothesis)
            |
            v
     +-------------+
     |VRDisclosure |  (vendor coordination state per advisory; D-04)
     +-------------+

Spanning across everything:

   +------------------+        +-----------------+
   | VREvidenceNode   |<------>| VREvidenceEdge  |
   | (one per claim,  |  fan   | (typed edges)   |
   |  observation,    |   out  +-----------------+
   |  artifact ref)   |
   +--------+---------+
            |
            v
   +-------------------+
   |   VRObligation    |  (an obligation is anchored to a node;
   |                   |   the graph cannot mark dependents
   +-------------------+   "confirmed" while obligations are open)
```

A few invariants the schema is forced to maintain:

- **A `VRTarget` always belongs to a `VRProject`.** No floating targets.
- **A `VRHypothesis` always belongs to a `VRTarget`** (even cross-target patterns are modeled as a *hypothesis on the project*, expressed by a target with `kind = PROJECT_VIRTUAL` — see §3.2).
- **A `VRCrash` always belongs to a `VRFuzzingCampaign`.** Crashes that come from manual triggers, not fuzzing, get a synthetic "manual" campaign per target so the foreign-key always holds.
- **A `VRExploit` references either `crash_id` xor `nday_task_id`** — exactly one of the two is non-NULL. Enforced as a `CHECK` constraint, not application logic.
- **A `VRAdvisory` references at least one `VRExploit`** (or, for non-exploitable but reportable findings, at least one `VRCrash` with `triage_state='not_exploitable_disclosed'`).
- **A `VRDisclosure` is 1:1 with a `VRAdvisory`.** The advisory is the body of the report; the disclosure record is the coordination state with the vendor.
- **`VREvidenceNode.target_id` is nullable** (project-level nodes like CHAIN, PATTERN have NULL). `VREvidenceNode.project_id` is **not** nullable.
- **All team-scoped tables share `team_id`**; the platform's row-level filter uses it. Project-scoped child tables (campaigns, hypotheses, crashes, etc.) duplicate `team_id` rather than join through the project; this matches the vulnerability module convention and avoids JOINs in hot-path queries.
- **Storage prefix today.** Tables live under `src/aila/modules/vr/db_models/` (not `vulnerability_research/`), table names are prefixed `vr_*`, and the module id used in routes and the frontend matches the package name: `vr`. The historical `vulnerability_research` naming above is preserved for design context only.

### Migration heads adjacent to this doc

The shipped schema is the union of `db_models/` modules and the Alembic migrations under `src/aila/alembic/versions/`. Three recent heads that affect the diagrams above:

| Revision | Adds |
|---|---|
| `060_vr_target_analysis_stages` | `vr_target_analysis_stages_json` on `vr_targets` (per-stage status + timestamps + attempts + error); `aila.modules.vr.services.stage_tracker` owns idempotency + RUNNING-timeout reaping. |
| `061_llm_idempotency_cache` | `llm_idempotency_cache` table keyed on `sha256(investigation_id, branch_id, turn_number, prompt_hash)`. Retries replay the cached decision so a transport hiccup never re-pays the LLM. Caller-supplied keys live in `vuln_researcher.run_turn`. |
| `062_vr_outcome_review` (current head) | `state` column on `vr_investigation_outcomes` (`draft | approved | rejected | dispatched`) and `vr_outcome_reviews` (one row per sibling vote: `approve | reject | request_edit | abstain`, with `UNIQUE(outcome_id, reviewer_branch_id)`). Powers the sibling-corroborated draft-outcome workflow plus the pre-submit draft-pending gate referenced in `01_REASONING_LOOP.md §8.bis.5`. |

---

## 2. State Machines

All state columns are `Text` with a `CHECK` constraint enumerating the allowed values. Values are lowercase snake_case so the same string is the API value, the storage value, and the display value (no `value_to_display()` mapping layer). Transitions are validated in the workflow layer; the DB constraint exists to catch programming errors (typo in a state literal), not as the authoritative state machine.

### 2.1 Project lifecycle

```
created --[targets registered]--> active --[engagement closed]--> completed --[60d]--> archived
   |                                |                                |
   |                                v                                v
   +-----------> archived  <-- archived (early termination)         (cold storage)
```

| state | meaning |
|---|---|
| `created` | Project row exists; no targets yet; operator is configuring scope. |
| `active` | At least one target registered; campaigns/hypotheses can run; reasoning loop accepts turns. |
| `completed` | Operator marked the engagement done. Read-only; advisories may still progress through `VRDisclosure` lifecycle. |
| `archived` | Cold storage. Read-only at API; large blob columns may be moved to object storage and replaced with refs. |

Transitions are operator-driven only — the runtime never auto-archives. Archive is a separate maintenance job.

### 2.2 Target lifecycle

```
registered --[recon done]--> analyzing --[harness ready]--> fuzzing
                                  |                            |
                                  |                            v
                                  +--------------------------> exploiting --[advisory drafted]--> reported
                                  |                            ^                                       |
                                  +----------------------------+                                       |
                                                                                                       |
                                                                          archived <-------------------+
```

| state | meaning |
|---|---|
| `registered` | Target identified, hashed, classified by `target_class`. No analysis has run. |
| `analyzing` | Static analysis, decompilation, IDA/Ghidra ingestion in progress; hypotheses being seeded. |
| `fuzzing` | At least one campaign in `running` or `monitoring`. |
| `exploiting` | At least one crash is in `triaged` or further; exploit loop is active. |
| `reported` | All exploitable findings on this target have advisories drafted. Target may still re-enter `fuzzing` for variant search. |
| `archived` | Target excluded from further work in this project. |

A target may be in *multiple conceptual phases simultaneously* (campaign running while exploit loop chases an earlier crash). The single `state` column captures the **dominant** phase — the one the project plan should display in the top-line view. Per-campaign and per-crash detail comes from those tables. We deliberately do not model this as an aggregate state graph; the operator wants one summary value, not a Cartesian product.

### 2.3 Hypothesis lifecycle

```
proposed --[turn picks it up]--> investigating --+--[reproducer + obligation discharge]--> confirmed
                                                  |
                                                  +--[refuted by evidence]--> rejected
                                                  |
                                                  +--[confirmed elsewhere]--> variant_searching
                                                                                    |
                                                                              [variants enumerated]
                                                                                    |
                                                                                    v
                                                                                confirmed
                                                                                    or
                                                                                rejected
```

| state | meaning |
|---|---|
| `proposed` | LLM emitted hypothesis text + target context. No turn has reasoned about it yet. |
| `investigating` | At least one turn has acted on this hypothesis (decompiled a function, run a tool, etc.). |
| `confirmed` | A reproducer exists (crash, taint trace, formal property). All confirmation obligations discharged. |
| `rejected` | Evidence refutes the hypothesis. Captured with the refuting obligation IDs; cannot be re-opened without new evidence (Metis rule). |
| `variant_searching` | Hypothesis confirmed; pattern signature derived; the LLM is enumerating siblings across the project. |

The `rejected` -> `proposed` transition is **prohibited at the DB level** (CHECK on transitions log). The LLM cannot reverse a refutation by re-reasoning over the same evidence; per Metis, only fresh evidence permits re-opening, which is modeled as a *new* hypothesis with a `parent_hypothesis_id` link.

### 2.4 Fuzzing campaign lifecycle

```
configured --[harness compiled, corpus ready]--> running --[periodic check]--> monitoring
    |                                                |                              |
    |                                                |                              v
    +--[failed to compile/start]--> failed           +--[crash found]--> triaging --+--> completed
                                                                                    |
                                                                                    v
                                                                                  resumed (-> running)
```

| state | meaning |
|---|---|
| `configured` | Campaign row exists; harness binary path set; corpus seeded; not yet started. |
| `running` | Fuzzer process is alive on the workstation. `process_pid`, `last_heartbeat_at` populated. |
| `monitoring` | The runtime is polling for new crashes / coverage growth on a cadence; the fuzzer is still alive but the runtime has stepped back from active observation. |
| `triaging` | Fuzzer paused; runtime is minimizing/deduplicating discovered crashes. |
| `completed` | Campaign ended (operator stop, time budget, coverage plateau, target rebuilt). Final stats locked. |
| `failed` | Failed to start, harness segfaults on first input, etc. Diagnostic in `failure_reason`. |

`monitoring` is a real state, not a UI flourish: it tells the scheduler "I can preempt this without losing work; just snapshot the corpus." Without it, the scheduler must treat any active campaign as `running` and refuse to multiplex.

### 2.5 Crash lifecycle

```
discovered --[afl-tmin / similar]--> minimized --[dedup + classify]--> triaged
                                                                          |
                                                                          +--[primitive identified]--> exploitable
                                                                          |
                                                                          +--[no useful primitive]--> not_exploitable
```

| state | meaning |
|---|---|
| `discovered` | Raw crash from the fuzzer — input file, signal, top of stack only. |
| `minimized` | Input minimized (afl-tmin or equivalent). Stable reproducer recorded. |
| `triaged` | Deduplicated against existing crashes. Root cause classified (CWE candidate, allocator-relevant, etc.). |
| `exploitable` | Tier-classified per `03_EXPLOIT_AUTOMATION.md`; the exploit loop has confirmed primitive existence. |
| `not_exploitable` | Triage concluded no useful primitive. Stored anyway — useful evidence and may be re-classified if new info arrives. |

A crash never returns to a previous state via transition alone; if "not_exploitable" needs to flip to "exploitable," a *new* crash row is created with `re_triage_of` pointing at the original. This forces fresh evidence and gives the audit trail.

### 2.6 Exploit lifecycle

```
drafting --[script compiles]--> testing --[1+ successful run]--> working --[reliability sweep >= threshold]--> reliable
   ^                                                                |
   |                                                                v
   +-------- abandoned <---- abandoned (any state, manual or budget) +
                                                                     |
                                                                     v
                                                              advisory_ready
```

| state | meaning |
|---|---|
| `drafting` | Exploit script being constructed turn-by-turn. May not yet compile or execute. |
| `testing` | Script runs; one or more runs observed; reliability not yet measured. |
| `working` | At least one reproducible success. May be flaky. |
| `reliable` | Sweep of M runs reached target threshold (default 90% per project policy; see §6 query patterns). |
| `advisory_ready` | The reliability + obligation discharge requirements are all met; advisory generation can proceed. |
| `abandoned` | The exploit loop bailed (budget exhausted, primitive proven inadequate). Reasoning trail preserved. |

Per Metis: `testing -> working` requires *evidence between turns*. An LLM cannot self-promote an exploit by re-reading the same run logs.

### 2.7 N-day task lifecycle

```
researching --[advisory + commit refs collected]--> patch_found --[diff understood]--> root_caused
                                                                                            |
                                                                                            v
                                                                                       poc_developing
                                                                                            |
                                                                                            v
                                                                                       poc_working --> advisory_written
```

| state | meaning |
|---|---|
| `researching` | CVE picked, public advisories being scraped, related commits being identified. |
| `patch_found` | The patch commit is identified and the *pre*-patch source is locatable. |
| `root_caused` | The bug is understood at the source level; pre-patch reproduction conditions are known. |
| `poc_developing` | Exploit being written against the pre-patch build. |
| `poc_working` | PoC reliably reproduces against pre-patch; correctly fails against post-patch (the negative test). |
| `advisory_written` | Internal write-up complete; if customer-facing, eligible for disclosure pipeline. |

N-day tasks share a state machine with research-mode `VRExploit` only conceptually — they each have their own state column because the milestones are different. A single `state` enum that mixes both makes neither legible. This is the answer to open question 7 in `03_EXPLOIT_AUTOMATION.md`: **two state machines, separate tables, separate workflows; no shared `mode` flag.**

### 2.8 Disclosure lifecycle

```
undisclosed --[vendor contacted]--> reported --[ack received]--> acknowledged
                                                                       |
                                                                       v
                                                              patch_pending
                                                                       |
                                                                       +--[patch shipped]--> patched
                                                                       |
                                                                       +--[deadline expired, going public]--> public
                                                              patched --[publish window]--> public
```

| state | meaning |
|---|---|
| `undisclosed` | Default. Advisory is internal-only. |
| `reported` | Reported to vendor PSIRT. Reporter, channel, timestamp recorded. |
| `acknowledged` | Vendor responded with a tracking ID or human acknowledgment. |
| `patch_pending` | Vendor confirmed they're working on a fix; expected ship date set or not set. |
| `patched` | Patch shipped; CVE may or may not be assigned yet. |
| `public` | Advisory is public — either coordinated release post-patch, or expired-deadline release. |

`patched -> public` is operator-controlled even if a coordinated release date is set; the runtime never auto-publishes (D-04 keeps the human in the loop).

---

## 3. Table Definitions

Concrete `SQLModel` classes follow. Each is what we expect to live in `src/aila/modules/vulnerability_research/db_models/`. Style copies the existing forensics and vulnerability modules: `Field` for short scalars, `sa_column=Column(Text)` for blobs, `__tablename__` always set explicitly, `__table_args__` carries indexes and check constraints.

### 3.1 Project, target, steering

```python
# src/aila/modules/vulnerability_research/db_models/project.py
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import CheckConstraint, Column, DateTime, Index, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now
from aila.storage.mixins import TeamScopedMixin

PROJECT_STATES = ("created", "active", "completed", "archived")


class VRProjectRecord(TeamScopedMixin, SQLModel, table=True):
    """One vulnerability research engagement.

    Owns: targets, n-day tasks, operator steering, evidence graph nodes.
    Lifetime: create -> active -> completed -> archived (operator-driven).
    """

    __tablename__ = "vr_projects"
    __table_args__ = (
        CheckConstraint(
            f"state IN ({', '.join(repr(s) for s in PROJECT_STATES)})",
            name="ck_vr_project_state",
        ),
        Index("ix_vr_projects_state", "state"),
        Index("ix_vr_projects_team_id", "team_id"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    name: str = Field(max_length=255)
    description: str = Field(default="", sa_column=Column(Text))
    engagement_kind: str = Field(default="open_research", max_length=32)
    # open_research | nday_research | mixed
    state: str = Field(default="created")
    workstation_id: int = Field(index=True)
    workspace_root: str = Field(sa_column=Column(Text))
    # Posture report config — small JSON of include/exclude flags
    report_config_json: str = Field(default="{}", sa_column=Column(Text))
    notes: str = Field(default="", sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
```

```python
# src/aila/modules/vulnerability_research/db_models/target.py
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import CheckConstraint, Column, DateTime, Index, Text, UniqueConstraint
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now
from aila.storage.mixins import TeamScopedMixin

TARGET_STATES = (
    "registered", "analyzing", "fuzzing",
    "exploiting", "reported", "archived",
)
TARGET_KINDS = (
    "native_binary", "shared_library", "kernel_module",
    "hypervisor_component", "java_artifact", "source_repo",
    "script_file", "config_parser", "network_protocol",
    "project_virtual",
)
TARGET_CLASSES = ("native", "kernel", "hypervisor", "java", "python", "js", "php", "go", "rust")


class VRTargetRecord(TeamScopedMixin, SQLModel, table=True):
    """One artifact within a project.

    The `kind` discriminator drives which tools apply (IDA for native, Bandit for
    python, etc.).  `target_class` (D-03) drives workflow branching.

    `project_virtual` targets exist for project-level concerns (CHAIN nodes,
    PATTERN nodes) that don't belong to any single artifact.
    """

    __tablename__ = "vr_targets"
    __table_args__ = (
        CheckConstraint(
            f"state IN ({', '.join(repr(s) for s in TARGET_STATES)})",
            name="ck_vr_target_state",
        ),
        CheckConstraint(
            f"kind IN ({', '.join(repr(s) for s in TARGET_KINDS)})",
            name="ck_vr_target_kind",
        ),
        UniqueConstraint("project_id", "path", name="uq_vr_target_project_path"),
        Index("ix_vr_targets_project_id", "project_id"),
        Index("ix_vr_targets_state", "state"),
        Index("ix_vr_targets_sha256", "sha256"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    project_id: str = Field(index=True)
    kind: str
    target_class: str  # native | kernel | hypervisor | java | python | ...
    path: str = Field(sa_column=Column(Text))
    sha256: str = Field(default="", sa_column=Column(Text))
    arch: str | None = Field(default=None, max_length=32)
    # network_exposure / privilege_context — small structured JSON
    surface_json: str = Field(default="{}", sa_column=Column(Text))
    mitigations_json: str = Field(default="{}", sa_column=Column(Text))
    state: str = Field(default="registered")
    # Pointer to the IDA/Ghidra database directory, if one exists
    analysis_db_path: str | None = Field(default=None, sa_column=Column(Text))
    notes: str = Field(default="", sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
```

```python
# src/aila/modules/vulnerability_research/db_models/steering.py
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, Index, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now
from aila.storage.mixins import TeamScopedMixin


class VROperatorSteeringRecord(TeamScopedMixin, SQLModel, table=True):
    """Operator-injected context for a project.

    Mirrors `ReasoningOperatorSteering` from forensics.  Pinned campaigns,
    priority overrides, strategy pins, banned strategies, free-text guidance.

    Append-only: each edit creates a new row with `supersedes` pointing to
    the prior one, so the audit trail of operator influence is preserved.
    """

    __tablename__ = "vr_operator_steering"
    __table_args__ = (
        Index("ix_vr_steering_project_id", "project_id"),
        Index("ix_vr_steering_active", "project_id", "is_active"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    project_id: str = Field(index=True)
    is_active: bool = Field(default=True)
    supersedes: str | None = Field(default=None)
    pinned_campaigns_json: str = Field(default="[]", sa_column=Column(Text))
    priority_overrides_json: str = Field(default="{}", sa_column=Column(Text))
    strategy_pins_json: str = Field(default="[]", sa_column=Column(Text))
    banned_strategies_json: str = Field(default="[]", sa_column=Column(Text))
    free_text: str = Field(default="", sa_column=Column(Text))
    author_user_id: str = Field(default="", max_length=64)
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
```

### 3.2 Hypothesis, campaign, crash

```python
# src/aila/modules/vulnerability_research/db_models/hypothesis.py
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import CheckConstraint, Column, DateTime, Index, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now
from aila.storage.mixins import TeamScopedMixin

HYPOTHESIS_STATES = (
    "proposed", "investigating", "confirmed",
    "rejected", "variant_searching",
)


class VRHypothesisRecord(TeamScopedMixin, SQLModel, table=True):
    """A research hypothesis about a target.

    `parent_hypothesis_id` chains re-opened hypotheses (a refuted hypothesis
    cannot be flipped to `proposed`; instead a new row is created with the
    parent reference, satisfying the Metis fresh-evidence rule).

    `signature_json` carries the structural pattern signature (function-hash
    or AST sketch) once a hypothesis is confirmed and pattern extraction has
    run; populated by the variant-search step.
    """

    __tablename__ = "vr_hypotheses"
    __table_args__ = (
        CheckConstraint(
            f"state IN ({', '.join(repr(s) for s in HYPOTHESIS_STATES)})",
            name="ck_vr_hypothesis_state",
        ),
        Index("ix_vr_hypotheses_target_id", "target_id"),
        Index("ix_vr_hypotheses_project_id", "project_id"),
        Index("ix_vr_hypotheses_state", "state"),
        Index("ix_vr_hypotheses_parent", "parent_hypothesis_id"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    project_id: str = Field(index=True)
    target_id: str = Field(index=True)
    parent_hypothesis_id: str | None = Field(default=None)
    title: str = Field(max_length=512)
    description: str = Field(sa_column=Column(Text))
    cwe_candidate: str | None = Field(default=None, max_length=32)
    state: str = Field(default="proposed")
    confidence: float = Field(default=0.0)
    # Outstanding evidence obligation IDs blocking confirmation
    blocking_obligation_ids_json: str = Field(default="[]", sa_column=Column(Text))
    # When confirmed, the structural pattern signature derived from this hypothesis
    signature_json: str | None = Field(default=None, sa_column=Column(Text))
    # Free-text reasoning trail — last summary written by the loop
    reasoning_summary: str = Field(default="", sa_column=Column(Text))
    rejected_reason: str = Field(default="", sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
```

```python
# src/aila/modules/vulnerability_research/db_models/campaign.py
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import CheckConstraint, Column, DateTime, Index, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now
from aila.storage.mixins import TeamScopedMixin

CAMPAIGN_STATES = (
    "configured", "running", "monitoring",
    "triaging", "completed", "failed",
)
FUZZER_KINDS = ("aflpp", "winafl", "honggfuzz", "libfuzzer", "manual", "grammar")


class VRFuzzingCampaignRecord(TeamScopedMixin, SQLModel, table=True):
    """One fuzzing run against one target.

    `process_pid` and `last_heartbeat_at` are populated while the fuzzer is
    alive; the watchdog uses them to detect dead campaigns.

    `manual` campaigns exist as a synthetic anchor for crashes produced
    outside fuzzing (PoC-driven, manual triggers) so VRCrash always has a
    parent campaign FK.
    """

    __tablename__ = "vr_fuzzing_campaigns"
    __table_args__ = (
        CheckConstraint(
            f"state IN ({', '.join(repr(s) for s in CAMPAIGN_STATES)})",
            name="ck_vr_campaign_state",
        ),
        CheckConstraint(
            f"fuzzer_kind IN ({', '.join(repr(s) for s in FUZZER_KINDS)})",
            name="ck_vr_campaign_fuzzer",
        ),
        Index("ix_vr_campaigns_target_id", "target_id"),
        Index("ix_vr_campaigns_project_id", "project_id"),
        Index("ix_vr_campaigns_state", "state"),
        Index("ix_vr_campaigns_heartbeat", "last_heartbeat_at"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    project_id: str = Field(index=True)
    target_id: str = Field(index=True)
    fuzzer_kind: str
    harness_path: str = Field(sa_column=Column(Text))
    corpus_path: str = Field(sa_column=Column(Text))
    output_path: str = Field(sa_column=Column(Text))
    config_json: str = Field(default="{}", sa_column=Column(Text))
    state: str = Field(default="configured")
    process_pid: int | None = Field(default=None)
    last_heartbeat_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    started_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    stopped_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    # Final stats locked at completion — execs, paths, coverage %, crashes
    stats_json: str = Field(default="{}", sa_column=Column(Text))
    failure_reason: str = Field(default="", sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
```

```python
# src/aila/modules/vulnerability_research/db_models/crash.py
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import CheckConstraint, Column, DateTime, Index, Integer, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now
from aila.storage.mixins import TeamScopedMixin

CRASH_STATES = (
    "discovered", "minimized", "triaged",
    "exploitable", "not_exploitable",
)


class VRCrashRecord(TeamScopedMixin, SQLModel, table=True):
    """One unique crash from a fuzzing campaign (or a synthetic 'manual' campaign).

    Dedup is by `crash_signature` (top-N stack frames + signal); rows with
    the same signature are folded into a single record at triage time.

    `re_triage_of` chains a re-classified crash to its predecessor — used
    when a `not_exploitable` crash is later found to be exploitable; the new
    row carries the new evidence, the old row stays for audit.
    """

    __tablename__ = "vr_crashes"
    __table_args__ = (
        CheckConstraint(
            f"state IN ({', '.join(repr(s) for s in CRASH_STATES)})",
            name="ck_vr_crash_state",
        ),
        Index("ix_vr_crashes_campaign_id", "campaign_id"),
        Index("ix_vr_crashes_project_id", "project_id"),
        Index("ix_vr_crashes_target_id", "target_id"),
        Index("ix_vr_crashes_signature", "crash_signature"),
        Index("ix_vr_crashes_state", "state"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    project_id: str = Field(index=True)
    target_id: str = Field(index=True)
    campaign_id: str = Field(index=True)
    crash_signature: str = Field(max_length=128)
    signal: str = Field(default="", max_length=16)  # SIGSEGV, SIGABRT, ...
    minimized_input_path: str | None = Field(default=None, sa_column=Column(Text))
    raw_input_path: str = Field(sa_column=Column(Text))
    asan_report: str = Field(default="", sa_column=Column(Text))
    gdb_transcript: str = Field(default="", sa_column=Column(Text))
    crashing_addr: str | None = Field(default=None, max_length=32)
    state: str = Field(default="discovered")
    cwe_candidate: str | None = Field(default=None, max_length=32)
    exploit_tier: int | None = Field(default=None, sa_column=Column(Integer))
    # Hypothesis this crash reproduces (NULL if it was found by undirected fuzzing)
    hypothesis_id: str | None = Field(default=None, index=True)
    re_triage_of: str | None = Field(default=None, index=True)
    triage_notes: str = Field(default="", sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
```

### 3.3 Exploit, advisory, disclosure, n-day

```python
# src/aila/modules/vulnerability_research/db_models/exploit.py
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import CheckConstraint, Column, DateTime, Index, Integer, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now
from aila.storage.mixins import TeamScopedMixin

EXPLOIT_STATES = (
    "drafting", "testing", "working",
    "reliable", "advisory_ready", "abandoned",
)


class VRExploitRecord(TeamScopedMixin, SQLModel, table=True):
    """One exploit / PoC.

    Exactly one of `crash_id` or `nday_task_id` is non-NULL — the CHECK
    constraint enforces the discriminator.

    Reliability: `successes` / `attempts` tracked turn-by-turn; the
    sweep-result column is locked at `reliable` transition time.
    """

    __tablename__ = "vr_exploits"
    __table_args__ = (
        CheckConstraint(
            f"state IN ({', '.join(repr(s) for s in EXPLOIT_STATES)})",
            name="ck_vr_exploit_state",
        ),
        CheckConstraint(
            "(crash_id IS NOT NULL AND nday_task_id IS NULL) "
            "OR (crash_id IS NULL AND nday_task_id IS NOT NULL)",
            name="ck_vr_exploit_anchor",
        ),
        Index("ix_vr_exploits_project_id", "project_id"),
        Index("ix_vr_exploits_target_id", "target_id"),
        Index("ix_vr_exploits_crash_id", "crash_id"),
        Index("ix_vr_exploits_nday_task_id", "nday_task_id"),
        Index("ix_vr_exploits_state", "state"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    project_id: str = Field(index=True)
    target_id: str = Field(index=True)
    crash_id: str | None = Field(default=None)
    nday_task_id: str | None = Field(default=None)
    tier: int = Field(default=1, sa_column=Column(Integer))  # Tier 1-4 from §3 of 03_EXPLOIT_AUTOMATION.md
    title: str = Field(max_length=512)
    primitive_vocab_json: str = Field(default="[]", sa_column=Column(Text))
    # ARW, AAR, RIP, LEAK_libc, etc. — see open question 13 in 03_EXPLOIT_AUTOMATION.md
    script_path: str = Field(sa_column=Column(Text))
    script_content: str = Field(default="", sa_column=Column(Text))
    state: str = Field(default="drafting")
    attempts: int = Field(default=0)
    successes: int = Field(default=0)
    reliability_pct: float | None = Field(default=None)  # locked at `reliable` transition
    sweep_target_pct: float = Field(default=90.0)
    sweep_result_json: str = Field(default="{}", sa_column=Column(Text))
    target_build_hash: str = Field(default="", max_length=128)
    mitigations_bypassed_json: str = Field(default="[]", sa_column=Column(Text))
    abandoned_reason: str = Field(default="", sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
```

```python
# src/aila/modules/vulnerability_research/db_models/advisory.py
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, Index, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now
from aila.storage.mixins import TeamScopedMixin


class VRAdvisoryRecord(TeamScopedMixin, SQLModel, table=True):
    """Disclosure-ready writeup for a single vulnerability.

    Links to the underlying `VRExploit` (or list, for chain advisories) via
    the evidence graph rather than direct FK — a chain advisory references
    multiple exploits across multiple targets, and we don't want N FK
    columns.

    `vendor_advisory_id` and `cve_id` are populated as the disclosure
    process progresses; both are nullable until then.
    """

    __tablename__ = "vr_advisories"
    __table_args__ = (
        Index("ix_vr_advisories_project_id", "project_id"),
        Index("ix_vr_advisories_severity", "severity"),
        Index("ix_vr_advisories_cve_id", "cve_id"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    project_id: str = Field(index=True)
    title: str = Field(max_length=512)
    severity: str = Field(default="UNKNOWN", max_length=16)
    cvss_vector: str = Field(default="", max_length=128)
    cvss_score: float | None = Field(default=None)
    cwe_id: str | None = Field(default=None, max_length=32)
    summary_md: str = Field(default="", sa_column=Column(Text))
    technical_writeup_md: str = Field(default="", sa_column=Column(Text))
    reproducer_path: str | None = Field(default=None, sa_column=Column(Text))
    affected_targets_json: str = Field(default="[]", sa_column=Column(Text))
    is_chain: bool = Field(default=False)
    chain_evidence_node_id: str | None = Field(default=None)
    cve_id: str | None = Field(default=None, max_length=32)
    vendor_advisory_id: str | None = Field(default=None, max_length=128)
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
```

```python
# src/aila/modules/vulnerability_research/db_models/disclosure.py
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import CheckConstraint, Column, DateTime, Index, Text, UniqueConstraint
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now
from aila.storage.mixins import TeamScopedMixin

DISCLOSURE_STATES = (
    "undisclosed", "reported", "acknowledged",
    "patch_pending", "patched", "public",
)


class VRDisclosureRecord(TeamScopedMixin, SQLModel, table=True):
    """Vendor coordination state for one advisory (D-04).

    1:1 with VRAdvisoryRecord.  All transitions are operator-driven; the
    runtime never auto-advances disclosure state.
    """

    __tablename__ = "vr_disclosures"
    __table_args__ = (
        CheckConstraint(
            f"state IN ({', '.join(repr(s) for s in DISCLOSURE_STATES)})",
            name="ck_vr_disclosure_state",
        ),
        UniqueConstraint("advisory_id", name="uq_vr_disclosure_advisory"),
        Index("ix_vr_disclosures_state", "state"),
        Index("ix_vr_disclosures_deadline", "public_deadline_at"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    advisory_id: str = Field(index=True)
    state: str = Field(default="undisclosed")
    vendor: str = Field(default="", max_length=255)
    vendor_psirt_email: str = Field(default="", max_length=255)
    vendor_tracking_id: str = Field(default="", max_length=128)
    reported_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    acknowledged_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    patched_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    public_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    public_deadline_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    correspondence_json: str = Field(default="[]", sa_column=Column(Text))
    notes: str = Field(default="", sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
```

```python
# src/aila/modules/vulnerability_research/db_models/nday.py
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import CheckConstraint, Column, DateTime, Index, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now
from aila.storage.mixins import TeamScopedMixin

NDAY_STATES = (
    "researching", "patch_found", "root_caused",
    "poc_developing", "poc_working", "advisory_written",
)


class VRNdayTaskRecord(TeamScopedMixin, SQLModel, table=True):
    """One CVE being researched for an N-day PoC.

    Distinct from VRTarget — an N-day task identifies *which CVE in which
    upstream codebase*; the actual binary built for PoC execution is still
    a VRTarget under the same project.

    `target_id` becomes non-NULL once a build of the vulnerable version is
    available locally and registered as a target.
    """

    __tablename__ = "vr_nday_tasks"
    __table_args__ = (
        CheckConstraint(
            f"state IN ({', '.join(repr(s) for s in NDAY_STATES)})",
            name="ck_vr_nday_state",
        ),
        Index("ix_vr_nday_project_id", "project_id"),
        Index("ix_vr_nday_cve_id", "cve_id"),
        Index("ix_vr_nday_state", "state"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    project_id: str = Field(index=True)
    cve_id: str = Field(max_length=32)
    upstream_project: str = Field(max_length=255)
    state: str = Field(default="researching")
    advisory_url: str = Field(default="", sa_column=Column(Text))
    patch_commit: str = Field(default="", max_length=128)
    pre_patch_ref: str = Field(default="", max_length=128)
    target_id: str | None = Field(default=None, index=True)
    root_cause_md: str = Field(default="", sa_column=Column(Text))
    notes: str = Field(default="", sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
```

### 3.4 Evidence graph and obligations

```python
# src/aila/modules/vulnerability_research/db_models/evidence.py
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import CheckConstraint, Column, DateTime, Index, Text, UniqueConstraint
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now
from aila.storage.mixins import TeamScopedMixin

NODE_KINDS = (
    "hypothesis", "observation", "crash", "triaged_bug",
    "exploit_attempt", "confirmed_vulnerability", "privilege_boundary",
    "ipc_edge", "chain", "pattern", "obligation",
    "operator_override", "negative_finding",
)
EDGE_KINDS = (
    "supports", "refutes", "reproduces", "exploits",
    "reached_via", "enables_step", "same_root_cause",
    "variant_of", "blocked_by",
)


class VREvidenceNodeRecord(TeamScopedMixin, SQLModel, table=True):
    """A node in the project evidence graph.

    `entity_table` + `entity_id` is the back-pointer to the canonical row
    for nodes that mirror first-class entities (a hypothesis node points at
    its VRHypothesisRecord); for synthetic nodes (CHAIN, PATTERN), both are
    NULL and the node carries its own data in `payload_json`.

    `target_id` is NULL for project-level nodes (CHAIN, PATTERN, project-
    wide PRIVILEGE_BOUNDARY).
    """

    __tablename__ = "vr_evidence_nodes"
    __table_args__ = (
        CheckConstraint(
            f"kind IN ({', '.join(repr(s) for s in NODE_KINDS)})",
            name="ck_vr_evidence_node_kind",
        ),
        Index("ix_vr_evidence_nodes_project_id", "project_id"),
        Index("ix_vr_evidence_nodes_target_id", "target_id"),
        Index("ix_vr_evidence_nodes_kind", "kind"),
        Index("ix_vr_evidence_nodes_entity", "entity_table", "entity_id"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    project_id: str = Field(index=True)
    target_id: str | None = Field(default=None)
    kind: str
    entity_table: str | None = Field(default=None, max_length=64)
    entity_id: str | None = Field(default=None)
    label: str = Field(default="", max_length=512)
    payload_json: str = Field(default="{}", sa_column=Column(Text))
    # Paths to artifact files (corpora, coredumps, listings, traces)
    evidence_refs_json: str = Field(default="[]", sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class VREvidenceEdgeRecord(TeamScopedMixin, SQLModel, table=True):
    """A directed, typed edge between two evidence nodes.

    Indexes on (src, kind) and (dst, kind) cover the two query directions
    we expect (forward traversal from a node, reverse "what depends on
    this" lookup).
    """

    __tablename__ = "vr_evidence_edges"
    __table_args__ = (
        CheckConstraint(
            f"kind IN ({', '.join(repr(s) for s in EDGE_KINDS)})",
            name="ck_vr_evidence_edge_kind",
        ),
        UniqueConstraint("src_node_id", "dst_node_id", "kind", name="uq_vr_evidence_edge"),
        Index("ix_vr_evidence_edges_src", "src_node_id", "kind"),
        Index("ix_vr_evidence_edges_dst", "dst_node_id", "kind"),
        Index("ix_vr_evidence_edges_project_id", "project_id"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    project_id: str = Field(index=True)
    src_node_id: str
    dst_node_id: str
    kind: str
    weight: float = Field(default=1.0)
    payload_json: str = Field(default="{}", sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
```

```python
# src/aila/modules/vulnerability_research/db_models/obligation.py
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import CheckConstraint, Column, DateTime, Index, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now
from aila.storage.mixins import TeamScopedMixin

OBLIGATION_STATES = ("open", "satisfied", "invalidated", "operator_overridden")
OBLIGATION_KINDS = (
    "reproducer_required",
    "reliability_sweep",
    "primitive_proof",
    "mitigation_bypass_proof",
    "negative_test_against_patched",
    "coverage_evidence",
    "isolated_repro_environment",
    "advisory_writeup_review",
)


class VRObligationRecord(TeamScopedMixin, SQLModel, table=True):
    """An evidence obligation gating a claim.

    `anchor_node_id` is the node whose progression the obligation gates.
    `discharged_by_node_id` is the node whose creation satisfied the
    obligation (NULL while open).

    The adjudicator queries this table for `state='open'` rows on any node
    in the chain of a finding before allowing `confirmed_vulnerability` or
    `advisory_ready` transitions.
    """

    __tablename__ = "vr_obligations"
    __table_args__ = (
        CheckConstraint(
            f"state IN ({', '.join(repr(s) for s in OBLIGATION_STATES)})",
            name="ck_vr_obligation_state",
        ),
        CheckConstraint(
            f"kind IN ({', '.join(repr(s) for s in OBLIGATION_KINDS)})",
            name="ck_vr_obligation_kind",
        ),
        Index("ix_vr_obligations_anchor", "anchor_node_id"),
        Index("ix_vr_obligations_state", "state"),
        Index("ix_vr_obligations_project_id", "project_id"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    project_id: str = Field(index=True)
    anchor_node_id: str
    kind: str
    description: str = Field(sa_column=Column(Text))
    state: str = Field(default="open")
    discharged_by_node_id: str | None = Field(default=None)
    discharged_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    operator_override_user_id: str | None = Field(default=None, max_length=64)
    operator_override_reason: str = Field(default="", sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
```

### 3.5 What is *not* its own table

Things considered and rejected:

- **Turn / decision history.** Lives in the existing platform tables (`reasoning_graph_snapshots` and the `WorkflowRunRecord` / step records). VR adds `case_state_json` references inside hypothesis and exploit rows, but the canonical turn log is platform-owned. No `vr_turns` table.
- **Artifact blobs as rows.** Decompilation listings, ASAN reports, GDB transcripts, exploit scripts — stored on the workstation filesystem under `project.workspace_root`, with paths recorded in the relevant row's `*_path` columns. The DB is metadata; large content stays on disk. The platform `report_repository` pattern is the model.
- **Per-binary IDA database snapshot.** Path stored in `VRTargetRecord.analysis_db_path`. The IDB itself is not in the DB.
- **Tool catalog / strategy registry.** Lives in code (`tool_keys.py`, `capabilities.py`), not in the DB. Same pattern as forensics.
- **Advisory↔exploit join table.** A chain advisory references many exploits, but we model that through `VREvidenceEdgeRecord` (advisory node → exploit nodes via `enables_step`) rather than introducing a `vr_advisory_exploits` join table. The graph is already the join.

---

## 4. Indexing Strategy

The hot-path queries below drive index choices. Two principles:

1. **Every state column is indexed.** Lifecycle queries ("show all `running` campaigns") run constantly from the scheduler.
2. **Every FK is indexed** as a column index, plus composite indexes where the workflow always filters by both (e.g., `(target_id, state)` on hypotheses for "unresolved on target X" without a separate scan).

Composite indexes worth calling out:

- `ix_vr_evidence_edges_src(src_node_id, kind)` and the symmetric `_dst` — graph traversal in either direction is one index scan, no full-table.
- `ix_vr_obligations_anchor(anchor_node_id)` — full-column index. A partial filter on `state='open'` would shrink the index by an order of magnitude; deferred until a measurement under load shows the full index isn't enough. Adding it later is a one-line migration.
- `ix_vr_crashes_signature(crash_signature)` is per-target via the project_id correlation; if signature collisions across projects ever become a problem (they won't — the signature includes the binary hash) we'll add a composite.

---

## 5. Query Patterns

The five queries the runtime runs most often. Each is shown in a SQLAlchemy-style sketch — close to what `StorageService` actually wraps. Team-scoping is omitted for clarity; the platform's row-level filter applies automatically.

### 5.1 All unresolved hypotheses for target X

```python
def unresolved_hypotheses(session, target_id: str) -> list[VRHypothesisRecord]:
    stmt = (
        select(VRHypothesisRecord)
        .where(VRHypothesisRecord.target_id == target_id)
        .where(VRHypothesisRecord.state.in_(("proposed", "investigating", "variant_searching")))
        .order_by(VRHypothesisRecord.confidence.desc(), VRHypothesisRecord.updated_at.desc())
    )
    return list(session.exec(stmt))
```

Index used: `ix_vr_hypotheses_target_id` + `ix_vr_hypotheses_state`. Exposed as `GET /vr/projects/{pid}/targets/{tid}/hypotheses?state=open`.

### 5.2 Crashes from campaign Y sorted by exploitability

```python
def campaign_crashes_by_exploitability(session, campaign_id: str) -> list[VRCrashRecord]:
    state_priority = case(
        (VRCrashRecord.state == "exploitable", 0),
        (VRCrashRecord.state == "triaged", 1),
        (VRCrashRecord.state == "minimized", 2),
        (VRCrashRecord.state == "discovered", 3),
        (VRCrashRecord.state == "not_exploitable", 4),
        else_=5,
    )
    stmt = (
        select(VRCrashRecord)
        .where(VRCrashRecord.campaign_id == campaign_id)
        .order_by(state_priority, VRCrashRecord.exploit_tier.asc().nullslast(), VRCrashRecord.created_at.asc())
    )
    return list(session.exec(stmt))
```

Index used: `ix_vr_crashes_campaign_id`. Sort is done on the result set; cardinality is bounded (a campaign produces tens to low thousands of unique crashes after dedup, not millions). If campaigns ever exceed this scale, the answer is to materialize an `exploitability_rank` column rather than to add a covering index.

### 5.3 All findings affecting library Z across all consumer binaries

This is the cross-binary variant query — the *reason* the evidence graph spans the project. Two phases: (a) find all `confirmed_vulnerability` nodes in library Z's target, (b) walk `reached_via` edges to consumers.

```python
def findings_affecting_library(session, project_id: str, library_target_id: str) -> list[dict]:
    library_findings = session.exec(
        select(VREvidenceNodeRecord)
        .where(VREvidenceNodeRecord.project_id == project_id)
        .where(VREvidenceNodeRecord.target_id == library_target_id)
        .where(VREvidenceNodeRecord.kind == "confirmed_vulnerability")
    ).all()

    out: list[dict] = []
    for finding in library_findings:
        consumer_edges = session.exec(
            select(VREvidenceEdgeRecord)
            .where(VREvidenceEdgeRecord.src_node_id == finding.id)
            .where(VREvidenceEdgeRecord.kind == "reached_via")
        ).all()
        out.append({
            "library_finding": finding,
            "consumers": [
                session.get(VREvidenceNodeRecord, edge.dst_node_id)
                for edge in consumer_edges
            ],
        })
    return out
```

Two index scans (project_id+target_id+kind, src_node_id+kind) and N point lookups. For a typical library with 5–20 findings and 3–10 consumers per finding, this is ~100 row reads — single-digit ms on PostgreSQL.

### 5.4 Full evidence chain from hypothesis to advisory

The "show me how we got here" report. Walks the graph forward from a hypothesis node, collecting every node that supports the eventual advisory.

```python
def evidence_chain(session, hypothesis_id: str) -> list[VREvidenceNodeRecord]:
    # The hypothesis's evidence graph node
    root = session.exec(
        select(VREvidenceNodeRecord)
        .where(VREvidenceNodeRecord.entity_table == "vr_hypotheses")
        .where(VREvidenceNodeRecord.entity_id == hypothesis_id)
    ).one()

    visited: set[str] = {root.id}
    frontier: list[str] = [root.id]
    chain: list[VREvidenceNodeRecord] = [root]

    while frontier:
        next_frontier: list[str] = []
        edges = session.exec(
            select(VREvidenceEdgeRecord)
            .where(VREvidenceEdgeRecord.src_node_id.in_(frontier))
            .where(VREvidenceEdgeRecord.kind.in_(("supports", "reproduces", "exploits", "enables_step")))
        ).all()
        for edge in edges:
            if edge.dst_node_id in visited:
                continue
            visited.add(edge.dst_node_id)
            next_frontier.append(edge.dst_node_id)
        if next_frontier:
            nodes = session.exec(
                select(VREvidenceNodeRecord)
                .where(VREvidenceNodeRecord.id.in_(next_frontier))
            ).all()
            chain.extend(nodes)
        frontier = next_frontier

    return chain
```

This is BFS over a small graph (a real project has thousands of nodes, but a single chain touches dozens). The query is bounded; we don't paginate. Output feeds the per-finding advisory's "evidence trail" appendix and the adjudicator's "did we satisfy every obligation along this path" check.

### 5.5 All obligations unsatisfied for current research state

Two flavors: (a) per-finding ("can this advisory progress?"), (b) project-wide ("what's blocking us right now?").

```python
def open_obligations_for_finding(session, finding_node_id: str) -> list[VRObligationRecord]:
    chain = evidence_chain_node_ids(session, finding_node_id)  # see 5.4
    return list(
        session.exec(
            select(VRObligationRecord)
            .where(VRObligationRecord.anchor_node_id.in_(chain))
            .where(VRObligationRecord.state == "open")
        )
    )


def open_obligations_for_project(session, project_id: str) -> list[VRObligationRecord]:
    return list(
        session.exec(
            select(VRObligationRecord)
            .where(VRObligationRecord.project_id == project_id)
            .where(VRObligationRecord.state == "open")
            .order_by(VRObligationRecord.created_at.asc())
        )
    )
```

Per-finding query is the pre-flight check the adjudicator runs before any state advance into `confirmed`/`reliable`/`advisory_ready`. Project-wide query feeds the operator dashboard ("here is what's on fire today"). Index used: `ix_vr_obligations_anchor` and `ix_vr_obligations_state`.

### 5.6 Other queries worth listing (without full SQL)

- **"All campaigns whose process died but state is still `running`"** — watchdog query, runs on a 30s timer; uses `ix_vr_campaigns_heartbeat` with `last_heartbeat_at < now() - threshold`.
- **"All exploits whose `target_build_hash` no longer matches a current target"** — re-build invalidation; uses `target_id` index then comparison.
- **"All disclosures with `public_deadline_at < now() + 7d` and state ≠ `public`"** — disclosure dashboard; uses `ix_vr_disclosures_deadline`.
- **"All confirmed RCE-class findings in this project, with consumer reachability"** — the example from `04_MULTI_TARGET.md` §6; combines 5.3 with a severity filter.
- **"All chains rooted in network and reaching kernel"** — graph filter on `payload_json.initial_capability` and `final_capability`. With `payload_json` as Text, this is a slow scan; if it becomes hot, materialize `initial_capability` and `final_capability` as columns on `VREvidenceNodeRecord` for `kind = 'chain'`.

---

## 6. Alembic Migrations

The full v0.1 schema arrives in **four migrations**, in this order:

| # | File | Adds |
|---|---|---|
| 040 | `040_vr_core_tables.py` | `vr_projects`, `vr_targets`, `vr_operator_steering` |
| 041 | `041_vr_research_tables.py` | `vr_hypotheses`, `vr_fuzzing_campaigns`, `vr_crashes` |
| 042 | `042_vr_exploit_tables.py` | `vr_exploits`, `vr_advisories`, `vr_disclosures`, `vr_nday_tasks` |
| 043 | `043_vr_evidence_graph.py` | `vr_evidence_nodes`, `vr_evidence_edges`, `vr_obligations` |

Why split into four:

- **No migration creates more than 4 tables.** Each is reviewable. A single 12-table migration is easy to write and impossible to review.
- **Logical groupings.** A reader can name what each migration delivers from its filename.
- **Independent rollback unit.** If we discover the obligation table needs reshape, we revert 043 alone, fix it, and re-apply — without touching the rest.
- **Matches the existing forensics pattern.** Forensics did not ship in one migration either; it grew across 028→039.

Conventions all four follow (matching `028_forensics_tables.py`):

- Filename: `NNN_vr_<group>.py`. Three-digit zero-padded number, snake_case suffix, no Plan/Phase prefix.
- Module docstring lists every table created and links to the upstream design decision (e.g., "see docs/vr/07_DATA_MODEL.md §3.1").
- `revision: str` and `down_revision: str | None` are explicit string literals.
- `branch_labels = None`, `depends_on = None`.
- `upgrade()` issues `op.create_table` and `op.create_index` in the order tables→indexes→constraints.
- `downgrade()` is implemented and reverses every step in opposite order. We don't ship one-way migrations (the platform has occasionally needed downgrades during pre-release iteration).
- All check constraints carry `name=` so they are reversible without name guessing.
- `team_id` columns are nullable at the DB level (TEAM-06). Application layer enforces non-null where required.

What comes *later* than v0.1, deliberately not in these migrations:

- Partial indexes for Postgres (`WHERE state='open'` on obligations, `WHERE state='running'` on campaigns) — added when we have a Postgres deployment under load and a measurement showing the full index isn't enough. Migration 044+.
- A materialized `latest_finding` table analogous to `LatestFindingRecord` for cross-target queries — punted until usage data shows the per-finding queries are too slow.
- An external object-storage offload column (`raw_input_storage_uri`) on `vr_crashes` for >100MB crashing inputs — added when on-disk space on the workstation becomes the bottleneck. Until then, paths are absolute on the workstation filesystem.

The migration set passes an offline test: against the project's PostgreSQL test database, run `alembic upgrade head`, then `alembic downgrade base`, then `alembic upgrade head` again. No errors, no schema drift between the up/down/up cycle. This is the same gate every other module's migrations pass.

---

## Open Questions

1. **Per-target `state` aggregation.** A target may have a campaign `running` *and* an exploit `working` *and* an unresolved hypothesis under investigation. The single `state` column collapses this. Is the right move (a) keep the single dominant state and let UI compute detail, (b) drop the column entirely and let UI roll up children, or (c) introduce a small `vr_target_status_view` that materializes per-aspect state? Option (a) is simplest; option (c) gets us a single-row read for dashboards but adds write fan-out.

2. **Rejection immutability.** The CHECK constraint preventing `rejected -> proposed` is a strong rule. But operators may genuinely want to override it after offline review ("this was a wrong rejection on bad evidence; please reopen"). Do we (a) enforce strictly at DB and require a new hypothesis row with `parent_hypothesis_id`, (b) allow operator-only overrides via a logged endpoint, or (c) drop the CHECK and rely on workflow-layer enforcement? The Metis principle prefers (a); operational reality may demand (b).

3. **Crash dedup signature.** `crash_signature` as max_length=128 assumes top-N stack frames + signal collapse to a stable hash. ASAN reports differ slightly between runs (allocation site addresses change with ASLR). What canonicalization runs before hashing? Does that canonicalization belong in a column, in code, or in the harness? Wrong answer here means duplicate "unique" crashes inflate counts.

4. **Evidence node entity back-pointer.** `entity_table` + `entity_id` is a polymorphic FK without DB enforcement. We rely on application code never producing dangling references. Is that good enough, or do we want a strict per-kind FK (extra columns, more nullable, constraint enforced)? Forensics ate the same complexity and went with the polymorphic approach; we're inheriting the tradeoff.

5. **Obligation kind enumeration.** The `OBLIGATION_KINDS` tuple is closed at the DB level via CHECK. Adding a new obligation kind requires a migration. That's a feature (no typos shipping to prod) and a cost (every adjudicator extension is gated on schema work). Acceptable for v0.1; revisit if we add obligation kinds at a >once-per-month cadence.

6. **Disclosure-state automation.** `patch_pending -> patched` could reasonably auto-advance when a configured "patched-version sensor" detects an upstream release. Should the schema reserve a `auto_advance_config_json` column on `VRDisclosureRecord` now, or keep disclosure strictly operator-driven and only revisit if automation pressure builds? Adding the column later is cheap; building features that assume it exists is the bigger cost.

7. **N-day↔Target binding.** A single CVE may map to multiple builds (ubuntu-22.04 build, alpine build, Windows build) — different binaries, same upstream defect. Do we (a) one `VRNdayTask` per (CVE, build) pair, (b) one task with N target_ids in a join table, or (c) one task with one `target_id` and force per-build tasks even when redundant? Currently §3.3 commits to (c) implicitly. (b) is more honest about the data; (a) is the simplest.

8. **Evidence graph size.** §6 of `04_MULTI_TARGET.md` claims SQLModel relations are sufficient at <100K nodes per project. A long engagement on a complex product (firmware-grade) could produce hundreds of thousands of observation nodes if every decompilation snippet becomes a node. Where's the break point? Do we cap node creation per turn, or accept that the largest projects need a different storage backend, or both?

9. **Cross-team visibility on shared advisories.** A vulnerability in a popular library affects many customers, possibly across teams within one operator org. The current model is strictly team-scoped — `team_id` on every row. If we ever need cross-team advisory pooling (one CVE, many customer engagements), we need either a project-wide vs team-wide flag on advisories or a separate "library advisory" object that engagements can attach to. Not v0.1, but the data model has to leave the door open.

10. **Campaign config drift.** `vr_fuzzing_campaigns.config_json` is an opaque blob. Two campaigns with subtly different fuzzer configs (different mutators, different dictionaries) look identical in the dashboard and produce un-comparable results. Do we extract the high-leverage config fields (mutators_enabled, dictionary_path, sanitizer_set) as their own columns for queryability, or accept that the config blob is the source of truth and add UI rendering for it? The cost of extraction is migration overhead; the cost of not doing it is invisible apples-to-oranges comparisons in posture reports.

11. **Updated_at on append-only tables.** `VROperatorSteeringRecord` is append-only via `supersedes`, yet still has `updated_at` from the convention. Drop the column for append-only tables, or keep the convention uniform and let `updated_at == created_at` on these rows? Uniformity is cheap; columns on the wire that always equal another column are a small dishonesty signal that the honesty audit may or may not flag.

12. **Soft delete vs hard delete.** Nothing in this schema supports soft delete. Archive is a state, not a tombstone. If a project is deleted, its rows go away — no `deleted_at` column. Forensics took the same stance. But operators occasionally want to restore an accidentally-deleted project. Is the answer (a) backups (not in module scope), (b) a deferred-delete queue at the API layer (not a schema change), or (c) actual soft-delete columns on `VRProject` only? (a) and (b) keep the schema clean; (c) embeds policy in the data model. We've left it to (a/b).
