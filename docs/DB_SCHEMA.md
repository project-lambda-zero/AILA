# Database Schema Reference

All SQLModel tables used by AILA, organized by ownership (platform vs module).

PostgreSQL 16 with the `pgvector` extension is the only supported backend. Tables
use SQLModel (SQLAlchemy Core) DDL; `sa_column=Column(Text)` carries large-text
columns; `pgvector` carries 384-dim embedding columns. asyncpg is the runtime
driver; Alembic swaps to psycopg automatically via `src/aila/alembic/env.py`.

Two creation paths coexist:
- Platform + module tables that predate the Alembic baseline (`001_baseline_stamp`)
  are created on first boot by `make db-init`, which runs `SQLModel.metadata.create_all()`
  then stamps `alembic_version` at the current head (`067_workflow_state_cursor_archived_state`).
- Every schema change since then ships as an Alembic revision under
  `src/aila/alembic/versions/`. See [`DATABASE_MIGRATIONS.md`](DATABASE_MIGRATIONS.md).

No production code path calls `metadata.create_all()` outside the `make db-init`
bootstrap and test fixtures.

Lifecycle note: rows that may exist (e.g. `WorkflowRunRecord` rows created upfront
by `_ensure_run_record` and later updated by the workflow engine) MUST be
persisted with `session.merge()`. `session.add()` always INSERTs and crashes on
conflict; `merge()` does INSERT-or-UPDATE keyed on the primary key.

---

## Platform Tables

### ManagedSystemRecord

SSH-reachable system registered with the platform.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | int | PK, auto | Row identity |
| name | str | unique, indexed | System display name |
| host | str | indexed | SSH hostname or IP |
| username | str | | SSH username |
| port | int | default=22 | SSH port |
| distro | str | default="unknown" | Linux distribution |
| description | str | default="" | Operator notes |
| private_key_path | str/null | | SSH key file path |
| password_secret_id | str/null | | SecretRecord.id for SSH password |
| known_hosts_path | str/null | | SSH known_hosts file |
| host_key_fingerprint | str/null | | Expected host key fingerprint |
| created_at | datetime | default=utc_now | Creation timestamp |
| updated_at | datetime | default=utc_now | Last modification |

### SecretRecord

AES-256-GCM encrypted secret.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | str(UUID) | PK | Secret identity |
| scope | str | indexed, UQ(scope,secret_key) | Namespace scope |
| secret_key | str | indexed, UQ(scope,secret_key) | Key within scope |
| backend | str | default="master-key" | Encryption backend |
| key_version | str | default="v1" | Encryption key version |
| algorithm | str | default="aes-256-gcm" | Encryption algorithm |
| nonce | str/null | | AES-GCM nonce |
| hint | str/null | | First 2 chars + "**" |
| ciphertext | Text | | Base64-encoded ciphertext |
| created_at | datetime | default=utc_now | Creation timestamp |
| updated_at | datetime | default=utc_now | Last modification |

**Unique constraint:** `uq_secretrecord_scope_secret_key` on (scope, secret_key).

### ProviderConfigRecord

Mutable provider configuration value (e.g., OpenAI model ID).

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | int | PK, auto | Row identity |
| config_key | str | indexed, UQ | Dotted config key |
| value | Text | | Configuration value |
| created_at | datetime | default=utc_now | Creation timestamp |
| updated_at | datetime | default=utc_now | Last modification |

**Unique constraint:** `uq_providerconfigrecord_config_key` on (config_key).

### WorkflowRunRecord

Top-level record for a single workflow execution.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | str(UUID) | PK | Run identity |
| query_text | str | | Original user query |
| action_id | Text | column="intent" | Resolved action/intent |
| module_id | Text | default="" | Handling module ID |
| status | str | default="running" | running/completed/failed |
| route_json | Text | default="{}" | Routing decision JSON |
| short_memory_json | Text | default="{}" | Session memory snapshot |
| summary_json | Text | default="{}" | Run summary JSON |
| report_path | str/null | | Report file path |
| created_at | datetime | default=utc_now | Run start time |
| completed_at | datetime/null | | Run end time |

**Index:** `ix_wfr_status_completed` on (status, completed_at).

### PermanentMemoryRecord

Persistent key-value memory entry scoped to a namespace.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | int | PK, auto | Row identity |
| namespace | str | indexed, UQ(namespace,memory_key) | Owner namespace |
| memory_key | str | indexed, UQ(namespace,memory_key) | Key within namespace |
| payload_json | Text | default="{}" | JSON payload |
| created_at | datetime | default=utc_now | Creation timestamp |
| updated_at | datetime | default=utc_now | Last modification |

**Unique constraint:** `uq_permanentmemoryrecord_namespace_memory_key` on (namespace, memory_key).

### ReportArtifactRecord

File-path reference for a single report artifact.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | int | PK, auto | Row identity |
| run_id | str | indexed | Owning WorkflowRunRecord.id |
| scope | str | indexed | "fleet" or "target" |
| system_id | int/null | indexed | Target system ID |
| system_name | str/null | indexed | Target system name |
| host | str/null | indexed | Target hostname |
| artifact_type | str | indexed | "csv", "summary_json", "rows_json" |
| path | str | default="" | Absolute file path |
| content | Text | default="" | Legacy path storage |
| created_at | datetime | default=utc_now | Creation timestamp |

**Index:** `ix_rar_run_scope_type` on (run_id, scope, artifact_type).

### ArtifactRecord

Generic artifact record for module-produced content.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | int | PK, auto | Row identity |
| run_id | str/null | indexed | Owning run ID |
| module_id | str | indexed | Source module |
| scope | str | indexed, default="module" | "module" or target-scoped |
| artifact_type | str | indexed | Content category |
| label | str | indexed, default="" | Human-readable label |
| target_name | str/null | indexed | Target system name |
| target_host | str/null | indexed | Target hostname |
| content_type | str | default="text/plain" | MIME type |
| body | Text | default="" | Artifact content |
| metadata_json | Text | default="{}" | Structured metadata |
| created_at | datetime | default=utc_now | Creation timestamp |
| updated_at | datetime | default=utc_now | Last modification |

### AuditEventRecord

Immutable audit trail entry.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | int | PK, auto | Row identity |
| run_id | str | indexed | Associated run/task ID |
| stage | str | indexed | Workflow stage or action category |
| action | str | | Action performed |
| status | str | default="completed" | Action outcome |
| target | str | default="" | Target entity ID |
| user_id | Text | indexed, default="system" | Acting user key_id |
| details_json | Text | default="{}" | Structured context |
| created_at | datetime | default=utc_now | Event timestamp |

**Immutable:** No UPDATE operations are performed on this table.

### ConfigEntryRecord

Typed configuration entry managed by ConfigRegistry.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | int | PK, auto | Row identity |
| namespace | str | indexed, UQ(namespace,key) | Config namespace |
| key | str | indexed, UQ(namespace,key) | Config key |
| value | Text | | Stored value |
| value_type | str | default="str" | Type hint (str/int/float/bool) |
| updated_at | datetime | default=utc_now | Last modification |

**Resolution order:** env var > DB row > schema default. See `docs/CONFIG_REGISTRY.md`.
**Unique constraint:** `uq_configentryrecord_namespace_key` on (namespace, key).

### KnowledgeEntryRecord

Vector-indexed knowledge entry for agent retrieval.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | int | PK, auto | Row identity |
| namespace | str | indexed | Agent class name |
| content | Text | | Knowledge text |
| embedding | LargeBinary | | 384-dim float32 BLOB |
| entry_metadata | Text | default="{}" | JSON metadata |
| dedup_key | Text/null | indexed, UQ(namespace,dedup_key) | Deduplication key |
| created_at | datetime | default=utc_now | Creation timestamp |

**Unique constraint:** `uq_knowledgeentryrecord_namespace_dedup_key` on (namespace, dedup_key).

### SeedVersionRecord

Tracks which modules have run seed_data() and at what version.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| module_id | str | PK | Module identifier |
| seed_version | str | | Version string |
| seeded_at | datetime | default=utc_now | Last seed timestamp |

### TaskRecord

Platform-owned task lifecycle record (task queue).

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | str(UUID) | PK | Task identity |
| track | Text | indexed | Task track (e.g., "vulnerability", "platform") |
| fn_path | Text | | Importable function path |
| fn_module | Text | indexed | Module identifier |
| status | Text | indexed, default="queued" | Task lifecycle status |
| user_id | Text | indexed | Owning ApiKeyRecord.id |
| group_id | Text | indexed | Owning role for RBAC scoping |
| kwargs_json | Text | default="{}" | Serialized task arguments |
| input_hash | Text/null | indexed, partial UNIQUE | SHA-256 dedup key for concurrent-submit safety. Partial unique index `ix_task_records_input_hash_unique` enforces uniqueness within active statuses (queued, running, waiting). Added by migration 065. |
| version | int | default=1 | Optimistic-lock version for safe concurrent updates. Added by migration 011. |
| result_path | Text/null | | **Legacy** -- retired file-path slot; no task in `src/aila/` populates it. Results live in module-specific tables. |
| error | Text/null | | Error message on failure |
| depends_on_json | Text/null | | JSON list of dependency task IDs |
| started_at | datetime/null | | Worker pickup time |
| heartbeat_at | datetime/null | | Last heartbeat from worker |
| completed_at | datetime/null | | Completion time |
| created_at | datetime | default=utc_now | Submission time |
| updated_at | datetime | default=utc_now | Last state change |

**Status transitions:** queued -> waiting -> running -> paused/done/failed/cancelled/dead_letter. See `TaskStatus` enum (8 values). CHECK constraint `ck_taskrecord_status_canonical` (migration 066) enforces valid values at the DB level.

### ApiKeyRecord

API key record for AILA REST API authentication.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | str(UUID) | PK | Key identity (used as key_id JWT claim) |
| hashed_key | Text | | bcrypt hash of raw key |
| key_prefix | Text | indexed | First 12 chars of raw key |
| role | Text | indexed, default="reader" | admin/operator/reader |
| label | Text | default="" | Human-readable label |
| created_by | Text | default="system" | Creator key_id, "cli", or "bootstrap" |
| created_at | datetime | default=utc_now | Creation timestamp |
| revoked_at | datetime/null | | Revocation timestamp (non-null = revoked) |

**Table name:** `apikeyrecord` (explicit `__tablename__`).

### SessionRecord

Conversation session owned by a single API key user.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | str(UUID) | PK | Session identity |
| user_id | Text | not null | Owning ApiKeyRecord.id |
| title | Text | default="Untitled" | Session title |
| created_at | datetime | default=utc_now | Creation timestamp |

**Table name:** `session_records`. **Index:** `ix_sr_user_id` on (user_id).

### SessionMessageRecord

Single turn in a conversation session.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | str(UUID) | PK | Message identity |
| session_id | Text | not null | Owning SessionRecord.id |
| role | Text | not null | "user" or "assistant" |
| content | Text | default="" | Message text |
| run_id | Text/null | | Background scan run_id if triggered |
| created_at | datetime | default=utc_now | Message timestamp |

**Table name:** `session_message_records`. **Index:** `ix_smr_session_id` on (session_id).

### ExplainCacheRecord

Cached LLM explanation for a vulnerability report.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | int | PK, auto | Row identity |
| run_id | Text | not null | WorkflowRunRecord.id |
| content | Text | default="" | LLM explanation text |
| cached_at | datetime | default=utc_now | Cache timestamp |

**Table name:** `explain_cache_records`. **Index:** `ix_ecr_run_id` on (run_id), unique.

---

## Vulnerability Module Tables

### PrioritizedFindingRecord

Scored finding record linked to a specific scan run.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | int | PK, auto | Row identity |
| run_id | str | indexed | Owning WorkflowRunRecord.id |
| system_id | int | indexed | Target ManagedSystemRecord.id |
| host | str | indexed | Target hostname |
| package_name | str | indexed | Affected package |
| installed_version | str | | Installed version |
| cve_id | str | indexed | CVE identifier |
| criticality | str | | Severity level |
| score | float | | Risk score |
| rationale | str | default="" | Scoring rationale |
| fixed_version | str/null | | Fix version |
| nvd_url | str | | NVD reference URL |
| created_at | datetime | default=utc_now | Creation timestamp |

### LatestFindingRecord

Materialized latest-state table for vulnerability findings (primary query surface).

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | int | PK, auto | Row identity |
| host | Text | not null, UQ(host,package_name,cve_id) | Target hostname |
| package_name | Text | not null, UQ(host,package_name,cve_id) | Affected package |
| cve_id | Text | not null, UQ(host,package_name,cve_id) | CVE identifier |
| system_id | int | indexed | Target system ID |
| system_name | Text | default="" | System display name |
| distribution | Text | default="" | Linux distribution |
| criticality | Text | not null | Severity level |
| score | float | | Risk score |
| rationale | Text | default="" | Scoring rationale |
| fixed_version | Text/null | | Fix version |
| nvd_url | Text | not null | NVD reference URL |
| compliance_tags_json | Text | default="[]" | JSON array of compliance tags |
| details_json | Text | default="{}" | Full context blob (reporting only) |
| last_scanned_at | datetime | default=utc_now | Last scan timestamp |
| created_at | datetime | default=utc_now | First seen timestamp |
| status | Text | default="open" | Remediation status |

**Table name:** `latest_finding_records`.
**Unique constraint:** `uq_latestfinding_target` on (host, package_name, cve_id).
**Indexes:** `ix_lfr_host` on (host), `ix_lfr_last_scanned` on (last_scanned_at).
**Upsert pattern:** `sa_insert().on_conflict_do_update()` keyed on (host, package_name, cve_id).

### AssetTagRecord

Operator-assigned asset tag on a registered system.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | int | PK, auto | Row identity |
| system_id | int | indexed | Target ManagedSystemRecord.id |
| tag_key | str | indexed, UQ(system_id,tag_key) | Tag key |
| tag_value | str | default="" | Tag value |
| created_at | datetime | default=utc_now | Creation timestamp |
| updated_at | datetime | default=utc_now | Last modification |

**Unique constraint:** `uq_assettag_system_key` on (system_id, tag_key).

### RemediationRecord

Operator-managed remediation state tracking.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | int | PK, auto | Row identity |
| host | str | indexed, UQ(host,package_name,cve_id) | Target hostname |
| package_name | str | indexed, UQ(host,package_name,cve_id) | Affected package |
| cve_id | str | indexed, UQ(host,package_name,cve_id) | CVE identifier |
| status | str | default="open", CHECK | open/remediated/accepted/deferred |
| notes | str | default="" | Operator notes |
| updated_at | datetime | default=utc_now | Last modification |

**CHECK constraint:** `ck_remediationrecord_status` -- status IN ('open', 'remediated', 'accepted', 'deferred').
**Unique constraint:** `uq_remediationrecord_finding` on (host, package_name, cve_id).

### DistributionProfileRecord

Stored Linux distribution profile for advisory source matching.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | int | PK, auto | Row identity |
| distro_key | str | indexed, unique | Primary lookup key |
| display_name | str | default="" | Human-readable name |
| os_release_ids_json | Text | default="[]" | JSON array of os-release IDs |
| inventory_command | Text | | Package list command |
| package_parser | str | CHECK | tab_separated/space_separated |
| advisory_strategy | str | CHECK | osv/arch-security/alpine-secdb |
| advisory_ecosystem | str/null | | OSV ecosystem string |
| advisory_batch_size | int/null | | Batch size for advisory queries |
| enabled | bool | default=True | Profile active flag |
| created_at | datetime | default=utc_now | Creation timestamp |
| updated_at | datetime | default=utc_now | Last modification |

**CHECK constraints:** `ck_distributionprofilerecord_package_parser`, `ck_distributionprofilerecord_advisory_strategy`.

### InventoryArtifactRecord

Persisted inventory collection record.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | int | PK, auto | Row identity |
| run_id | str | indexed | Owning run ID |
| system_id | int | indexed | Target system ID |
| host | str | indexed | Target hostname |
| distro | str | default="unknown" | Detected distribution |
| kernel | str | default="" | Kernel version |
| status | str | default="collected" | collected/failed |
| error_message | str/null | | Error on failure |
| payload_json | Text | default="{}" | Full InventoryArtifact JSON |
| collected_at | datetime | default=utc_now | Collection timestamp |

### ScoringPolicyRecord

Stored scoring policy configuration.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| policy_id | str | PK | Policy identifier (default: "default") |
| payload_json | Text | default="{}" | Serialized ScoringPolicyConfig |
| created_at | datetime | default=utc_now | Creation timestamp |
| updated_at | datetime | default=utc_now | Last modification |

### ScheduledScanRecord

Cron-based scan schedule configuration.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | int | PK, auto | Row identity |
| target_name | str | indexed | Target system name |
| cron_expression | str | | Cron schedule expression |
| enabled | bool | default=True | Schedule active flag |
| created_at | datetime | default=utc_now | Creation timestamp |
| updated_at | datetime | default=utc_now | Last modification |
| last_run_at | datetime/null | | Last execution time |
| last_run_result | str/null | | Last execution outcome |

### CacheRecord

Module-level key-value cache entry.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| namespace | str | PK (composite), indexed | Cache namespace (e.g., "cve_intel") |
| cache_key | str | PK (composite) | Cache key within namespace |
| payload_json | Text | default="{}" | Cached JSON data |
| last_synced_at | datetime | default=utc_now | Cache freshness timestamp |

**Index:** `ix_cacherecord_namespace` on (namespace).

---

## Additional Platform Tables

The original platform section above covers the core lifecycle tables. The
following platform-owned tables ship today and are persisted by `make db-init` +
the Alembic migration chain. Column lists are abbreviated to the load-bearing
fields; consult `src/aila/storage/db_models.py`, `src/aila/platform/tasks/models.py`,
`src/aila/platform/llm/cost_record.py`, and `src/aila/platform/llm/idempotency_cache.py`
for the full SQLModel definitions.

### Workflow engine

- **WorkflowStateCursor** (`workflow_state_cursor`) -- one row per active workflow run; tracks `current_state`, `version`, scheduled-tick metadata, crash sentinel (`__crashed__`). Migration 067 adds `archived_state` (nullable `VARCHAR(128)`) to preserve the prior `current_state` across pause / resume cycles. Non-NULL only when the cursor sits at `__paused__`. Source: `src/aila/storage/db_models.py:193-200`.
- **WorkflowStateTransition** (`workflow_state_transitions`) -- append-only audit/replay log of every state transition. Indexed `(run_id, sequence DESC)` for tail-reads.

### LLM pipeline + audit

- **AuditSealRecord** (`auditsealrecord`) -- cryptographic seals over LLM pipeline outputs. HMAC key from `platform.llm_seal_hmac_key`.
- **VerificationRecord** (`verification_records`) -- cross-model verification results (Phase 174 LLM-SEC-01).
- **ReasoningGraphSnapshotRecord** (`reasoning_graph_snapshots`) -- durable graph snapshot emitted by the platform reasoning engine; unique on `(module_id, run_id, sequence)`.
- **LLMCostRecord** (`llm_cost_records`) -- per-call token + USD cost record; indexes on `(run_id, model_id)` and `(team_id, created_at)`.
- **LLMIdempotencyCacheRecord** (`llm_idempotency_cache`) -- request-key keyed cache for retry-safe LLM calls (migration 061). PK is the SHA-256 of `(investigation, branch, turn, prompt_hash)`. Carries `response_json`, token counts, cost, 7-day TTL.

### Multi-team auth (Phase 177)

- **UserRecord** (`user_records`) -- username/password user. Hash via argon2id.
- **OIDCProviderRecord** (`oidc_provider_records`) -- OIDC provider configuration (Microsoft, generic OIDC).
- **RefreshTokenRecord** (`refresh_token_records`) -- refresh-token record for user sessions; key_id blacklist on revoke.
- **TeamRecord** (`team_records`) -- first-class team identity. UNIQUE on `name`. Soft-delete via `deleted_at`.
- **TeamMemberRecord** (`team_member_records`) -- explicit (team, user) edge with role. UNIQUE on `(team_id, user_id)`.

### Plan C -- endpoint support

- **NotificationRecord** (`notification_records`) -- per-user notifications.
- **WidgetLayoutRecord** (`widget_layout_records`) -- dashboard widget layout JSON per user (one row per user).
- **SavedFilterRecord** (`saved_filter_records`) -- user-saved filter configs for entity list views.
- **ScheduledReportRecord** (`scheduled_report_records`) -- cron-scheduled report jobs.
- **FindingWorkflowRecord** (`finding_workflow_records`) -- audit trail entry for finding workflow state transitions.
- **AssetTagVocabRecord** (`asset_tag_vocab_records`) -- admin-managed tag key vocabulary.

### Plan D -- network discovery

- **ConfidenceDriftRecord** (`confidence_drift_records`) -- per-`(target_name, task_type)` drift tracking.
- **SystemPortRecord** (`system_port_records`) -- open TCP/UDP listening ports per system (from `ss -tlnp`).
- **SystemServiceRecord** (`system_service_records`) -- running systemd services per system.
- **SystemConnectionRecord** (`system_connection_records`) -- active TCP connections between registered systems (topology edges).
- **SystemMetadataRecord** (`system_metadata_records`) -- per-system SSH-discovered metadata (Phase 176d). UNIQUE on `system_id`.

### Automation

- **AutomationScheduleRecord** (`automation_schedule_records`) -- cron-driven automation schedule.

---

## Vulnerability Module -- Additional Tables

- **FindingFeedbackRecord** (`finding_feedbacks`) -- operator feedback on a finding (false-positive / accepted / deferred etc.). CHECK constraint on `reason`.

---

## Forensics Module Tables

Owned by `aila.modules.forensics.db_models`. Every table is prefixed with
`forensics_` to keep ownership obvious in the shared database.

- **ForensicsProjectRecord** (`forensics_projects`, migration 028) -- top-level forensics project.
- **ForensicsProjectEvidenceRecord** (`forensics_project_evidence`, migration 028) -- evidence file metadata; `size_bytes` widened to BIGINT in migration 031.
- **ForensicsArtifactRecord** (`forensics_artifacts`, migration 028) -- artifacts produced during analysis; `source_investigation_id` column added in migration 036.
- **ForensicsLeadRecord** (`forensics_leads`, migration 028) -- investigative leads surfaced by analyzers.
- **ForensicsInvestigationRecord** (`forensics_investigations`, migration 028) -- one investigation per project run; `parent_investigation_id` added in migration 037, `task_id` linkage in migration 030.
- **ForensicsAgentStepRecord** (`forensics_agent_steps`, migration 028) -- per-step agent trace.
- **ForensicsWriteupRecord** (`forensics_writeups`, migration 028) -- generated investigation writeup.
- **ForensicsAnswerCandidateRecord** (`forensics_answer_candidates`, migration 028) -- candidate answers for question-driven investigations.
- **ForensicsAnalystDirectiveRecord** (`forensics_analyst_directives`, migrations 032/039) -- operator directives that steer agent behavior.
- **ForensicsSolidEvidenceRecord** (`forensics_solid_evidence`, migration 034) -- promoted, high-confidence evidence.
- **ForensicsFindingSuppressionRecord** (`forensics_finding_suppressions`, migration 035) -- operator-suppressed findings.

---

## Vulnerability Research (VR) Module Tables

Owned by `aila.modules.vr.db_models`. Created and evolved by migrations 040 + 042 + 044 + 045 + 046 + 047 + 048 + 050 + 052 + 053 + 055 + 060 + 061 + 062. See those migration files for the canonical DDL.

- **VRWorkspaceRecord** (`vr_workspaces`, migration 042) -- team-scoped workspace. UNIQUE on `(team_id, slug)`.
- **VRTargetRecord** (`vr_targets`, migration 042) -- persistent target identity inside a workspace. **Migration 060** added `analysis_stages_json` for per-stage durable analysis state across the `ingestion` / `capability_profile` / `function_ranking` pipeline.
- **VRTargetTagIndexRecord** (`vr_target_tag_index`, migration 042) -- denormalized tag-to-target index for fast multi-tag filter queries. UNIQUE on `(target_id, tag, tag_source)`.
- **VRProjectRecord** (`vr_projects`, migration 040; FK to target hardened in migration 043) -- per-target research project with budget/obligation snapshot.
- **VRFindingRecord** (`vr_findings`, migration 040; nullable `project_id` since migration 057; `poc_skip_reason` since migration 059) -- confirmed vulnerabilities with triage, PoC, disclosure state.
- **VRInvestigationRecord** (`vr_investigations`, migration 044; `is_favorite` since migration 058; CVE intel columns since migration 056) -- one operator-initiated reasoning session.
- **VRInvestigationBranchRecord** (`vr_investigation_branches`, migration 044; `strategy_family` added in migration 049) -- one persona-branched conversation within an investigation. Migration 064 backfills NULL `persona_voice` rows with `'unspecified'` and adds NOT NULL with `server_default='unspecified'`.
- **VRInvestigationMessageRecord** (`vr_investigation_messages`, migration 044) -- per-turn message stream for a branch. Migration 063 adds `auto_steering_key` (nullable `VARCHAR(128)`) with partial UNIQUE constraint `uq_vr_investigation_messages_auto_steering_key` on `(investigation_id, auto_steering_key)` WHERE `auto_steering_key IS NOT NULL`. Used by `auto_steering.maybe_post_auto_steering` for dedup.
- **VRInvestigationOutcomeRecord** (`vr_investigation_outcomes`, migration 044; `state` column added in **migration 062**) -- typed outcomes emitted by a branch. `state` is `draft | approved | rejected | dispatched`; the dispatcher refuses any outcome whose state is not `approved`.
- **VRInvestigationOutcomeReviewRecord** (`vr_outcome_reviews`, **migration 062**) -- sibling-review row per `(outcome_id, reviewer_branch_id)`. Vote enum is `approve | reject | request_edit | abstain`; the quorum evaluator flips the outcome to `approved` once enough approve votes land with zero rejects.
- **VRInvestigationTargetRecord** (`vr_investigation_targets`, migration 048) -- many-to-many between investigations and additional targets.
- **VRMcpCallLogRecord** (`vr_mcp_call_log`, migration 052) -- every MCP tool call surfaced through the VR bridges (audit-mcp / ida-headless-mcp).
- **VRPatternRecord** (`vr_patterns`, migration 045) -- durable pattern memory shared across investigations.
- **VRCVERecord** (`vr_cve_records`, migration 050) -- CVE record cache. UNIQUE on `cve_id`.
- **VRCVEFeedStateRecord** (`vr_cve_feed_state`, migration 050) -- per-source feed poll state.
- **VRDisclosureSubmissionRecord** (`vr_disclosure_submissions`, migration 046) -- vendor disclosure submission tracking.
- **VRFuzzCampaignRecord** (`vr_fuzz_campaigns`, migration 047; `system_id` FK added in migration 054) -- fuzzing campaign metadata.
- **VRFuzzCrashRecord** (`vr_fuzz_crashes`, migration 047) -- deduplicated crashes; UNIQUE on `(campaign_id, stack_hash)`.
- **VRFuzzCampaignProposalRecord** (`vr_fuzz_campaign_proposals`, migration 055) -- proposed campaigns awaiting operator approval.
- **VRFuzzTelemetryRecord** (`vr_fuzz_telemetry`, migration 053) -- fuzz campaign telemetry samples.

---

## Table Summary

Counts reflect the Alembic head `067_workflow_state_cursor_archived_state` (2026-06-21).

| Group | Owner | Tables |
|---|---|---|
| Core lifecycle (SSH, secrets, providers, workflow runs, memory, reports, artifacts, audit, config, knowledge, seeds, tasks, API keys, sessions, messages, explain cache) | Platform | 16 |
| Workflow engine (state cursor + transitions) | Platform | 2 |
| LLM pipeline + audit (seals, verification, reasoning snapshots, cost, idempotency cache) | Platform | 5 |
| Multi-team auth (users, OIDC, refresh tokens, teams, team members) | Platform | 5 |
| Plan C endpoint support (notifications, widget layout, saved filters, scheduled reports, finding workflow, asset tag vocab) | Platform | 6 |
| Plan D network discovery (confidence drift, ports, services, connections, metadata) | Platform | 5 |
| Automation schedules | Platform | 1 |
| Vulnerability module (findings, asset tags, remediation, distribution profile, inventory, scoring policy, scheduled scans, cache, finding feedback) | Vulnerability | 10 |
| Forensics module | Forensics | 11 |
| Vulnerability Research module | VR | 20 |

The `hello_world` module ships as a reference and does not own any DB tables.

---

*Generated from source models in `src/aila/storage/db_models.py`, `src/aila/platform/tasks/models.py`, `src/aila/platform/llm/cost_record.py`, `src/aila/platform/llm/idempotency_cache.py`, `src/aila/platform/automation/models.py`, and the per-module `db_models/` packages under `src/aila/modules/<module>/`.*
*Last updated: 2026-06-21 (Alembic head `067_workflow_state_cursor_archived_state`).*