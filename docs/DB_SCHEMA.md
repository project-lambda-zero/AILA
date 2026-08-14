# Database Schema Reference

All SQLModel tables used by AILA, grouped by ownership (platform vs module).
This file is regenerated from the live SQLModel metadata (every model imported
by `src/aila/alembic/env.py`), so it reflects the current model definitions
rather than a hand-maintained snapshot.

PostgreSQL 16 with the `pgvector` extension is the only supported backend.
Tables use SQLModel (SQLAlchemy Core) DDL. The knowledge embedding column is a
1024-dim `pgvector` produced by BGE-M3 (`BAAI/bge-m3`); the `all-MiniLM-L6-v2`
fallback (384-dim) is zero-padded to 1024 by `KnowledgeService.embed` when it is
selected via the `knowledge_embedding_model` config key. asyncpg is the runtime
driver; Alembic swaps to psycopg automatically via `src/aila/alembic/env.py`.

Two creation paths coexist:
- Platform + module tables that predate the Alembic baseline
  (`001_baseline_stamp`) are created on first boot by `make db-init`, which runs
  `SQLModel.metadata.create_all()` then stamps `alembic_version` at the current
  head (`123_vr_fuzz_source_investigation`).
- Every schema change since then ships as an Alembic revision under
  `src/aila/alembic/versions/`. See [`DATABASE_MIGRATIONS.md`](DATABASE_MIGRATIONS.md).

No production code path calls `metadata.create_all()` outside the `make db-init`
bootstrap and test fixtures.

Lifecycle note: rows that may already exist (for example `WorkflowRunRecord`
rows created upfront by `_ensure_run_record` and later updated by the workflow
engine) MUST be persisted with `session.merge()`. `session.add()` always INSERTs
and crashes on conflict; `merge()` does INSERT-or-UPDATE keyed on the PK.


---

## Platform Tables (57)


### `apikeyrecord`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | VARCHAR | PK, default=<function ApiKeyRecord.<lambda> at 0x000000003B2737E0> |
| `hashed_key` | TEXT |  |
| `key_prefix` | TEXT | indexed |
| `role` | TEXT | indexed, server_default=reader |
| `label` | TEXT | server_default= |
| `created_by` | TEXT | server_default=system |
| `user_id` | TEXT | indexed |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B273880> |
| `revoked_at` | DATETIME |  |

### `artifactrecord`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | INTEGER | PK |
| `run_id` | VARCHAR | indexed |
| `module_id` | VARCHAR | indexed, NOT NULL |
| `scope` | VARCHAR | indexed, NOT NULL, default=module |
| `artifact_type` | VARCHAR | indexed, NOT NULL |
| `label` | VARCHAR | indexed, NOT NULL, default= |
| `target_name` | VARCHAR | indexed |
| `target_host` | VARCHAR | indexed |
| `content_type` | VARCHAR | NOT NULL, default=text/plain |
| `body` | TEXT |  |
| `metadata_json` | TEXT |  |
| `created_at` | DATETIME | indexed, NOT NULL, default=<function utc_now at 0x000000003AAA32E0> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003AAA3380> |

### `asset_tag_vocab_records`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function AssetTagVocabRecord.<lambda> at 0x000000003B31BEC0> |
| `tag_key` | VARCHAR | unique, indexed, NOT NULL |
| `description` | VARCHAR | NOT NULL, default= |
| `is_system_default` | BOOLEAN | NOT NULL, default=False |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B344040> |

### `auditeventrecord`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | INTEGER | PK |
| `run_id` | VARCHAR | indexed, NOT NULL |
| `stage` | VARCHAR | indexed, NOT NULL |
| `action` | VARCHAR | NOT NULL |
| `status` | VARCHAR | NOT NULL, default=completed |
| `target` | VARCHAR | NOT NULL, default= |
| `user_id` | TEXT | indexed, server_default=system |
| `details_json` | TEXT |  |
| `created_at` | DATETIME | indexed, NOT NULL, default=<function utc_now at 0x000000003AAE1440> |

### `auditsealrecord`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | INTEGER | PK |
| `run_id` | VARCHAR | indexed, NOT NULL |
| `seal_hash` | VARCHAR | NOT NULL |
| `input_hash` | VARCHAR | NOT NULL |
| `output_hash` | VARCHAR | NOT NULL |
| `model_id` | VARCHAR | NOT NULL |
| `task_type` | VARCHAR | indexed, NOT NULL |
| `prompt_content_hash` | VARCHAR | indexed |
| `prompt_version` | VARCHAR | indexed |
| `timestamp` | DATETIME | NOT NULL |
| `classification` | VARCHAR |  |
| `confidence` | VARCHAR |  |
| `evidence_validation_pass` | BOOLEAN |  |
| `content_stored` | BOOLEAN | NOT NULL, default=False |
| `prompt_content` | TEXT |  |
| `response_content` | TEXT |  |
| `posture_mode` | TEXT |  |
| `key_id` | TEXT |  |
| `prompt_content_encrypted` | TEXT |  |
| `response_content_encrypted` | TEXT |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003AAE34C0> |

### `confidence_drift_records`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function ConfidenceDriftRecord.<lambda> at 0x000000003B345120> |
| `target_name` | VARCHAR | indexed, NOT NULL |
| `task_type` | VARCHAR | indexed, NOT NULL |
| `window_size` | INTEGER | NOT NULL |
| `confidence_scores_json` | TEXT |  |
| `mean_confidence` | FLOAT | NOT NULL |
| `std_deviation` | FLOAT | NOT NULL |
| `drift_status` | VARCHAR | NOT NULL |
| `alert_fired` | BOOLEAN | NOT NULL, default=False |
| `computed_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B3453A0> |

### `configentryrecord`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | INTEGER | PK |
| `namespace` | VARCHAR | indexed, NOT NULL |
| `key` | VARCHAR | indexed, NOT NULL |
| `value` | TEXT |  |
| `value_type` | VARCHAR | NOT NULL, default=str |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003AB5CF40> |

### `eval_benchmarks`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function EvalBenchmarkRecord.<lambda> at 0x000000003B4B19E0> |
| `key` | VARCHAR(256) | indexed, NOT NULL |
| `name` | VARCHAR(256) | NOT NULL |
| `cases_json` | TEXT | NOT NULL |
| `created_by` | VARCHAR(128) | NOT NULL, default= |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B4B1800> |

### `eval_calibration_proposals`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function CalibrationProposalRecord.<lambda> at 0x000000003B3DCC20> |
| `outcome_kind` | VARCHAR(64) | indexed, NOT NULL |
| `before_threshold` | FLOAT | NOT NULL |
| `after_threshold` | FLOAT | NOT NULL |
| `approve_count` | INTEGER | NOT NULL, default=0 |
| `reject_count` | INTEGER | NOT NULL, default=0 |
| `mean_confidence_reject` | FLOAT | NOT NULL, default=0.0 |
| `mean_confidence_approve` | FLOAT | NOT NULL, default=0.0 |
| `reasoning` | TEXT | NOT NULL, default= |
| `evidence_json` | TEXT | NOT NULL, default={} |
| `status` | VARCHAR(16) | NOT NULL, default=active |
| `superseded_by` | VARCHAR(64) |  |
| `reverted_from` | VARCHAR(64) |  |
| `actor` | VARCHAR(128) | NOT NULL, default= |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B3DCB80> |

### `eval_calibration_samples`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function CalibrationScoreSample.<lambda> at 0x000000003B48E480> |
| `task_type` | VARCHAR(64) | indexed, NOT NULL |
| `outcome_kind` | VARCHAR(64) | NOT NULL, default= |
| `model_id` | VARCHAR(128) | NOT NULL, default= |
| `raw_confidence` | FLOAT | NOT NULL, default=0.0 |
| `correct` | BOOLEAN | NOT NULL, default=False |
| `outcome_id` | VARCHAR(64) |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B48E660> |

### `eval_calibrator_versions`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function CalibratorVersionRecord.<lambda> at 0x000000003B48CC20> |
| `task_type` | VARCHAR(64) | indexed, NOT NULL |
| `method` | VARCHAR(32) | NOT NULL |
| `params_json` | TEXT | NOT NULL, default={} |
| `ece_before` | FLOAT | NOT NULL, default=0.0 |
| `ece_after` | FLOAT | NOT NULL, default=0.0 |
| `sample_count` | INTEGER | NOT NULL, default=0 |
| `status` | VARCHAR(16) | NOT NULL, default=candidate |
| `superseded_by` | VARCHAR(64) |  |
| `actor` | VARCHAR(128) | NOT NULL, default= |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B48CB80> |

### `eval_runs`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function EvalRunRecord.<lambda> at 0x000000003B4B2F20> |
| `key` | VARCHAR(256) | indexed, NOT NULL |
| `candidate_version` | VARCHAR(32) | NOT NULL |
| `baseline_version` | VARCHAR(32) |  |
| `benchmark_id` | VARCHAR(64) | FK -> eval_benchmarks.id, NOT NULL |
| `report_json` | TEXT | NOT NULL |
| `verdict` | VARCHAR(16) | NOT NULL |
| `actor` | VARCHAR(128) | NOT NULL, default= |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B4B3060> |

### `explain_cache_records`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | INTEGER | PK |
| `run_id` | TEXT | NOT NULL |
| `content` | TEXT | server_default= |
| `cached_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B2AB2E0> |

### `finding_workflow_records`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function FindingWorkflowRecord.<lambda> at 0x000000003B31A840> |
| `finding_id` | VARCHAR | indexed, NOT NULL |
| `module_id` | VARCHAR | indexed, NOT NULL |
| `current_state` | VARCHAR | indexed, NOT NULL, default=new |
| `previous_state` | VARCHAR |  |
| `transitioned_by` | VARCHAR | NOT NULL |
| `notes` | TEXT |  |
| `team_id` | VARCHAR(64) | indexed |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B31A700> |

### `investigation_ledger`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | INTEGER | PK |
| `investigation_id` | VARCHAR(64) | NOT NULL |
| `author_branch_id` | VARCHAR(64) | NOT NULL |
| `kind` | VARCHAR(32) | NOT NULL |
| `payload_json` | TEXT | NOT NULL |
| `objective_key` | VARCHAR(128) |  |
| `owner_branch_id` | VARCHAR(64) |  |
| `status` | VARCHAR(32) |  |
| `supersedes_id` | INTEGER |  |
| `idempotency_key` | VARCHAR(128) |  |
| `created_at` | DATETIME | NOT NULL |

### `knowledge_entry_edges`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | INTEGER | PK |
| `src_id` | INTEGER | FK -> knowledgeentryrecord.id, NOT NULL |
| `dst_id` | INTEGER | FK -> knowledgeentryrecord.id, NOT NULL |
| `relation` | VARCHAR(64) | NOT NULL |
| `weight` | FLOAT | NOT NULL, default=1.0 |
| `created_at` | DATETIME | NOT NULL |

### `knowledgeentryrecord`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | INTEGER | PK |
| `namespace` | VARCHAR | indexed, NOT NULL |
| `content` | TEXT |  |
| `embedding` | VECTOR(1024) |  |
| `search_vector` | TSVECTOR | server_default=Computed(<sqlalchemy.sql.elements.TextClause object at 0x000000003AA3B110>, persisted=True) |
| `entry_metadata` | TEXT |  |
| `dedup_key` | TEXT | indexed |
| `model_id` | VARCHAR | indexed |
| `content_hash` | VARCHAR | indexed |
| `source_type` | VARCHAR | indexed |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003AB5E840> |
| `updated_at` | DATETIME |  |

### `lifecycle_canary_assignments`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function LifecycleCanaryAssignment.<lambda> at 0x000000003B530EA0> |
| `key` | VARCHAR(256) | indexed, NOT NULL |
| `kind` | VARCHAR(16) | NOT NULL |
| `version` | VARCHAR(32) | NOT NULL |
| `cohort_percent` | INTEGER |  |
| `state` | VARCHAR(16) | NOT NULL, default=active |
| `actor` | VARCHAR(128) | NOT NULL, default= |
| `reason` | TEXT | NOT NULL, default= |
| `last_signal_json` | TEXT |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B530F40> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B530E00> |

### `lifecycle_transitions`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function LifecycleTransitionRecord.<lambda> at 0x000000003B532E80> |
| `key` | VARCHAR(256) | indexed, NOT NULL |
| `version` | VARCHAR(32) | NOT NULL |
| `from_stage` | VARCHAR(32) | NOT NULL |
| `to_stage` | VARCHAR(32) | NOT NULL |
| `actor` | VARCHAR(128) | NOT NULL, default= |
| `reason` | TEXT | NOT NULL, default= |
| `metrics_snapshot_json` | TEXT |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B532DE0> |

### `llm_cost_records`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | VARCHAR | PK, default=<function LLMCostRecord.<lambda> at 0x000000003CF545E0> |
| `run_id` | VARCHAR | indexed, NOT NULL, default=_no_run |
| `investigation_id` | VARCHAR | indexed |
| `branch_id` | VARCHAR | indexed |
| `turn_number` | INTEGER |  |
| `prompt_content_hash` | VARCHAR | indexed |
| `prompt_version` | VARCHAR | indexed |
| `model_id` | VARCHAR | indexed, NOT NULL |
| `task_type` | VARCHAR | indexed, NOT NULL, default= |
| `prompt_tokens` | INTEGER | NOT NULL, default=0 |
| `completion_tokens` | INTEGER | NOT NULL, default=0 |
| `cost_usd` | FLOAT | NOT NULL, default=0.0 |
| `human_cost_hours` | FLOAT |  |
| `human_cost_usd` | FLOAT |  |
| `prompt_preview` | VARCHAR |  |
| `response_preview` | VARCHAR |  |
| `duration_ms` | INTEGER |  |
| `status` | VARCHAR | NOT NULL, default=ok |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003CF54680> |

### `managedsystemrecord`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | INTEGER | PK |
| `name` | VARCHAR | unique, indexed, NOT NULL |
| `host` | VARCHAR | indexed, NOT NULL |
| `username` | VARCHAR | NOT NULL |
| `port` | INTEGER | NOT NULL, default=22 |
| `distro` | VARCHAR | NOT NULL, default=unknown |
| `description` | VARCHAR | NOT NULL, default= |
| `private_key_path` | VARCHAR |  |
| `private_key_secret_id` | VARCHAR |  |
| `password_secret_id` | VARCHAR |  |
| `known_hosts_path` | VARCHAR |  |
| `host_key_fingerprint` | VARCHAR |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003A9EE520> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003A9EE5C0> |

### `mcp_approval_change_log`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function McpApprovalChangeRecord.<lambda> at 0x000000003CFB2B60> |
| `instance_id` | TEXT | indexed, NOT NULL |
| `from_state` | TEXT | NOT NULL |
| `to_state` | TEXT | NOT NULL |
| `approver` | TEXT | NOT NULL |
| `schema_hash` | TEXT |  |
| `reason` | TEXT |  |
| `created_at` | DATETIME | NOT NULL, server_default=now() |

### `mcp_server_instances`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function McpServerInstance.<lambda> at 0x000000003CFB0A40> |
| `name` | TEXT | indexed, NOT NULL |
| `transport` | TEXT | NOT NULL, server_default=http |
| `endpoint` | TEXT | NOT NULL |
| `capability_tags` | TEXT | NOT NULL, server_default=[] |
| `enabled` | BOOLEAN | indexed, NOT NULL, default=True |
| `module_scope` | TEXT | indexed |
| `team_id` | TEXT | indexed |
| `approval_state` | TEXT | NOT NULL, server_default=pending |
| `approved_hash` | TEXT |  |
| `schema_hash` | TEXT |  |
| `server_card_json` | TEXT |  |
| `created_at` | DATETIME | NOT NULL, server_default=now() |
| `updated_at` | DATETIME |  |

### `notification_records`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function NotificationRecord.<lambda> at 0x000000003B2D85E0> |
| `user_id` | VARCHAR | indexed, NOT NULL |
| `title` | VARCHAR | NOT NULL |
| `body` | TEXT |  |
| `category` | VARCHAR | indexed, NOT NULL, default=info |
| `source_module` | VARCHAR |  |
| `source_entity_id` | VARCHAR |  |
| `is_read` | BOOLEAN | indexed, NOT NULL, default=False |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B2D8720> |
| `read_at` | DATETIME |  |

### `oidc_provider_records`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function OIDCProviderRecord.<lambda> at 0x000000003B270540> |
| `provider_name` | VARCHAR | indexed, NOT NULL, default=microsoft |
| `provider_type` | TEXT | NOT NULL, server_default=microsoft |
| `display_name` | TEXT |  |
| `tenant_id` | TEXT |  |
| `issuer_url` | TEXT |  |
| `client_id` | TEXT |  |
| `client_secret_encrypted` | TEXT |  |
| `scopes_json` | TEXT | NOT NULL, server_default=["openid","email","profile"] |
| `is_enabled` | BOOLEAN | NOT NULL, default=True |
| `default_team_id` | TEXT |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B270900> |

### `permanentmemoryrecord`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | INTEGER | PK |
| `namespace` | VARCHAR | indexed, NOT NULL |
| `memory_key` | VARCHAR | indexed, NOT NULL |
| `payload_json` | TEXT |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003AA6BE20> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003AA6BD80> |

### `platform_journal`

| Column | Type | Constraints |
|--------|------|-------------|
| `chain_id` | VARCHAR(64) | PK |
| `seq` | BIGINT | PK |
| `journal_id` | VARCHAR(36) | NOT NULL |
| `team_id` | VARCHAR(36) | indexed |
| `prev_hash` | VARCHAR(64) |  |
| `row_hash` | VARCHAR(64) | NOT NULL |
| `payload_hash` | VARCHAR(64) | NOT NULL |
| `kind` | VARCHAR(48) | NOT NULL |
| `source` | VARCHAR(128) | NOT NULL |
| `actor_kind` | VARCHAR(16) | NOT NULL |
| `actor_id` | VARCHAR(128) | NOT NULL |
| `action` | VARCHAR(128) | NOT NULL |
| `status` | VARCHAR(16) | NOT NULL |
| `run_id` | VARCHAR(36) |  |
| `investigation_id` | VARCHAR(36) |  |
| `branch_id` | VARCHAR(36) |  |
| `turn_number` | INTEGER |  |
| `correlation_id` | VARCHAR(64) | NOT NULL |
| `parent_journal_id` | VARCHAR(36) |  |
| `payload_json` | JSONB | NOT NULL |
| `contains_secret` | BOOLEAN | NOT NULL, server_default=false |
| `schema_version` | SMALLINT | NOT NULL, server_default=1 |
| `occurred_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003D0122A0> |
| `written_at` | DATETIME | NOT NULL, server_default=now() |

### `platform_journal_deadletter`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function PlatformJournalDeadletterRecord.<lambda> at 0x000000003D040360> |
| `chain_id` | VARCHAR(64) | NOT NULL |
| `team_id` | VARCHAR(36) |  |
| `entry_json` | JSONB | NOT NULL |
| `failure_kind` | VARCHAR(32) | NOT NULL |
| `failure_detail` | TEXT | NOT NULL |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003D040220> |
| `replayed_at` | DATETIME |  |
| `replay_seq` | BIGINT |  |

### `prompt_alias_changes`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function PromptAliasChangeRecord.<lambda> at 0x000000003B546DE0> |
| `key` | VARCHAR(256) | NOT NULL |
| `alias` | VARCHAR(32) | NOT NULL |
| `from_version` | VARCHAR(32) |  |
| `to_version` | VARCHAR(32) | NOT NULL |
| `actor` | VARCHAR(128) | NOT NULL, default= |
| `reason` | TEXT | NOT NULL, default= |
| `changed_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B546E80> |

### `prompt_aliases`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function PromptAliasRecord.<lambda> at 0x000000003B545940> |
| `key` | VARCHAR(256) | indexed, NOT NULL |
| `alias` | VARCHAR(32) | NOT NULL |
| `version` | VARCHAR(32) | NOT NULL |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B5458A0> |

### `prompt_versions`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function PromptVersionRecord.<lambda> at 0x000000003B5440E0> |
| `key` | VARCHAR(256) | NOT NULL |
| `version` | VARCHAR(32) | NOT NULL |
| `content_hash` | VARCHAR(64) | NOT NULL |
| `body` | TEXT | NOT NULL |
| `author` | VARCHAR(128) | NOT NULL, default= |
| `notes` | TEXT | NOT NULL, default= |
| `roster_json` | TEXT | NOT NULL, default={} |
| `routing_json` | TEXT | NOT NULL, default={} |
| `exemplars_json` | TEXT | NOT NULL, default=[] |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B544220> |

### `providerconfigrecord`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | INTEGER | PK |
| `config_key` | VARCHAR | indexed, NOT NULL |
| `value` | TEXT |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003AA1E200> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003AA1E3E0> |

### `reasoning_graph_snapshots`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function ReasoningGraphSnapshotRecord.<lambda> at 0x000000003AB19800> |
| `run_id` | VARCHAR | indexed |
| `module_id` | VARCHAR | indexed, NOT NULL |
| `subject_kind` | VARCHAR | indexed, NOT NULL |
| `subject_id` | VARCHAR | indexed, NOT NULL |
| `step_number` | INTEGER | indexed, NOT NULL |
| `strategy_family` | VARCHAR | NOT NULL, default=generic |
| `graph_json` | JSONB | NOT NULL |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003AB19760> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003AB19940> |

### `refresh_token_records`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | VARCHAR | PK, default=<function RefreshTokenRecord.<lambda> at 0x000000003B272020> |
| `user_id` | VARCHAR | indexed, NOT NULL |
| `token_hash` | TEXT | unique |
| `expires_at` | DATETIME | NOT NULL |
| `revoked_at` | DATETIME |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B271F80> |
| `ip_address` | VARCHAR |  |
| `user_agent` | VARCHAR |  |

### `reportartifactrecord`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | INTEGER | PK |
| `run_id` | VARCHAR | indexed, NOT NULL |
| `scope` | VARCHAR | indexed, NOT NULL |
| `system_id` | INTEGER | indexed |
| `system_name` | VARCHAR | indexed |
| `host` | VARCHAR | indexed |
| `artifact_type` | VARCHAR | indexed, NOT NULL |
| `path` | VARCHAR | NOT NULL, default= |
| `content` | TEXT |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003AAA1440> |

### `retrieval_eval_benchmarks`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function RetrievalBenchmarkRecord.<lambda> at 0x000000003B4D5EE0> |
| `key` | VARCHAR(256) | indexed, NOT NULL |
| `name` | VARCHAR(256) | NOT NULL |
| `k` | INTEGER | NOT NULL, default=10 |
| `cases_json` | TEXT | NOT NULL |
| `created_by` | VARCHAR(128) | NOT NULL, default= |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B4D5E40> |

### `retrieval_eval_runs`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function RetrievalRunRecord.<lambda> at 0x000000003B4D74C0> |
| `key` | VARCHAR(256) | indexed, NOT NULL |
| `benchmark_id` | VARCHAR(64) | FK -> retrieval_eval_benchmarks.id, NOT NULL |
| `candidate_label` | VARCHAR(64) | NOT NULL |
| `baseline_label` | VARCHAR(64) |  |
| `report_json` | TEXT | NOT NULL |
| `verdict` | VARCHAR(16) | NOT NULL |
| `actor` | VARCHAR(128) | NOT NULL, default= |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B4D7600> |

### `saved_filter_records`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function SavedFilterRecord.<lambda> at 0x000000003B2DB060> |
| `user_id` | VARCHAR | indexed, NOT NULL |
| `name` | VARCHAR | NOT NULL |
| `entity_type` | VARCHAR | indexed, NOT NULL |
| `filter_json` | TEXT |  |
| `is_pinned` | BOOLEAN | NOT NULL, default=False |
| `shared_with_team` | BOOLEAN | NOT NULL, default=False |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B2DB2E0> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B2DB380> |

### `scheduled_report_records`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | VARCHAR | PK, default=<function ScheduledReportRecord.<lambda> at 0x000000003B318AE0> |
| `name` | VARCHAR | NOT NULL |
| `report_type` | VARCHAR | indexed, NOT NULL |
| `cron_expression` | VARCHAR | NOT NULL |
| `recipient_emails_json` | TEXT |  |
| `config_json` | TEXT |  |
| `is_active` | BOOLEAN | indexed, NOT NULL, default=True |
| `last_run_at` | DATETIME |  |
| `created_by` | VARCHAR | indexed, NOT NULL |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B318C20> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B318CC0> |

### `secretrecord`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function SecretRecord.<lambda> at 0x000000003AA1CCC0> |
| `scope` | VARCHAR | indexed, NOT NULL |
| `secret_key` | VARCHAR | indexed, NOT NULL |
| `backend` | VARCHAR | NOT NULL, default=master-key |
| `key_version` | VARCHAR | NOT NULL, default=v1 |
| `algorithm` | VARCHAR | NOT NULL, default=aes-256-gcm |
| `nonce` | VARCHAR |  |
| `hint` | VARCHAR |  |
| `ciphertext` | TEXT |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003AA1CD60> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003AA1CE00> |

### `seedversionrecord`

| Column | Type | Constraints |
|--------|------|-------------|
| `module_id` | VARCHAR | PK |
| `seed_version` | VARCHAR | NOT NULL |
| `seeded_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003AB8C180> |

### `session_message_records`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function SessionMessageRecord.<lambda> at 0x000000003B2AA200> |
| `session_id` | TEXT | NOT NULL |
| `role` | TEXT | NOT NULL |
| `content` | TEXT | server_default= |
| `run_id` | TEXT |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B2AA2A0> |

### `session_records`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function SessionRecord.<lambda> at 0x000000003B2A8FE0> |
| `user_id` | TEXT | NOT NULL |
| `title` | TEXT | server_default=Untitled |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B2A9120> |

### `specialist_agent`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function SpecialistAgentRecord.<lambda> at 0x000000003D916C00> |
| `module_id` | VARCHAR(64) | indexed, NOT NULL |
| `name` | VARCHAR(64) | NOT NULL |
| `capability` | VARCHAR(64) | indexed, NOT NULL |
| `strategy_family` | VARCHAR(128) |  |
| `description` | TEXT | default= |
| `enabled` | BOOLEAN | NOT NULL, default=True |
| `team_id` | VARCHAR(64) | indexed |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003D916B60> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003D916CA0> |

### `system_connection_records`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | INTEGER | PK |
| `source_system_id` | INTEGER | indexed, NOT NULL |
| `dest_system_id` | INTEGER | indexed, NOT NULL |
| `dest_ip` | VARCHAR | NOT NULL, default= |
| `dest_port` | INTEGER | NOT NULL |
| `protocol` | VARCHAR | NOT NULL, default=tcp |
| `state` | VARCHAR | NOT NULL, default=ESTABLISHED |
| `last_collected` | DATETIME | NOT NULL |
| `is_stale` | BOOLEAN | NOT NULL, default=False |

### `system_metadata_records`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | INTEGER | PK |
| `system_id` | INTEGER | indexed, NOT NULL |
| `gateway_ip` | VARCHAR |  |
| `gateway_interface` | VARCHAR |  |
| `external_ip` | VARCHAR |  |
| `os_name` | VARCHAR |  |
| `os_pretty_name` | VARCHAR |  |
| `kernel` | VARCHAR |  |
| `cpu_cores` | INTEGER |  |
| `memory_mb` | INTEGER |  |
| `disk_gb` | INTEGER |  |
| `uptime_seconds` | INTEGER |  |
| `last_collected` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B3932E0> |
| `is_stale` | BOOLEAN | NOT NULL, default=False |

### `system_port_records`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | INTEGER | PK |
| `system_id` | INTEGER | indexed, NOT NULL |
| `port` | INTEGER | NOT NULL |
| `protocol` | VARCHAR | NOT NULL, default=tcp |
| `local_address` | VARCHAR | NOT NULL, default= |
| `process_name` | VARCHAR |  |
| `pid` | INTEGER |  |
| `last_collected` | DATETIME | NOT NULL |
| `is_stale` | BOOLEAN | NOT NULL, default=False |

### `system_service_records`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | INTEGER | PK |
| `system_id` | INTEGER | indexed, NOT NULL |
| `service_name` | VARCHAR | indexed, NOT NULL |
| `service_type` | VARCHAR | NOT NULL, default=systemd |
| `state` | VARCHAR | NOT NULL, default=running |
| `sub_state` | VARCHAR | NOT NULL, default= |
| `last_collected` | DATETIME | NOT NULL |
| `is_stale` | BOOLEAN | NOT NULL, default=False |

### `taskrecord`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | VARCHAR | PK, default=<function TaskRecord.<lambda> at 0x000000003AB8E160> |
| `track` | TEXT | indexed |
| `fn_path` | TEXT |  |
| `fn_module` | TEXT | indexed |
| `status` | TEXT | indexed, server_default=queued |
| `user_id` | TEXT | indexed |
| `group_id` | TEXT | indexed |
| `kwargs_json` | TEXT | server_default={} |
| `result_path` | TEXT |  |
| `error` | TEXT |  |
| `depends_on_json` | TEXT |  |
| `input_hash` | TEXT | indexed |
| `version` | INTEGER | NOT NULL, server_default=1 |
| `started_at` | DATETIME |  |
| `heartbeat_at` | DATETIME |  |
| `completed_at` | DATETIME |  |
| `created_at` | DATETIME | NOT NULL |
| `updated_at` | DATETIME | NOT NULL |

### `team_member_records`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function TeamMemberRecord.<lambda> at 0x000000003CFE7F60> |
| `team_id` | TEXT | indexed, NOT NULL |
| `user_id` | TEXT | indexed, NOT NULL |
| `role` | TEXT | NOT NULL, server_default=operator |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003CFE7EC0> |

### `team_records`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function TeamRecord.<lambda> at 0x000000003CFE6CA0> |
| `name` | TEXT | indexed, NOT NULL |
| `description` | TEXT | NOT NULL, server_default= |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003CFE6C00> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003CFE6D40> |
| `deleted_at` | DATETIME |  |

### `user_records`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | VARCHAR | PK, default=<function UserRecord.<lambda> at 0x000000003B2523E0> |
| `username` | VARCHAR(64) | unique, indexed, NOT NULL |
| `email` | TEXT | indexed |
| `hashed_password` | TEXT |  |
| `role` | TEXT | indexed, server_default=operator |
| `group_id` | TEXT | indexed |
| `is_active` | BOOLEAN | indexed, NOT NULL, default=True |
| `oidc_sub` | TEXT | indexed |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B252340> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B252520> |
| `last_login_at` | DATETIME |  |

### `verification_records`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function VerificationRecord.<lambda> at 0x000000003AB1B380> |
| `run_id` | VARCHAR | indexed, NOT NULL |
| `task_type` | VARCHAR | indexed, NOT NULL |
| `first_model_id` | VARCHAR | NOT NULL |
| `first_verdict` | TEXT |  |
| `first_confidence` | FLOAT | NOT NULL |
| `first_evidence` | TEXT |  |
| `second_model_id` | VARCHAR | NOT NULL |
| `second_verdict` | TEXT |  |
| `second_confidence` | FLOAT | NOT NULL |
| `second_evidence` | TEXT |  |
| `agreement` | BOOLEAN | NOT NULL |
| `disposition` | VARCHAR | NOT NULL |
| `final_verdict` | TEXT |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003AB1B6A0> |

### `widget_layout_records`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function WidgetLayoutRecord.<lambda> at 0x000000003B2D9C60> |
| `user_id` | VARCHAR | unique, indexed, NOT NULL |
| `layout_json` | TEXT |  |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003B2D9DA0> |

### `workflow_state_cursor`

| Column | Type | Constraints |
|--------|------|-------------|
| `run_id` | VARCHAR | PK, FK -> workflowrunrecord.id |
| `current_state` | VARCHAR(128) | NOT NULL |
| `state_input` | JSONB | NOT NULL |
| `retries_in_state` | INTEGER | NOT NULL, default=0 |
| `definition_id` | VARCHAR(128) | NOT NULL |
| `updated_at` | DATETIME | NOT NULL, server_default=now() |
| `version` | INTEGER | NOT NULL, default=0 |
| `archived_state` | VARCHAR(128) |  |
| `investigation_id` | VARCHAR(64) | indexed |
| `branch_id` | VARCHAR(64) | indexed |

### `workflow_state_transitions`

| Column | Type | Constraints |
|--------|------|-------------|
| `run_id` | VARCHAR | PK, FK -> workflowrunrecord.id |
| `seq` | INTEGER | PK |
| `from_state` | VARCHAR(128) | NOT NULL |
| `to_state` | VARCHAR(128) | NOT NULL |
| `event` | VARCHAR(64) | NOT NULL |
| `input_hash` | VARCHAR(64) |  |
| `output_hash` | VARCHAR(64) |  |
| `duration_ms` | INTEGER |  |
| `error_class` | VARCHAR(128) |  |
| `error_message` | VARCHAR |  |
| `happened_at` | DATETIME | NOT NULL, server_default=now() |

### `workflowrunrecord`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | VARCHAR | PK, default=<function WorkflowRunRecord.<lambda> at 0x000000003AA1F7E0> |
| `query_text` | VARCHAR | NOT NULL |
| `intent` | TEXT |  |
| `module_id` | TEXT | indexed, server_default= |
| `status` | VARCHAR | NOT NULL, default=running |
| `route_json` | JSONB | NOT NULL, server_default={} |
| `short_memory_json` | JSONB | NOT NULL, server_default={} |
| `summary_json` | JSONB | NOT NULL, server_default={} |
| `report_path` | VARCHAR |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003AA1F920> |
| `completed_at` | DATETIME |  |
| `plan_json` | JSONB |  |

---

## VR Tables (20)


### `vr_cve_feed_state`

| Column | Type | Constraints |
|--------|------|-------------|
| `source` | VARCHAR(16) | PK |
| `last_polled_at` | DATETIME |  |
| `last_cursor` | VARCHAR(256) |  |
| `last_error` | TEXT |  |
| `consecutive_errors` | INTEGER | NOT NULL, default=0 |
| `records_ingested` | INTEGER | NOT NULL, default=0 |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DF8CF40> |

### `vr_cve_records`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function VRCVERecord.<lambda> at 0x000000003DF4F060> |
| `cve_id` | VARCHAR(32) | indexed, NOT NULL |
| `source` | VARCHAR(16) | indexed, NOT NULL |
| `title` | VARCHAR(512) | NOT NULL, default= |
| `description` | TEXT |  |
| `published_at` | DATETIME | indexed |
| `last_modified_at` | DATETIME |  |
| `cvss_score` | FLOAT | indexed |
| `cwe_ids_json` | TEXT |  |
| `references_json` | TEXT |  |
| `affected_components_json` | TEXT |  |
| `raw_payload_json` | TEXT |  |
| `invalidations_triggered` | INTEGER | NOT NULL, default=0 |
| `ingested_at` | DATETIME | indexed, NOT NULL, default=<function utc_now at 0x000000003DF4F100> |

### `vr_disclosure_submissions`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | VARCHAR | PK, default=<function VRDisclosureSubmissionRecord.<lambda> at 0x000000003DF8EE80> |
| `finding_id` | VARCHAR | FK -> vr_findings.id, indexed, NOT NULL |
| `workspace_id` | VARCHAR | FK -> vr_workspaces.id, indexed, NOT NULL |
| `track_id` | VARCHAR(64) | indexed, NOT NULL |
| `kind` | VARCHAR(32) | indexed, NOT NULL |
| `status` | VARCHAR(24) | indexed, NOT NULL, default=drafted |
| `poc_tier` | VARCHAR(24) | NOT NULL, default=no_poc |
| `severity_rating` | VARCHAR(64) |  |
| `embargo_days_used` | INTEGER |  |
| `embargo_until` | DATETIME | indexed |
| `vendor_reference` | VARCHAR(128) | indexed |
| `bounty_awarded_usd` | FLOAT |  |
| `rendered_submission_body` | TEXT |  |
| `rendered_submission_format` | VARCHAR(16) | NOT NULL, default=markdown |
| `last_rendered_at` | DATETIME |  |
| `rendered_submission_metadata_json` | TEXT |  |
| `notes` | TEXT |  |
| `validation_errors_json` | TEXT |  |
| `sections_json` | TEXT |  |
| `regenerated_from_finding_at` | DATETIME |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DF8ED40> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DF8EDE0> |

### `vr_findings`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function VRFindingRecord.<lambda> at 0x000000003DFC25C0> |
| `project_id` | TEXT | indexed |
| `target_id` | VARCHAR | FK -> vr_targets.id, indexed |
| `team_id` | VARCHAR | indexed |
| `crash_type` | VARCHAR(64) | indexed |
| `crash_signature` | VARCHAR(128) |  |
| `root_cause` | TEXT |  |
| `vulnerable_function` | VARCHAR(255) |  |
| `poc_code` | TEXT |  |
| `poc_language` | VARCHAR(32) |  |
| `poc_reliability` | VARCHAR(16) |  |
| `poc_skip_reason` | TEXT |  |
| `asan_report` | TEXT |  |
| `cvss_vector` | VARCHAR(128) |  |
| `cvss_score` | FLOAT |  |
| `cwe_id` | VARCHAR(16) |  |
| `advisory_json` | TEXT |  |
| `disclosure_status` | VARCHAR(32) | indexed, NOT NULL, default=undisclosed |
| `vendor_contact` | TEXT |  |
| `reported_at` | DATETIME |  |
| `embargo_until` | DATETIME |  |
| `assigned_cve_id` | VARCHAR(32) |  |
| `patch_version` | VARCHAR(64) |  |
| `evidence_refs_json` | TEXT |  |
| `obligations_json` | TEXT |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DFC2660> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DFC2480> |

### `vr_fuzz_campaign_proposals`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | VARCHAR | PK, default=<function VRFuzzCampaignProposalRecord.<lambda> at 0x000000003E06D300> |
| `investigation_id` | VARCHAR | FK -> vr_investigations.id, indexed, NOT NULL |
| `outcome_id` | VARCHAR | FK -> vr_investigation_outcomes.id, NOT NULL |
| `target_id` | VARCHAR | FK -> vr_targets.id, indexed, NOT NULL |
| `workspace_id` | VARCHAR | FK -> vr_workspaces.id, indexed, NOT NULL |
| `profile` | VARCHAR(128) | NOT NULL |
| `rationale` | TEXT |  |
| `confidence` | VARCHAR(24) | NOT NULL, default=medium |
| `target_descriptor_json` | TEXT |  |
| `suggested_engine_id` | VARCHAR(32) |  |
| `suggested_engine_config_json` | TEXT |  |
| `suggested_strategy_id` | VARCHAR(32) |  |
| `suggested_duration_hours` | INTEGER |  |
| `harness_source` | TEXT |  |
| `harness_language` | VARCHAR(16) |  |
| `harness_build_command` | TEXT |  |
| `harness_target_path` | VARCHAR(1024) |  |
| `seed_corpus_json` | TEXT |  |
| `dictionary_content` | TEXT |  |
| `status` | VARCHAR(24) | indexed, NOT NULL, default=pending |
| `accepted_campaign_id` | VARCHAR | FK -> vr_fuzz_campaigns.id |
| `decided_at` | DATETIME |  |
| `decided_by` | VARCHAR(64) |  |
| `decision_reason` | TEXT |  |
| `prepare_log` | TEXT |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E06D260> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E06D120> |

### `vr_fuzz_campaigns`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | VARCHAR | PK, default=<function VRFuzzCampaignRecord.<lambda> at 0x000000003E009D00> |
| `target_id` | VARCHAR | FK -> vr_targets.id, indexed, NOT NULL |
| `workspace_id` | VARCHAR | FK -> vr_workspaces.id, indexed, NOT NULL |
| `name` | VARCHAR(255) | indexed, NOT NULL |
| `engine_id` | VARCHAR(64) | indexed, NOT NULL |
| `strategy_id` | VARCHAR(64) | indexed, NOT NULL |
| `engine_config_json` | TEXT |  |
| `strategy_config_json` | TEXT |  |
| `status` | VARCHAR(24) | indexed, NOT NULL, default=created |
| `duration_hours` | INTEGER |  |
| `analysis_system_id` | INTEGER | indexed |
| `remote_pid` | INTEGER |  |
| `remote_corpus_dir` | VARCHAR(1024) |  |
| `remote_crashes_dir` | VARCHAR(1024) |  |
| `launched_at` | DATETIME |  |
| `launch_log` | TEXT |  |
| `execs_per_sec` | FLOAT |  |
| `total_execs` | INTEGER | NOT NULL, default=0 |
| `corpus_size` | INTEGER | NOT NULL, default=0 |
| `coverage_pct` | FLOAT |  |
| `crashes_found` | INTEGER | NOT NULL, default=0 |
| `started_at` | DATETIME |  |
| `stopped_at` | DATETIME |  |
| `last_progress_at` | DATETIME |  |
| `notes` | TEXT |  |
| `source_investigation_id` | VARCHAR(64) | indexed |
| `source_outcome_id` | VARCHAR(64) |  |
| `last_coverage_emitted_pct` | FLOAT |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E009C60> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E009DA0> |

### `vr_fuzz_crashes`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | VARCHAR | PK, default=<function VRFuzzCrashRecord.<lambda> at 0x000000003E0353A0> |
| `campaign_id` | VARCHAR | FK -> vr_fuzz_campaigns.id, indexed, NOT NULL |
| `stack_hash` | VARCHAR(128) | indexed, NOT NULL |
| `crash_type` | VARCHAR(64) | indexed |
| `crash_signature` | VARCHAR(512) |  |
| `severity` | VARCHAR(16) | indexed, NOT NULL, default=unknown |
| `triage_verdict` | VARCHAR(32) | indexed, NOT NULL, default=untriaged |
| `triage_reason` | VARCHAR(512) |  |
| `duplicate_of_crash_id` | VARCHAR(64) | indexed |
| `promoted_to_finding_id` | VARCHAR(64) | indexed |
| `reproducer_path` | VARCHAR(1024) |  |
| `reproducer_size_bytes` | INTEGER |  |
| `stack_trace` | TEXT |  |
| `extra_json` | TEXT |  |
| `reproducer_head_hex` | TEXT |  |
| `reproducer_head_truncated_size` | INTEGER |  |
| `llm_summary` | TEXT |  |
| `triage_chain_json` | TEXT |  |
| `discovered_at` | DATETIME | indexed, NOT NULL, default=<function utc_now at 0x000000003E035440> |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E035260> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E0354E0> |

### `vr_fuzz_telemetry`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function VRFuzzTelemetryRecord.<lambda> at 0x000000003E19DE40> |
| `campaign_id` | VARCHAR | FK -> vr_fuzz_campaigns.id, indexed, NOT NULL |
| `measured_at` | DATETIME | indexed, NOT NULL, default=<function utc_now at 0x000000003E19DEE0> |
| `execs_per_sec` | FLOAT |  |
| `total_execs` | BIGINT |  |
| `corpus_size` | INTEGER |  |
| `coverage_pct` | FLOAT |  |
| `crashes_found` | INTEGER |  |

### `vr_investigation_branches`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function BranchRecordBase.<lambda> at 0x000000003DF4C860> |
| `investigation_id` | VARCHAR | FK -> vr_investigations.id, indexed, NOT NULL |
| `parent_branch_id` | VARCHAR | FK -> vr_investigation_branches.id, indexed |
| `merged_into_branch_id` | VARCHAR | FK -> vr_investigation_branches.id, indexed |
| `status` | VARCHAR(32) | indexed, NOT NULL, default=active |
| `persona_voice` | VARCHAR(32) | NOT NULL, default=unspecified |
| `strategy_family` | VARCHAR(128) | indexed |
| `fork_reason` | TEXT | default= |
| `fork_at_turn` | INTEGER |  |
| `case_state_json` | TEXT | default={} |
| `branch_cost_usd` | FLOAT | NOT NULL, default=0.0 |
| `turn_count` | INTEGER | NOT NULL, default=0 |
| `closed_reason` | TEXT | default= |
| `promoted` | BOOLEAN | NOT NULL, default=False |
| `closed_at` | DATETIME |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DF4C900> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DF4C9A0> |

### `vr_investigation_messages`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function MessageRecordBase.<lambda> at 0x000000003E0E9580> |
| `investigation_id` | VARCHAR | FK -> vr_investigations.id, indexed, NOT NULL |
| `branch_id` | VARCHAR | FK -> vr_investigation_branches.id, indexed, NOT NULL |
| `sender_kind` | VARCHAR(16) | NOT NULL |
| `sender_id` | VARCHAR(64) |  |
| `payload_kind` | VARCHAR(32) | indexed, NOT NULL |
| `payload_json` | TEXT | default={} |
| `operator_intent` | VARCHAR(32) |  |
| `at_turn` | INTEGER |  |
| `evidence_refs_json` | TEXT | default=[] |
| `auto_steering_key` | VARCHAR(128) |  |
| `created_at` | DATETIME | indexed, NOT NULL, default=<function utc_now at 0x000000003E0E9620> |

### `vr_investigation_outcomes`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function OutcomeRecordBase.<lambda> at 0x000000003E0EADE0> |
| `investigation_id` | VARCHAR | FK -> vr_investigations.id, indexed, NOT NULL |
| `branch_id` | VARCHAR | FK -> vr_investigation_branches.id, indexed, NOT NULL |
| `outcome_kind` | VARCHAR(32) | indexed, NOT NULL |
| `payload_json` | TEXT | default={} |
| `confidence` | VARCHAR(16) | NOT NULL |
| `evidence_refs_json` | TEXT | default=[] |
| `accepted_by_operator` | BOOLEAN | NOT NULL, default=False |
| `accepted_at` | DATETIME |  |
| `state` | VARCHAR(16) | indexed, NOT NULL, default=draft |
| `dispatch_status` | VARCHAR(16) | indexed, NOT NULL, default=pending |
| `dispatch_target` | VARCHAR(128) |  |
| `claimed_at` | DATETIME |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E0EAFC0> |

### `vr_investigation_targets`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | VARCHAR | PK, default=<function InvestigationTargetRecordBase.<lambda> at 0x000000003E0B2200> |
| `investigation_id` | VARCHAR | FK -> vr_investigations.id, indexed, NOT NULL |
| `target_id` | VARCHAR | FK -> vr_targets.id, indexed, NOT NULL |
| `role` | VARCHAR(32) | indexed, NOT NULL, default=comparison |
| `rationale` | TEXT | default= |
| `attached_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E0B23E0> |

### `vr_investigations`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | VARCHAR | PK, default=<function InvestigationRecordBase.<lambda> at 0x000000003E06F920> |
| `project_id` | VARCHAR(64) | indexed |
| `parent_investigation_id` | VARCHAR | FK -> vr_investigations.id, indexed |
| `target_id` | VARCHAR | FK -> vr_targets.id, indexed, NOT NULL |
| `secondary_target_refs_json` | TEXT | default=[] |
| `kind` | VARCHAR(32) | indexed, NOT NULL, default=discovery |
| `title` | VARCHAR(255) | NOT NULL |
| `initial_question` | TEXT | default= |
| `status` | VARCHAR(32) | indexed, NOT NULL, default=created |
| `pause_reason` | VARCHAR(32) |  |
| `auto_pilot` | BOOLEAN | NOT NULL, default=True |
| `is_favorite` | BOOLEAN | NOT NULL, default=False |
| `strategy_family` | VARCHAR(64) | NOT NULL, default=vulnerability_research.discovery_research |
| `persona_dispatch_json` | TEXT | default={} |
| `cost_budget_usd` | FLOAT | NOT NULL, default=50.0 |
| `cost_actual_usd` | FLOAT | NOT NULL, default=0.0 |
| `llm_tokens_cost_usd` | FLOAT | NOT NULL, default=0.0 |
| `mcp_calls_cost_usd` | FLOAT | NOT NULL, default=0.0 |
| `fuzz_infra_cost_usd` | FLOAT | NOT NULL, default=0.0 |
| `primary_outcome_id` | VARCHAR(64) |  |
| `linked_campaign_ids_json` | TEXT | default=[] |
| `linked_finding_ids_json` | TEXT | default=[] |
| `prompt_pins_json` | TEXT | default={} |
| `started_at` | DATETIME |  |
| `stopped_at` | DATETIME |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E06FC40> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E06FCE0> |

### `vr_mcp_call_log`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function McpCallLogRecordBase.<lambda> at 0x000000003E0B37E0> |
| `server_id` | VARCHAR(64) | indexed, NOT NULL |
| `base_url` | VARCHAR(512) | NOT NULL |
| `action` | VARCHAR(128) | NOT NULL |
| `status` | VARCHAR(16) | NOT NULL |
| `http_status` | INTEGER |  |
| `latency_ms` | INTEGER |  |
| `error_excerpt` | TEXT |  |
| `target_id` | VARCHAR(36) | indexed |
| `team_id` | VARCHAR(36) |  |
| `instance_id` | VARCHAR(128) | indexed |
| `investigation_id` | VARCHAR(36) | indexed |
| `branch_id` | VARCHAR(36) | indexed |
| `turn_number` | INTEGER |  |
| `called_at` | DATETIME | indexed, NOT NULL, default=<function utc_now at 0x000000003E0B39C0> |

### `vr_outcome_reviews`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function OutcomeReviewRecordBase.<lambda> at 0x000000003E124AE0> |
| `outcome_id` | VARCHAR | FK -> vr_investigation_outcomes.id, indexed, NOT NULL |
| `reviewer_branch_id` | VARCHAR | FK -> vr_investigation_branches.id, NOT NULL |
| `reviewer_persona` | VARCHAR(64) | NOT NULL |
| `vote` | VARCHAR(16) | indexed, NOT NULL |
| `comment` | TEXT | default= |
| `suggested_edits_json` | TEXT | default={} |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E124B80> |

### `vr_patterns`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | VARCHAR | PK, default=<function PatternRecordBase.<lambda> at 0x000000003E125EE0> |
| `workspace_id` | VARCHAR | FK -> vr_workspaces.id, indexed, NOT NULL |
| `investigation_id` | VARCHAR | FK -> vr_investigations.id, indexed |
| `kind` | VARCHAR(32) | indexed, NOT NULL |
| `summary` | VARCHAR(512) | NOT NULL |
| `body` | TEXT | default= |
| `applicability_json` | TEXT | default={} |
| `confidence` | VARCHAR(16) | indexed, NOT NULL, default=medium |
| `evidence_refs_json` | TEXT | default=[] |
| `status` | VARCHAR(16) | indexed, NOT NULL, default=draft |
| `scope` | VARCHAR(16) | indexed, NOT NULL, default=local |
| `superseded_by` | VARCHAR(64) | indexed |
| `trust_tier` | VARCHAR(16) | indexed, NOT NULL, default=unreviewed |
| `provenance_json` | TEXT | default={} |
| `knowledge_entry_id` | INTEGER | indexed |
| `times_retrieved` | INTEGER | NOT NULL, default=0 |
| `last_used_at` | DATETIME |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E126020> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E125F80> |

### `vr_projects`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | VARCHAR | PK, default=<function ProjectRecordBase.<lambda> at 0x000000003E160860> |
| `name` | VARCHAR(255) | indexed, NOT NULL |
| `target_id` | VARCHAR | FK -> vr_targets.id, indexed, NOT NULL |
| `analysis_system_id` | INTEGER |  |
| `context_notes` | TEXT | default= |
| `status` | VARCHAR(32) | indexed, NOT NULL, default=created |
| `created_by` | VARCHAR(64) | indexed |
| `budget_json` | TEXT | default={} |
| `obligations_json` | TEXT | default={} |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E160900> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E1607C0> |
| `cve_id` | VARCHAR(32) | indexed |
| `patched_target_id` | VARCHAR | FK -> vr_targets.id, indexed |
| `poc_system_id` | INTEGER |  |

### `vr_target_tag_index`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function TargetTagIndexBase.<lambda> at 0x000000003E19C360> |
| `target_id` | VARCHAR | FK -> vr_targets.id, indexed, NOT NULL |
| `workspace_id` | VARCHAR | FK -> vr_workspaces.id, indexed, NOT NULL |
| `tag` | VARCHAR(128) | indexed, NOT NULL |
| `tag_source` | VARCHAR(32) | NOT NULL |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E19C4A0> |

### `vr_targets`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | VARCHAR | PK, default=<function TargetRecordBase.<lambda> at 0x000000003E1627A0> |
| `workspace_id` | VARCHAR | FK -> vr_workspaces.id, indexed, NOT NULL |
| `display_name` | VARCHAR(255) | NOT NULL |
| `kind` | VARCHAR(64) | indexed, NOT NULL |
| `descriptor_json` | TEXT | default={} |
| `primary_language` | VARCHAR(32) |  |
| `secondary_languages_json` | TEXT | default=[] |
| `status` | VARCHAR(32) | indexed, NOT NULL, default=active |
| `capability_profile_json` | TEXT | default={} |
| `tags_json` | TEXT | default=[] |
| `analysis_state` | VARCHAR(24) | indexed, NOT NULL, default=pending |
| `analysis_state_message` | TEXT |  |
| `analysis_started_at` | DATETIME |  |
| `analysis_completed_at` | DATETIME |  |
| `_mcp_handles_json` | TEXT | NOT NULL, default={}, server_default={} |
| `analysis_stages_json` | TEXT | NOT NULL, default={}, server_default={} |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E1625C0> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E162700> |

### `vr_workspaces`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | VARCHAR | PK, default=<function WorkspaceRecordBase.<lambda> at 0x000000003E19F060> |
| `name` | VARCHAR(255) | indexed, NOT NULL |
| `slug` | VARCHAR(128) | indexed, NOT NULL |
| `description` | TEXT | default= |
| `theme` | VARCHAR(64) | NOT NULL, default=custom |
| `status` | VARCHAR(32) | indexed, NOT NULL, default=active |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E19F1A0> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E19F240> |

---

## Malware Tables (17)


### `malware_families`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | VARCHAR | PK, default=<function MalwareFamilyRecord.<lambda> at 0x000000003DD01DA0> |
| `workspace_id` | VARCHAR | FK -> malware_workspaces.id, indexed, NOT NULL |
| `name` | VARCHAR(128) | indexed, NOT NULL |
| `aliases_json` | TEXT |  |
| `description` | TEXT |  |
| `actor_cluster` | VARCHAR(128) | indexed |
| `references_json` | TEXT |  |
| `status` | VARCHAR(16) | indexed, NOT NULL, default=draft |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DD01C60> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DD01D00> |

### `malware_findings`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | VARCHAR | PK, default=<function MalwareFindingRecord.<lambda> at 0x000000003DD03EC0> |
| `investigation_id` | VARCHAR | FK -> malware_investigations.id, indexed |
| `target_id` | VARCHAR | FK -> malware_targets.id, indexed |
| `kind` | VARCHAR(64) | indexed, NOT NULL |
| `confidence` | VARCHAR(16) | indexed, NOT NULL, default=medium |
| `payload_json` | TEXT |  |
| `operator_notes` | TEXT |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DD03E20> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DD03F60> |

### `malware_investigation_branches`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function BranchRecordBase.<lambda> at 0x000000003DCC7600> |
| `investigation_id` | VARCHAR | FK -> malware_investigations.id, indexed, NOT NULL |
| `parent_branch_id` | VARCHAR | FK -> malware_investigation_branches.id, indexed |
| `merged_into_branch_id` | VARCHAR | FK -> malware_investigation_branches.id, indexed |
| `status` | VARCHAR(32) | indexed, NOT NULL, default=active |
| `persona_voice` | VARCHAR(32) | NOT NULL, default=unspecified |
| `strategy_family` | VARCHAR(128) | indexed |
| `fork_reason` | TEXT | default= |
| `fork_at_turn` | INTEGER |  |
| `case_state_json` | TEXT | default={} |
| `branch_cost_usd` | FLOAT | NOT NULL, default=0.0 |
| `turn_count` | INTEGER | NOT NULL, default=0 |
| `closed_reason` | TEXT | default= |
| `promoted` | BOOLEAN | NOT NULL, default=False |
| `closed_at` | DATETIME |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DCC76A0> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DCC7740> |

### `malware_investigation_messages`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function MessageRecordBase.<lambda> at 0x000000003DDB20C0> |
| `investigation_id` | VARCHAR | FK -> malware_investigations.id, indexed, NOT NULL |
| `branch_id` | VARCHAR | FK -> malware_investigation_branches.id, indexed, NOT NULL |
| `sender_kind` | VARCHAR(16) | NOT NULL |
| `sender_id` | VARCHAR(64) |  |
| `payload_kind` | VARCHAR(32) | indexed, NOT NULL |
| `payload_json` | TEXT | default={} |
| `operator_intent` | VARCHAR(32) |  |
| `at_turn` | INTEGER |  |
| `evidence_refs_json` | TEXT | default=[] |
| `auto_steering_key` | VARCHAR(128) |  |
| `created_at` | DATETIME | indexed, NOT NULL, default=<function utc_now at 0x000000003DDB2020> |
| `acked_at` | DATETIME | indexed |

### `malware_investigation_outcomes`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function OutcomeRecordBase.<lambda> at 0x000000003DDF6660> |
| `investigation_id` | VARCHAR | FK -> malware_investigations.id, indexed, NOT NULL |
| `branch_id` | VARCHAR | FK -> malware_investigation_branches.id, indexed, NOT NULL |
| `outcome_kind` | VARCHAR(32) | indexed, NOT NULL |
| `payload_json` | TEXT | default={} |
| `confidence` | VARCHAR(16) | NOT NULL |
| `evidence_refs_json` | TEXT | default=[] |
| `accepted_by_operator` | BOOLEAN | NOT NULL, default=False |
| `accepted_at` | DATETIME |  |
| `state` | VARCHAR(16) | indexed, NOT NULL, default=draft |
| `dispatch_status` | VARCHAR(16) | indexed, NOT NULL, default=pending |
| `dispatch_target` | VARCHAR(128) |  |
| `claimed_at` | DATETIME |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DDF6840> |

### `malware_investigation_targets`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | VARCHAR | PK, default=<function InvestigationTargetRecordBase.<lambda> at 0x000000003DD3B380> |
| `investigation_id` | VARCHAR | FK -> malware_investigations.id, indexed, NOT NULL |
| `target_id` | VARCHAR | FK -> malware_targets.id, indexed, NOT NULL |
| `role` | VARCHAR(32) | indexed, NOT NULL, default=comparison |
| `rationale` | TEXT | default= |
| `attached_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DD3B420> |

### `malware_investigations`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | VARCHAR | PK, default=<function InvestigationRecordBase.<lambda> at 0x000000003DD3B7E0> |
| `project_id` | VARCHAR(64) | indexed |
| `parent_investigation_id` | VARCHAR | FK -> malware_investigations.id, indexed |
| `target_id` | VARCHAR | FK -> malware_targets.id, indexed, NOT NULL |
| `secondary_target_refs_json` | TEXT | default=[] |
| `kind` | VARCHAR(32) | indexed, NOT NULL, default=full_analysis |
| `title` | VARCHAR(255) | NOT NULL |
| `initial_question` | TEXT | default= |
| `status` | VARCHAR(32) | indexed, NOT NULL, default=created |
| `pause_reason` | VARCHAR(32) |  |
| `auto_pilot` | BOOLEAN | NOT NULL, default=True |
| `is_favorite` | BOOLEAN | NOT NULL, default=False |
| `persona_dispatch_json` | TEXT | default={} |
| `cost_budget_usd` | FLOAT | NOT NULL, default=50.0 |
| `cost_actual_usd` | FLOAT | NOT NULL, default=0.0 |
| `llm_tokens_cost_usd` | FLOAT | NOT NULL, default=0.0 |
| `mcp_calls_cost_usd` | FLOAT | NOT NULL, default=0.0 |
| `fuzz_infra_cost_usd` | FLOAT | NOT NULL, default=0.0 |
| `primary_outcome_id` | VARCHAR(64) |  |
| `linked_campaign_ids_json` | TEXT | default=[] |
| `linked_finding_ids_json` | TEXT | default=[] |
| `prompt_pins_json` | TEXT | default={} |
| `started_at` | DATETIME |  |
| `stopped_at` | DATETIME |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DD3B9C0> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DD3BA60> |
| `analysis_depth` | VARCHAR(16) | indexed, NOT NULL, default=medium |
| `inherit_observations` | BOOLEAN | NOT NULL, default=True |
| `strategy_family` | VARCHAR(64) | NOT NULL, default=malware_analysis.full_analysis |

### `malware_mcp_call_log`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function McpCallLogRecordBase.<lambda> at 0x000000003DDB0360> |
| `server_id` | VARCHAR(64) | indexed, NOT NULL |
| `base_url` | VARCHAR(512) | NOT NULL |
| `action` | VARCHAR(128) | NOT NULL |
| `status` | VARCHAR(16) | NOT NULL |
| `http_status` | INTEGER |  |
| `latency_ms` | INTEGER |  |
| `error_excerpt` | TEXT |  |
| `target_id` | VARCHAR(36) | indexed |
| `team_id` | VARCHAR(36) |  |
| `instance_id` | VARCHAR(128) | indexed |
| `investigation_id` | VARCHAR(36) | indexed |
| `branch_id` | VARCHAR(36) | indexed |
| `turn_number` | INTEGER |  |
| `called_at` | DATETIME | indexed, NOT NULL, default=<function utc_now at 0x000000003DDB04A0> |

### `malware_observations`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | VARCHAR | PK, default=<function MalwareObservationRecord.<lambda> at 0x000000003DDF4900> |
| `target_id` | VARCHAR | FK -> malware_targets.id, NOT NULL |
| `investigation_id` | VARCHAR | FK -> malware_investigations.id, indexed |
| `branch_id` | VARCHAR | FK -> malware_investigation_branches.id |
| `kind` | VARCHAR(48) | NOT NULL |
| `polarity` | VARCHAR(16) | NOT NULL, default=positive |
| `source` | VARCHAR(16) | indexed, NOT NULL, default=agent |
| `payload_json` | TEXT |  |
| `evidence_refs_json` | TEXT |  |
| `dedup_hash` | VARCHAR(64) |  |
| `supersedes_id` | VARCHAR(64) |  |
| `superseded_by_id` | VARCHAR(64) | indexed |
| `created_at` | DATETIME | indexed, NOT NULL, default=<function utc_now at 0x000000003DDF4A40> |

### `malware_outcome_reviews`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function OutcomeReviewRecordBase.<lambda> at 0x000000003DE34360> |
| `outcome_id` | VARCHAR | FK -> malware_investigation_outcomes.id, indexed, NOT NULL |
| `reviewer_branch_id` | VARCHAR | FK -> malware_investigation_branches.id, NOT NULL |
| `reviewer_persona` | VARCHAR(64) | NOT NULL |
| `vote` | VARCHAR(16) | indexed, NOT NULL |
| `comment` | TEXT | default= |
| `suggested_edits_json` | TEXT | default={} |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DE34400> |

### `malware_patterns`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | VARCHAR | PK, default=<function PatternRecordBase.<lambda> at 0x000000003DE35760> |
| `workspace_id` | VARCHAR | FK -> malware_workspaces.id, indexed, NOT NULL |
| `investigation_id` | VARCHAR | FK -> malware_investigations.id, indexed |
| `kind` | VARCHAR(32) | indexed, NOT NULL |
| `summary` | VARCHAR(512) | NOT NULL |
| `body` | TEXT | default= |
| `applicability_json` | TEXT | default={} |
| `confidence` | VARCHAR(16) | indexed, NOT NULL, default=medium |
| `evidence_refs_json` | TEXT | default=[] |
| `status` | VARCHAR(16) | indexed, NOT NULL, default=draft |
| `scope` | VARCHAR(16) | indexed, NOT NULL, default=local |
| `superseded_by` | VARCHAR(64) | indexed |
| `trust_tier` | VARCHAR(16) | indexed, NOT NULL, default=unreviewed |
| `provenance_json` | TEXT | default={} |
| `knowledge_entry_id` | INTEGER | indexed |
| `times_retrieved` | INTEGER | NOT NULL, default=0 |
| `last_used_at` | DATETIME |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DE358A0> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DE35800> |

### `malware_playbook_family_assignments`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function MalwarePlaybookFamilyAssignmentRecord.<lambda> at 0x000000003DE6A3E0> |
| `playbook_id` | VARCHAR | FK -> malware_playbooks.id, indexed, NOT NULL |
| `family_id` | VARCHAR | FK -> malware_families.id, indexed, NOT NULL |
| `auto_trigger_threshold` | FLOAT |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DE6A340> |

### `malware_playbooks`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | VARCHAR | PK, default=<function MalwarePlaybookRecord.<lambda> at 0x000000003DE685E0> |
| `workspace_id` | VARCHAR | FK -> malware_workspaces.id, indexed, NOT NULL |
| `name` | VARCHAR(128) | indexed, NOT NULL |
| `description` | TEXT |  |
| `steps_json` | TEXT |  |
| `status` | VARCHAR(16) | indexed, NOT NULL, default=draft |
| `run_count` | INTEGER | NOT NULL, default=0 |
| `last_run_at` | DATETIME |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DE68680> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DE68720> |

### `malware_projects`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | VARCHAR | PK, default=<function ProjectRecordBase.<lambda> at 0x000000003DE6BEC0> |
| `name` | VARCHAR(255) | indexed, NOT NULL |
| `target_id` | VARCHAR | FK -> malware_targets.id, indexed, NOT NULL |
| `analysis_system_id` | INTEGER |  |
| `context_notes` | TEXT | default= |
| `status` | VARCHAR(32) | indexed, NOT NULL, default=created |
| `created_by` | VARCHAR(64) | indexed |
| `budget_json` | TEXT | default={} |
| `obligations_json` | TEXT | default={} |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DE6BF60> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DEB0040> |

### `malware_target_tag_index`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function TargetTagIndexBase.<lambda> at 0x000000003DEED260> |
| `target_id` | VARCHAR | FK -> malware_targets.id, indexed, NOT NULL |
| `workspace_id` | VARCHAR | FK -> malware_workspaces.id, indexed, NOT NULL |
| `tag` | VARCHAR(128) | indexed, NOT NULL |
| `tag_source` | VARCHAR(32) | NOT NULL |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DEED3A0> |

### `malware_targets`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | VARCHAR | PK, default=<function TargetRecordBase.<lambda> at 0x000000003DEEC540> |
| `workspace_id` | VARCHAR | FK -> malware_workspaces.id, indexed, NOT NULL |
| `display_name` | VARCHAR(255) | NOT NULL |
| `kind` | VARCHAR(64) | indexed, NOT NULL |
| `descriptor_json` | TEXT | default={} |
| `primary_language` | VARCHAR(32) |  |
| `secondary_languages_json` | TEXT | default=[] |
| `status` | VARCHAR(32) | indexed, NOT NULL, default=active |
| `capability_profile_json` | TEXT | default={} |
| `tags_json` | TEXT | default=[] |
| `analysis_state` | VARCHAR(24) | indexed, NOT NULL, default=pending |
| `analysis_state_message` | TEXT |  |
| `analysis_started_at` | DATETIME |  |
| `analysis_completed_at` | DATETIME |  |
| `_mcp_handles_json` | TEXT | NOT NULL, default={}, server_default={} |
| `analysis_stages_json` | TEXT | NOT NULL, default={}, server_default={} |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DEB3F60> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DEB3EC0> |
| `parent_target_id` | VARCHAR | FK -> malware_targets.id, indexed |
| `sha256` | VARCHAR(64) | indexed |

### `malware_workspaces`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | VARCHAR | PK, default=<function WorkspaceRecordBase.<lambda> at 0x000000003DEEE7A0> |
| `name` | VARCHAR(255) | indexed, NOT NULL |
| `slug` | VARCHAR(128) | indexed, NOT NULL |
| `description` | TEXT | default= |
| `theme` | VARCHAR(64) | NOT NULL, default=custom |
| `status` | VARCHAR(32) | indexed, NOT NULL, default=active |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DEEF100> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DEEEDE0> |

---

## Forensics Tables (16)


### `forensics_agent_steps`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function AgentStepRecord.<lambda> at 0x000000003DB56520> |
| `investigation_id` | VARCHAR | indexed, NOT NULL |
| `team_id` | VARCHAR | indexed |
| `step_number` | INTEGER | NOT NULL, default=0 |
| `action` | VARCHAR | NOT NULL, default=reasoning |
| `script_content` | TEXT |  |
| `command` | TEXT |  |
| `stdout` | TEXT |  |
| `stderr` | TEXT |  |
| `exit_code` | INTEGER |  |
| `reasoning` | TEXT |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DB563E0> |

### `forensics_analyst_directives`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function AnalystDirectiveRecord.<lambda> at 0x000000003DADFE20> |
| `project_id` | VARCHAR | indexed, NOT NULL |
| `investigation_id` | VARCHAR | indexed |
| `text` | TEXT |  |
| `created_by` | VARCHAR | indexed |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DADFD80> |
| `resolved_at` | DATETIME |  |
| `active` | BOOLEAN | indexed, NOT NULL, default=True |
| `verdict` | VARCHAR(16) | indexed |
| `strategy_family` | VARCHAR(64) | indexed |
| `required_artifact` | TEXT |  |
| `source_investigation_id` | VARCHAR(64) |  |
| `source_answer_id` | VARCHAR(64) |  |

### `forensics_answer_candidates`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function AnswerCandidateRecord.<lambda> at 0x000000003DC7F920> |
| `project_id` | VARCHAR | indexed, NOT NULL |
| `team_id` | VARCHAR | indexed |
| `investigation_id` | VARCHAR | indexed |
| `question_text` | TEXT |  |
| `answer_text` | TEXT |  |
| `confidence` | VARCHAR | NOT NULL, default=caveated |
| `primary_artifact_id` | VARCHAR |  |
| `corroboration_json` | TEXT |  |
| `format_hint` | VARCHAR | NOT NULL, default= |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DC7FA60> |

### `forensics_artifacts`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function ArtifactRecord.<lambda> at 0x000000003DAB5440> |
| `project_id` | VARCHAR | indexed, NOT NULL |
| `artifact_family` | VARCHAR | indexed, NOT NULL |
| `artifact_type` | VARCHAR | indexed, NOT NULL |
| `source_tool` | VARCHAR | NOT NULL, default= |
| `source_evidence_id` | VARCHAR |  |
| `source_investigation_id` | VARCHAR(64) | indexed |
| `data_json` | TEXT |  |
| `lead_score` | FLOAT |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DAB54E0> |

### `forensics_finding_suppressions`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function FindingSuppressionRecord.<lambda> at 0x000000003DB325C0> |
| `project_id` | VARCHAR(64) | indexed, NOT NULL |
| `fingerprint` | VARCHAR(64) | NOT NULL |
| `artifact_type` | VARCHAR(128) |  |
| `executable` | TEXT |  |
| `path` | TEXT |  |
| `name` | TEXT |  |
| `finding_user` | TEXT |  |
| `reasons_json` | TEXT |  |
| `notes` | TEXT |  |
| `source_directive_id` | VARCHAR(64) |  |
| `suppressed_by` | VARCHAR(64) |  |
| `suppressed_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DB32520> |

### `forensics_investigation_branches`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function BranchRecordBase.<lambda> at 0x000000003DADD620> |
| `investigation_id` | VARCHAR | FK -> forensics_investigations.id, indexed, NOT NULL |
| `parent_branch_id` | VARCHAR | FK -> forensics_investigation_branches.id, indexed |
| `merged_into_branch_id` | VARCHAR | FK -> forensics_investigation_branches.id, indexed |
| `status` | VARCHAR(32) | indexed, NOT NULL, default=active |
| `persona_voice` | VARCHAR(32) | NOT NULL, default=unspecified |
| `strategy_family` | VARCHAR(128) | indexed |
| `fork_reason` | TEXT | default= |
| `fork_at_turn` | INTEGER |  |
| `case_state_json` | TEXT | default={} |
| `branch_cost_usd` | FLOAT | NOT NULL, default=0.0 |
| `turn_count` | INTEGER | NOT NULL, default=0 |
| `closed_reason` | TEXT | default= |
| `promoted` | BOOLEAN | NOT NULL, default=False |
| `closed_at` | DATETIME |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DADD760> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DADD800> |

### `forensics_investigation_messages`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function MessageRecordBase.<lambda> at 0x000000003DBA22A0> |
| `investigation_id` | VARCHAR | FK -> forensics_investigations.id, indexed, NOT NULL |
| `branch_id` | VARCHAR | FK -> forensics_investigation_branches.id, indexed, NOT NULL |
| `sender_kind` | VARCHAR(16) | NOT NULL |
| `sender_id` | VARCHAR(64) |  |
| `payload_kind` | VARCHAR(32) | indexed, NOT NULL |
| `payload_json` | TEXT | default={} |
| `operator_intent` | VARCHAR(32) |  |
| `at_turn` | INTEGER |  |
| `evidence_refs_json` | TEXT | default=[] |
| `auto_steering_key` | VARCHAR(128) |  |
| `created_at` | DATETIME | indexed, NOT NULL, default=<function utc_now at 0x000000003DBA2160> |

### `forensics_investigation_outcomes`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function OutcomeRecordBase.<lambda> at 0x000000003DBA25C0> |
| `investigation_id` | VARCHAR | FK -> forensics_investigations.id, indexed, NOT NULL |
| `branch_id` | VARCHAR | FK -> forensics_investigation_branches.id, indexed, NOT NULL |
| `outcome_kind` | VARCHAR(32) | indexed, NOT NULL |
| `payload_json` | TEXT | default={} |
| `confidence` | VARCHAR(16) | NOT NULL |
| `evidence_refs_json` | TEXT | default=[] |
| `accepted_by_operator` | BOOLEAN | NOT NULL, default=False |
| `accepted_at` | DATETIME |  |
| `state` | VARCHAR(16) | indexed, NOT NULL, default=draft |
| `dispatch_status` | VARCHAR(16) | indexed, NOT NULL, default=pending |
| `dispatch_target` | VARCHAR(128) |  |
| `claimed_at` | DATETIME |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DBA2480> |

### `forensics_investigations`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function InvestigationRunRecord.<lambda> at 0x000000003DB542C0> |
| `project_id` | VARCHAR | indexed, NOT NULL |
| `team_id` | VARCHAR | indexed |
| `question` | TEXT |  |
| `status` | VARCHAR | indexed, NOT NULL, default=pending |
| `task_id` | VARCHAR | indexed |
| `max_attempts` | INTEGER | NOT NULL, default=10 |
| `attempts_used` | INTEGER | NOT NULL, default=0 |
| `final_answer` | TEXT |  |
| `confidence` | VARCHAR |  |
| `parent_investigation_id` | VARCHAR(64) | indexed |
| `prompt_pins_json` | TEXT | default={} |
| `strategy_family` | VARCHAR(64) | NOT NULL, default=generic |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DB54360> |
| `updated_at` | DATETIME | default=<function utc_now at 0x000000003DB54180> |

### `forensics_leads`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function LeadRecord.<lambda> at 0x000000003DAB7060> |
| `project_id` | VARCHAR | indexed, NOT NULL |
| `artifact_id` | VARCHAR | indexed, NOT NULL |
| `score` | FLOAT | NOT NULL, default=0.0 |
| `reason` | TEXT |  |
| `artifact_family` | VARCHAR | NOT NULL, default= |
| `related_artifact_ids_json` | TEXT |  |
| `question_families_json` | TEXT |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DAB7100> |

### `forensics_outcome_reviews`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function OutcomeReviewRecordBase.<lambda> at 0x000000003DBE2AC0> |
| `outcome_id` | VARCHAR | FK -> forensics_investigation_outcomes.id, indexed, NOT NULL |
| `reviewer_branch_id` | VARCHAR | FK -> forensics_investigation_branches.id, NOT NULL |
| `reviewer_persona` | VARCHAR(64) | NOT NULL |
| `vote` | VARCHAR(16) | indexed, NOT NULL |
| `comment` | TEXT | default= |
| `suggested_edits_json` | TEXT | default={} |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DBE2C00> |

### `forensics_patterns`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | VARCHAR | PK, default=<function PatternRecordBase.<lambda> at 0x000000003DC34180> |
| `workspace_id` | VARCHAR | FK -> forensics_projects.id, indexed, NOT NULL |
| `investigation_id` | VARCHAR | FK -> forensics_investigations.id, indexed |
| `kind` | VARCHAR(32) | indexed, NOT NULL |
| `summary` | VARCHAR(512) | NOT NULL |
| `body` | TEXT | default= |
| `applicability_json` | TEXT | default={} |
| `confidence` | VARCHAR(16) | indexed, NOT NULL, default=medium |
| `evidence_refs_json` | TEXT | default=[] |
| `status` | VARCHAR(16) | indexed, NOT NULL, default=draft |
| `scope` | VARCHAR(16) | indexed, NOT NULL, default=local |
| `superseded_by` | VARCHAR(64) | indexed |
| `trust_tier` | VARCHAR(16) | indexed, NOT NULL, default=unreviewed |
| `provenance_json` | TEXT | default={} |
| `knowledge_entry_id` | INTEGER | indexed |
| `times_retrieved` | INTEGER | NOT NULL, default=0 |
| `last_used_at` | DATETIME |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DC351C0> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DC34220> |

### `forensics_project_evidence`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function ProjectEvidenceRecord.<lambda> at 0x000000003DC7E020> |
| `project_id` | VARCHAR | indexed, NOT NULL |
| `file_path` | TEXT |  |
| `evidence_type` | VARCHAR | indexed, NOT NULL, default=unknown |
| `file_hash_sha256` | VARCHAR |  |
| `size_bytes` | BIGINT |  |
| `metadata_json` | TEXT |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DC7DF80> |

### `forensics_projects`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function ForensicsProjectRecord.<lambda> at 0x000000003DC35BC0> |
| `name` | VARCHAR(255) | indexed, NOT NULL |
| `description` | TEXT |  |
| `system_id` | INTEGER | indexed, NOT NULL |
| `evidence_directory` | TEXT |  |
| `analyzer_os` | VARCHAR(16) | NOT NULL, default=linux |
| `project_kind` | VARCHAR(32) | indexed, NOT NULL, default=disk_evidence |
| `status` | VARCHAR | indexed, NOT NULL, default=created |
| `team_id` | VARCHAR | indexed |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DC35D00> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DC35DA0> |

### `forensics_solid_evidence`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function SolidEvidenceRecord.<lambda> at 0x000000003DCC59E0> |
| `project_id` | VARCHAR(64) | indexed, NOT NULL |
| `question` | TEXT |  |
| `answer` | TEXT |  |
| `verdict` | VARCHAR(16) | indexed, NOT NULL |
| `confidence` | VARCHAR(16) | NOT NULL, default=unknown |
| `source_investigation_id` | VARCHAR(64) | indexed |
| `source_answer_id` | VARCHAR(64) |  |
| `source_directive_id` | VARCHAR(64) |  |
| `primary_artifact` | TEXT |  |
| `corroboration_json` | TEXT |  |
| `tagged_by` | VARCHAR(64) |  |
| `tagged_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DCC5A80> |
| `notes` | TEXT |  |

### `forensics_writeups`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | VARCHAR | PK, default=<function WriteUpRecord.<lambda> at 0x000000003DB57F60> |
| `project_id` | VARCHAR | indexed, NOT NULL |
| `team_id` | VARCHAR | indexed |
| `investigation_id` | VARCHAR | indexed |
| `title` | VARCHAR(512) | NOT NULL, default= |
| `content_markdown` | TEXT |  |
| `methodology` | TEXT |  |
| `artifacts_referenced_json` | TEXT |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003DBA0040> |

---

## Vulnerability Tables (10)


### `assettagrecord`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | INTEGER | PK |
| `system_id` | INTEGER | indexed, NOT NULL |
| `tag_key` | VARCHAR | indexed, NOT NULL |
| `tag_value` | VARCHAR | NOT NULL, default= |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E255D00> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E255C60> |

### `cacherecord`

| Column | Type | Constraints |
|--------|------|-------------|
| `namespace` | VARCHAR | PK |
| `cache_key` | VARCHAR | PK |
| `payload_json` | TEXT |  |
| `last_synced_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E1DD260> |

### `distributionprofilerecord`

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | INTEGER | PK |
| `distro_key` | VARCHAR | unique, indexed, NOT NULL |
| `display_name` | VARCHAR | NOT NULL, default= |
| `os_release_ids_json` | TEXT |  |
| `inventory_command` | TEXT |  |
| `package_parser` | VARCHAR | NOT NULL |
| `advisory_strategy` | VARCHAR | NOT NULL |
| `advisory_ecosystem` | VARCHAR |  |
| `advisory_batch_size` | INTEGER |  |
| `enabled` | BOOLEAN | NOT NULL, default=True |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E1DE3E0> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E1DE480> |

### `finding_feedbacks`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | INTEGER | PK |
| `finding_id` | INTEGER | NOT NULL |
| `user_id` | TEXT | NOT NULL |
| `reason` | TEXT | NOT NULL |
| `notes` | TEXT | server_default= |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E2836A0> |

### `inventoryartifactrecord`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | INTEGER | PK |
| `run_id` | VARCHAR | indexed, NOT NULL |
| `system_id` | INTEGER | indexed, NOT NULL |
| `host` | VARCHAR | indexed, NOT NULL |
| `distro` | VARCHAR | NOT NULL, default=unknown |
| `kernel` | VARCHAR | NOT NULL, default= |
| `status` | VARCHAR | NOT NULL, default=collected |
| `error_message` | VARCHAR |  |
| `payload_json` | TEXT |  |
| `collected_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E1DFCE0> |

### `latest_finding_records`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | INTEGER | PK |
| `host` | TEXT | NOT NULL |
| `package_name` | TEXT | NOT NULL |
| `cve_id` | TEXT | NOT NULL |
| `system_id` | INTEGER | indexed, NOT NULL |
| `system_name` | TEXT | server_default= |
| `distribution` | TEXT | server_default= |
| `criticality` | TEXT | NOT NULL |
| `score` | FLOAT | NOT NULL |
| `rationale` | TEXT | server_default= |
| `fixed_version` | TEXT |  |
| `nvd_url` | TEXT | NOT NULL |
| `compliance_tags_json` | TEXT | server_default=[] |
| `details_json` | TEXT | server_default={} |
| `last_scanned_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E2816C0> |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E281620> |
| `status` | TEXT | server_default=open |
| `is_kev` | BOOLEAN | NOT NULL, server_default=false |
| `current_workflow_state` | TEXT | NOT NULL, server_default=new |

### `prioritizedfindingrecord`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | INTEGER | PK |
| `run_id` | VARCHAR | indexed, NOT NULL |
| `system_id` | INTEGER | indexed, NOT NULL |
| `host` | VARCHAR | indexed, NOT NULL |
| `package_name` | VARCHAR | indexed, NOT NULL |
| `installed_version` | VARCHAR | NOT NULL |
| `cve_id` | VARCHAR | indexed, NOT NULL |
| `criticality` | VARCHAR | NOT NULL |
| `score` | FLOAT | NOT NULL |
| `rationale` | VARCHAR | NOT NULL, default= |
| `fixed_version` | VARCHAR |  |
| `nvd_url` | VARCHAR | NOT NULL |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E21BEC0> |

### `remediationrecord`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | INTEGER | PK |
| `host` | VARCHAR | indexed, NOT NULL |
| `package_name` | VARCHAR | indexed, NOT NULL |
| `cve_id` | VARCHAR | indexed, NOT NULL |
| `status` | VARCHAR | NOT NULL, default=open |
| `notes` | VARCHAR | NOT NULL, default= |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E257420> |

### `scheduledscanrecord`

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | VARCHAR | indexed |
| `id` | INTEGER | PK |
| `target_name` | VARCHAR | indexed, NOT NULL |
| `cron_expression` | VARCHAR | NOT NULL |
| `enabled` | BOOLEAN | NOT NULL, default=True |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E21A700> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E21A7A0> |
| `last_run_at` | DATETIME |  |
| `last_run_result` | VARCHAR |  |

### `scoringpolicyrecord`

| Column | Type | Constraints |
|--------|------|-------------|
| `policy_id` | VARCHAR | PK |
| `payload_json` | TEXT |  |
| `created_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E2193A0> |
| `updated_at` | DATETIME | NOT NULL, default=<function utc_now at 0x000000003E2194E0> |

---

*Generated from live SQLModel metadata (120 tables). Alembic head `121_backfill_investigation_cost`. Regenerate with `.run/schema_dump.py` + `.run/gen_schema_md.py` after model changes.*
