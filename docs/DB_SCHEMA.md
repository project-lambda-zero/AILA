# Database Schema Reference

All SQLModel tables used by AILA, organized by ownership (platform vs module).

SQLite is the default database backend. All tables use SQLModel (SQLAlchemy Core) DDL with `sa_column=Column(Text)` for dialect-agnostic large-text columns. WAL mode is enabled at engine creation for concurrent read/write access.

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
| checkpoint_json | Text/null | | Checkpoint state for resume |
| result_path | Text/null | | Path to task output |
| error | Text/null | | Error message on failure |
| depends_on_json | Text/null | | JSON list of dependency task IDs |
| started_at | datetime/null | | Worker pickup time |
| heartbeat_at | datetime/null | | Last heartbeat from worker |
| completed_at | datetime/null | | Completion time |
| created_at | datetime | default=utc_now | Submission time |
| updated_at | datetime | default=utc_now | Last state change |

**Status transitions:** queued -> waiting -> running -> done/failed/cancelled. See `TaskStatus` enum.

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

## Table Summary

| # | Table | Owner | Records |
|---|-------|-------|---------|
| 1 | ManagedSystemRecord | Platform | SSH targets |
| 2 | SecretRecord | Platform | Encrypted secrets |
| 3 | ProviderConfigRecord | Platform | Provider settings |
| 4 | WorkflowRunRecord | Platform | Workflow executions |
| 5 | PermanentMemoryRecord | Platform | Agent memory |
| 6 | ReportArtifactRecord | Platform | Report file paths |
| 7 | ArtifactRecord | Platform | Generic artifacts |
| 8 | AuditEventRecord | Platform | Audit trail |
| 9 | ConfigEntryRecord | Platform | ConfigRegistry entries |
| 10 | KnowledgeEntryRecord | Platform | Agent RAG vectors |
| 11 | SeedVersionRecord | Platform | Module seed tracking |
| 12 | TaskRecord | Platform | Task queue lifecycle |
| 13 | ApiKeyRecord | Platform | API authentication keys |
| 14 | SessionRecord | Platform | Chat sessions |
| 15 | SessionMessageRecord | Platform | Chat messages |
| 16 | ExplainCacheRecord | Platform | LLM explanation cache |
| 17 | PrioritizedFindingRecord | Vulnerability | Per-run scored findings |
| 18 | LatestFindingRecord | Vulnerability | Latest-state findings |
| 19 | AssetTagRecord | Vulnerability | System asset tags |
| 20 | RemediationRecord | Vulnerability | Remediation tracking |
| 21 | DistributionProfileRecord | Vulnerability | Distribution profiles |
| 22 | InventoryArtifactRecord | Vulnerability | Inventory snapshots |
| 23 | ScoringPolicyRecord | Vulnerability | Scoring configuration |
| 24 | ScheduledScanRecord | Vulnerability | Cron schedules |
| 25 | CacheRecord | Vulnerability | Advisory/CVE cache |

---

*Generated from source models in `src/aila/storage/db_models.py`, `src/aila/platform/tasks/models.py`, and `src/aila/modules/vulnerability/db_models/`.*
*Last updated: 2026-04-05 (v1.7)*
