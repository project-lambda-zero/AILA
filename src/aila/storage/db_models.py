"""Platform-level SQLModel table definitions for AILA.

These models represent the core persistence layer shared across all modules.
Module-specific models live under their respective modules/ subdirectory and
are registered via SchemaRegistry during register_tools().

Each model is written at a defined lifecycle stage and consumed by specific
query surfaces -- these are documented per class.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    Computed,
    DateTime,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR
from sqlmodel import Field, SQLModel

from ..platform.contracts._common import utc_now
from .mixins import TeamScopedMixin


class ManagedSystemRecord(TeamScopedMixin, SQLModel, table=True):
    """Persisted SSH-reachable system registered with the platform.

    Written by: aila register-system (CLI) and the systems platform tool.
    Consumed by: inventory collection, SSH command tool, system listing.

    The name field uniquely identifies a system across the fleet.  host is the
    SSH hostname or IP.  private_key_path and password_secret_id are mutually
    exclusive authentication options; only one should be set.
    """

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    host: str = Field(index=True)
    username: str
    port: int = 22
    distro: str = Field(default="unknown")
    description: str = Field(default="")
    private_key_path: str | None = None
    private_key_secret_id: str | None = None
    password_secret_id: str | None = None
    known_hosts_path: str | None = None
    host_key_fingerprint: str | None = None
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class SecretRecord(SQLModel, table=True):
    """AES-256-GCM encrypted secret stored in the database.

    Secrets are NEVER stored in plaintext.  The ciphertext field holds the
    base64-encoded AES-GCM ciphertext.  The nonce and key_version fields are
    required for decryption via MasterKeySecretProtector.

    Written by: SecretStore.upsert_secret().
    Consumed by: SecretStore.get_secret_by_key() / get_secret_by_id().

    The hint field stores the first 2 characters of the plaintext followed by
    "**" to allow operators to confirm which secret is stored without exposing
    the full value.
    """

    __table_args__ = (
        UniqueConstraint("scope", "secret_key", name="uq_secretrecord_scope_secret_key"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    scope: str = Field(index=True)
    secret_key: str = Field(index=True)
    backend: str = Field(default="master-key")
    key_version: str = Field(default="v1")
    algorithm: str = Field(default="aes-256-gcm")
    nonce: str | None = None
    hint: str | None = None
    ciphertext: str = Field(sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class ProviderConfigRecord(SQLModel, table=True):
    """Mutable provider configuration value stored in the database.

    Written by: ProviderConfigStore.upsert_config() (via aila config set).
    Consumed by: ProviderConfigStore.get_config(), LLMConfigProvider.

    config_key is a flat dotted string such as "openai_model_id" or
    "openai_api_base".  This table is separate from ConfigEntryRecord to
    maintain the historical separation between typed module configs (registry)
    and raw provider strings.
    """

    __table_args__ = (
        UniqueConstraint("config_key", name="uq_providerconfigrecord_config_key"),
    )

    id: int | None = Field(default=None, primary_key=True)
    config_key: str = Field(index=True)
    value: str = Field(sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class WorkflowRunRecord(TeamScopedMixin, SQLModel, table=True):
    """Top-level record for a single workflow execution (one CLI dispatch).

    Written by: workflow orchestrator at run start (status="running") and at
    run end (status="completed" or "failed").
    Consumed by: ReportRepository.latest_report(), history queries, audit tools.

    The compound index on (status, completed_at) is used by
    ReportRepository.latest_report() to walk completed runs in reverse
    chronological order without a full table scan.

    The action_id column is stored as "intent" in the DB for historical reasons
    (column name predates the action/intent renaming).  module_id tracks which
    feature module handled the run for module-scoped report queries.
    """

    __table_args__ = (
        Index("ix_wfr_status_completed", "status", "completed_at"),
    )
    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    query_text: str
    action_id: str = Field(default="", sa_column=Column("intent", Text))
    module_id: str = Field(default="", sa_column=Column("module_id", Text, server_default="", index=True))
    status: str = Field(default="running")
    route_json: str = Field(default="{}", sa_column=Column(Text))
    short_memory_json: str = Field(default="{}", sa_column=Column(Text))
    summary_json: str = Field(default="{}", sa_column=Column(Text))
    report_path: str | None = None
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    completed_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    # Phase 178 (D-07, D-38): nullable JSONB column holding the frozen plan
    # belonging to a run.  Populated by Phase 179's @platform_task wrapper; Phase 178
    # adds only the column (migration 025).
    plan_json: dict[str, Any] | None = Field(
        default=None,
        sa_column=Column("plan_json", JSONB, nullable=True),
    )


class WorkflowStateCursor(SQLModel, table=True):
    """Active state per workflow run. One row per run_id.

    Atomic updates via optimistic ``version`` lock:
    ``UPDATE ... SET version = version + 1 WHERE run_id = :id AND version = :loaded``.
    A 0-row UPDATE means another worker advanced the cursor first; the engine
    raises ``WorkflowConflictError`` (D-32), which ARQ treats as a bare
    exception and retries the whole job. No split-brain.

    Written by: ``DurableStateMachine._save_state`` on every successful
    transition and on retry persistence (D-17).
    Read by: ``DurableStateMachine._load_or_init_cursor`` on every
    ``execute`` entry (fresh start + ARQ-retry resume).

    SIGKILL mid-UPDATE cannot leave partial state because the UPDATE is a
    single-statement transaction.
    """

    __tablename__ = "workflow_state_cursor"

    run_id: str = Field(primary_key=True, foreign_key="workflowrunrecord.id")
    # State/definition identifiers bounded at 128 chars (Phase 178 security
    # fix): prevents unbounded writes to audit/cursor columns that could
    # amplify storage-based DoS via crafted state names.
    current_state: str = Field(
        sa_column=Column("current_state", String(128), nullable=False),
    )
    state_input: dict[str, Any] = Field(
        sa_column=Column("state_input", JSONB, nullable=False)
    )
    retries_in_state: int = Field(default=0, nullable=False)
    definition_id: str = Field(
        sa_column=Column("definition_id", String(128), nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(
            "updated_at",
            DateTime(timezone=True),
            nullable=False,
            server_default=func.now(),
        ),
    )
    version: int = Field(default=0, nullable=False)

    # Phase B (cutover): preserves the prior `current_state` across a
    # pause/resume cycle. NULL except while the cursor is at
    # ``__paused__``. Pause writes archived_state = current_state, then
    # sets current_state = '__paused__'. Resume reverses the assignment
    # and clears archived_state. See migration 067.
    archived_state: str | None = Field(
        default=None,
        sa_column=Column("archived_state", String(128), nullable=True),
    )


class WorkflowStateTransition(SQLModel, table=True):
    """Append-only audit/replay log of every engine state transition.

    Composite PK ``(run_id, seq)`` -- the index implied by the PK already
    covers the (run_id, seq) lookup pattern, so no redundant
    ``ix_wst_run_id`` is declared (minor-flag #1). A secondary index on
    ``(to_state, happened_at DESC)`` (D-43) serves admin UI queries and the
    engine-internal ``has_state_ever_completed`` lookup planned for Phase
    180.

    NEVER UPDATE or DELETE -- orphan ``entered`` rows with no matching
    ``exited:*`` are the intentional audit signal for crashed attempts
    (D-41). INSERT failures propagate; writes are NOT best-effort (D-34).

    Expected row rate: ~2 rows per state per run (one ``entered`` + one
    ``exited:*``). Retention/pruning is deferred to Phase 181 admin
    endpoints.
    """

    __tablename__ = "workflow_state_transitions"
    __table_args__ = (
        # D-43: DESC order expressed in the Alembic DDL via raw SQL; the
        # Python-level Index here covers the column pair so
        # SQLModel.metadata.create_all (used by the test fixture) creates
        # the index correctly for tests.
        Index("ix_wst_to_state_happened_at", "to_state", "happened_at"),
    )

    run_id: str = Field(
        primary_key=True,
        foreign_key="workflowrunrecord.id",
    )
    seq: int = Field(primary_key=True)
    # State identifiers bounded at 128 chars (Phase 178 security fix).
    from_state: str = Field(
        sa_column=Column("from_state", String(128), nullable=False),
    )
    to_state: str = Field(
        sa_column=Column("to_state", String(128), nullable=False),
    )
    # event: entered | exited:ok | exited:retry | exited:failed |
    #        exited:timeout | exited:failed_in_failure_handler
    event: str = Field(
        sa_column=Column("event", String(64), nullable=False),
    )
    input_hash: str | None = Field(
        default=None,
        sa_column=Column("input_hash", String(64), nullable=True),
    )
    output_hash: str | None = Field(
        default=None,
        sa_column=Column("output_hash", String(64), nullable=True),
    )
    duration_ms: int | None = None
    error_class: str | None = Field(
        default=None,
        sa_column=Column("error_class", String(128), nullable=True),
    )
    error_message: str | None = None  # engine truncates at 2000 chars (D-44)
    happened_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(
            "happened_at",
            DateTime(timezone=True),
            nullable=False,
            server_default=func.now(),
        ),
    )


class PermanentMemoryRecord(TeamScopedMixin, SQLModel, table=True):
    """Persistent key-value memory entry scoped to a namespace.

    Written by: PermanentMemoryStore.remember() (platform memory tool).
    Consumed by: PermanentMemoryStore.recall() / recall_entry().

    namespace is typically the agent class name or platform component identifier.
    memory_key is an arbitrary string key within that namespace.  payload_json
    holds the JSON-serialized dict payload.

    Unlike session memory (which is cleared when a run ends), permanent memory
    persists across runs and is explicitly managed by the operator or platform.
    """

    __table_args__ = (
        UniqueConstraint("namespace", "memory_key", name="uq_permanentmemoryrecord_namespace_memory_key"),
    )

    id: int | None = Field(default=None, primary_key=True)
    namespace: str = Field(index=True)
    memory_key: str = Field(index=True)
    payload_json: str = Field(default="{}", sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class ReportArtifactRecord(TeamScopedMixin, SQLModel, table=True):
    """File-path reference for a single report artifact produced by a workflow run.

    Written by: ReportArtifactStore.persist_run_bundle() in the state_persist
    workflow stage (canonical artifact ID assignment site, Phase 46).
    Consumed by: ReportArtifactStore.load_run_bundle(), ReportRepository.latest_report().

    Artifact content is NOT stored in the database -- only the file path is
    persisted (SCALE-05: keeps the database lean, report files can be megabytes).
    The path column holds the absolute file path; the content column stores
    the same path as a string for legacy reasons.

    scope is "fleet" for the combined report or "target" for a per-system report.
    artifact_type is one of "csv", "summary_json", or "rows_json".

    The compound index on (run_id, scope, artifact_type) is used by
    ReportArtifactStore.load_run_bundle() to retrieve all artifacts for a
    run in a single query without a full table scan.
    """

    __table_args__ = (
        Index("ix_rar_run_scope_type", "run_id", "scope", "artifact_type"),
    )
    id: int | None = Field(default=None, primary_key=True)
    run_id: str = Field(index=True)
    scope: str = Field(index=True)
    system_id: int | None = Field(default=None, index=True)
    system_name: str | None = Field(default=None, index=True)
    host: str | None = Field(default=None, index=True)
    artifact_type: str = Field(index=True)
    path: str = Field(default="")
    content: str = Field(default="", sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class ArtifactRecord(TeamScopedMixin, SQLModel, table=True):
    """Generic artifact record for module-produced text or structured content.

    Written by: platform artifacts tool (artifacts.store).
    Consumed by: artifacts.search platform tool, agent knowledge retrieval.

    Unlike ReportArtifactRecord (which stores only file paths), ArtifactRecord
    can store the body content inline.  scope distinguishes module-level from
    target-scoped artifacts.  label is a human-readable identifier for search.
    metadata_json holds arbitrary structured metadata as a JSON string.
    """

    id: int | None = Field(default=None, primary_key=True)
    run_id: str | None = Field(default=None, index=True)
    module_id: str = Field(index=True)
    scope: str = Field(default="module", index=True)
    artifact_type: str = Field(index=True)
    label: str = Field(default="", index=True)
    target_name: str | None = Field(default=None, index=True)
    target_host: str | None = Field(default=None, index=True)
    content_type: str = Field(default="text/plain")
    body: str = Field(default="", sa_column=Column(Text))
    metadata_json: str = Field(default="{}", sa_column=Column(Text))
    created_at: datetime = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True), index=True,
    )
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class AuditEventRecord(TeamScopedMixin, SQLModel, table=True):
    """Immutable audit trail entry for a platform or module action.

    Written by: audit.log platform tool at any stage of a workflow run.
    Consumed by: compliance queries, operator audit review.

    Each record captures a (run_id, stage, action, target, status) tuple.
    details_json holds additional structured context.  user_id defaults to
    "system" for automated actions; operator-initiated actions set it explicitly.
    Records are immutable once written -- no UPDATE operations are performed.
    """

    id: int | None = Field(default=None, primary_key=True)
    run_id: str = Field(index=True)
    stage: str = Field(index=True)
    action: str
    status: str = Field(default="completed")
    target: str = Field(default="")
    user_id: str = Field(
        default="system",
        sa_column=Column("user_id", Text, server_default="system", index=True),
    )
    details_json: str = Field(default="{}", sa_column=Column(Text))
    created_at: datetime = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True), index=True,
    )


class AuditSealRecord(SQLModel, table=True):
    """Cryptographic seal record for LLM pipeline audit trail.

    Written by: seal pipeline step after every LLM call.
    Consumed by: compliance auditors via GET /audit/seals, operator review.

    Each record holds an HMAC-SHA256 digest computed over a canonical JSON
    payload that bundles the full pipeline chain output: classification,
    validation, confidence, and response hashes.  The seal_hash is verifiable
    with the HMAC key stored in ConfigRegistry.

    prompt_content and response_content are opt-in per task_type
    (llm_seal_store_content_{task_type} = "true" in ConfigRegistry).
    When not enabled, those fields remain NULL to avoid storing sensitive data.

    Pruning: expired records (created_at < now - retention_days) are deleted
    in the same DB session that inserts the new record. No background job.
    """

    __table_args__ = (
        Index("ix_auditsealrecord_created_at", "created_at"),
    )

    id: int | None = Field(default=None, primary_key=True)
    run_id: str = Field(index=True)
    seal_hash: str
    input_hash: str
    output_hash: str
    model_id: str
    task_type: str = Field(index=True)
    timestamp: datetime = Field(sa_type=DateTime(timezone=True))
    classification: str | None = None
    confidence: str | None = None
    evidence_validation_pass: bool | None = None
    content_stored: bool = Field(default=False)
    prompt_content: str | None = Field(default=None, sa_column=Column(Text))
    response_content: str | None = Field(default=None, sa_column=Column(Text))
    posture_mode: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    key_id: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    prompt_content_encrypted: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    response_content_encrypted: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class ReasoningGraphSnapshotRecord(SQLModel, table=True):
    """Durable graph snapshot emitted by the platform reasoning engine.

    Written by: platform reasoning engine consumers after each reasoning turn.
    Consumed by: reasoning graph query surfaces, analyst inspection, and future
    cross-domain replay flows.
    """

    __tablename__ = "reasoning_graph_snapshots"
    __table_args__ = (
        UniqueConstraint(
            "module_id",
            "subject_kind",
            "subject_id",
            "step_number",
            name="uq_reasoninggraphs_subject_step",
        ),
        Index("ix_reasoninggraphs_subject", "module_id", "subject_kind", "subject_id"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    run_id: str | None = Field(default=None, index=True)
    module_id: str = Field(index=True)
    subject_kind: str = Field(index=True)
    subject_id: str = Field(index=True)
    step_number: int = Field(index=True)
    strategy_family: str = Field(default="generic")
    graph_json: dict[str, Any] = Field(
        sa_column=Column("graph_json", JSONB, nullable=False)
    )
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class VerificationRecord(SQLModel, table=True):
    """Cross-model verification result for the LLM pipeline.

    Stores both models' evidence and verdicts when second-model verification
    is triggered by low confidence scores.  The second model receives the
    SAME original prompt (blind -- no first model output) to prevent
    anchoring bias.

    Written by: verify pipeline step when confidence < threshold.
    Consumed by: compliance auditors, operator review via /audit/verifications.

    disposition is one of "verified" (models agree) or "flagged_for_review"
    (models disagree).  final_verdict is the first model's verdict when they
    agree, or "REVIEW_REQUIRED" when they disagree.
    """

    __tablename__ = "verification_records"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    run_id: str = Field(index=True)
    task_type: str = Field(index=True)
    # First model
    first_model_id: str
    first_verdict: str = Field(sa_column=Column(Text))
    first_confidence: float
    first_evidence: str = Field(sa_column=Column(Text))
    # Second model (blind assessment)
    second_model_id: str
    second_verdict: str = Field(sa_column=Column(Text))
    second_confidence: float
    second_evidence: str = Field(sa_column=Column(Text))
    # Resolution
    agreement: bool
    disposition: str  # "verified" | "flagged_for_review"
    final_verdict: str = Field(sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class ConfigEntryRecord(SQLModel, table=True):
    """Typed configuration entry managed by ConfigRegistry.

    Written by: ConfigRegistry.register() (on first registration of a namespace)
    and ConfigRegistry.set() (explicit operator override).
    Consumed by: ConfigRegistry.get() (fallback after env var check).

    The resolution order for a given (namespace, key) is:
    1. AILA_{NAMESPACE}_{KEY} environment variable
    2. This table row
    3. Schema field default

    value_type enables safe casting on read (str/int/float/bool).
    """

    __table_args__ = (
        UniqueConstraint("namespace", "key", name="uq_configentryrecord_namespace_key"),
    )

    id: int | None = Field(default=None, primary_key=True)
    namespace: str = Field(index=True)
    key: str = Field(index=True)
    value: str = Field(sa_column=Column(Text))
    value_type: str = Field(default="str")
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class KnowledgeEntryRecord(SQLModel, table=True):
    """Vector-indexed knowledge entry for agent retrieval.

    Written by: agent knowledge injection during module register_tools().
    Consumed by: agent knowledge retrieval (pgvector cosine similarity + tsvector FTS).

    namespace is the agent class name (e.g. "ScoringAgent") per D-04.
    embedding is a 1024-dimensional vector stored as pgvector Vector(1024)
    and queried via cosine distance with HNSW index. Dimension matches
    the default embedding model BGE-M3 (BAAI/bge-m3).
    search_vector is a PostgreSQL tsvector generated column for full-text search,
    auto-maintained by PostgreSQL on INSERT/UPDATE.
    dedup_key prevents duplicate seeding of identical knowledge entries across
    restarts; NULL means no deduplication is applied.
    entry_metadata holds arbitrary JSON for display and filtering.
    """

    __table_args__ = (
        UniqueConstraint("namespace", "dedup_key", name="uq_knowledgeentryrecord_namespace_dedup_key"),
        Index(
            "ix_knowledge_embedding_hnsw",
            "embedding",
            postgresql_using="hnsw",
            postgresql_with={"m": 16, "ef_construction": 64},
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
        Index("ix_knowledge_search_vector", "search_vector", postgresql_using="gin"),
    )

    id: int | None = Field(default=None, primary_key=True)
    namespace: str = Field(index=True)
    content: str = Field(sa_column=Column(Text))
    embedding: Any = Field(sa_column=Column("embedding", Vector(1024)))
    search_vector: Any = Field(
        sa_column=Column(
            "search_vector",
            TSVECTOR,
            Computed("to_tsvector('english', content)", persisted=True),
        ),
        default=None,
    )
    entry_metadata: str = Field(default="{}", sa_column=Column("entry_metadata", Text))
    dedup_key: str | None = Field(default=None, sa_column=Column("dedup_key", Text, nullable=True, index=True))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class SeedVersionRecord(SQLModel, table=True):
    """Tracks which modules have run seed_data() and at what version.

    module_id: matches ModuleProtocol.module_id (e.g. 'vulnerability').
    seed_version: semver or date string; bump to re-seed on upgrade.
    seeded_at: timestamp of last successful seed run.
    """
    module_id: str = Field(primary_key=True)
    seed_version: str
    seeded_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


# Task queue -- platform-owned task lifecycle record
# Imported here so SQLModel.metadata registers TaskRecord when db_models is
# imported (which happens during init_db). The `as TaskRecord` + noqa F401
# idiom is the established re-export pattern in this codebase.
from aila.platform.tasks.models import TaskRecord


class UserRecord(TeamScopedMixin, SQLModel, table=True):
    """User account record for AILA REST API username/password authentication.

    Stores argon2id-hashed passwords (NOT bcrypt). The hashed_password field is
    NULL for OIDC-only accounts where no local password is set.

    Written by: POST /users (admin creates user), OIDC auto-provisioning.
    Consumed by: POST /auth/login (verify), user management endpoints.

    Per D-13: argon2id via argon2-cffi.
    Per D-17: admin-invite only -- no self-registration.
    Per D-18: RBAC with admin/operator/reader roles.
    Per D-20: soft-delete via is_active=false.
    """

    __tablename__ = "user_records"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    username: str = Field(index=True, unique=True, min_length=3, max_length=64)
    email: str | None = Field(default=None, sa_column=Column(Text, nullable=True, index=True))
    hashed_password: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    role: str = Field(
        default="operator",
        sa_column=Column(Text, server_default="operator", index=True),
    )
    group_id: str | None = Field(default=None, sa_column=Column(Text, nullable=True, index=True))
    is_active: bool = Field(default=True, index=True)
    oidc_sub: str | None = Field(default=None, sa_column=Column(Text, nullable=True, index=True))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    last_login_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))


class OIDCProviderRecord(SQLModel, table=True):
    """OIDC provider configuration for multi-provider authentication (Phase 177).

    Supports Microsoft Azure AD (tenant_id), Google OIDC (well-known
    autodiscovery), and generic OIDC (operator-supplied issuer_url). The
    client_secret is stored encrypted via the SecretStore pattern; the
    ``client_secret_encrypted`` column holds the SecretRecord id, never the
    plaintext.

    provider_type controls how the callback handler resolves endpoints:
        "microsoft" -> login.microsoftonline.com/{tenant_id}
        "google"    -> accounts.google.com (well-known)
        "generic"   -> issuer_url (well-known)

    Written by: POST /auth/oidc/providers (admin only).
    Consumed by: GET /auth/oidc/authorize (login flow).
    """

    __tablename__ = "oidc_provider_records"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    provider_name: str = Field(default="microsoft", index=True)
    provider_type: str = Field(
        default="microsoft",
        sa_column=Column(Text, server_default="microsoft", nullable=False),
    )
    display_name: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    tenant_id: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    issuer_url: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    client_id: str = Field(sa_column=Column(Text))
    client_secret_encrypted: str = Field(sa_column=Column(Text))
    scopes_json: str = Field(
        default='["openid","email","profile"]',
        sa_column=Column(Text, server_default='["openid","email","profile"]', nullable=False),
    )
    is_enabled: bool = Field(default=True)
    default_team_id: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class RefreshTokenRecord(TeamScopedMixin, SQLModel, table=True):
    """Refresh token record for user session management.

    Stores SHA-256 hash of issued refresh tokens (never the plaintext token).
    Per D-14: 7-day refresh token lifetime. Revocation via revoked_at timestamp.

    Written by: POST /auth/login, POST /auth/refresh.
    Consumed by: POST /auth/refresh (verify), POST /auth/logout (revoke).
    """

    __tablename__ = "refresh_token_records"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    user_id: str = Field(index=True)
    token_hash: str = Field(sa_column=Column(Text, unique=True))
    expires_at: datetime = Field(sa_type=DateTime(timezone=True))
    revoked_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    ip_address: str | None = Field(default=None, description="IP address at token creation")
    user_agent: str | None = Field(default=None, description="User-Agent header at token creation")


class ApiKeyRecord(TeamScopedMixin, SQLModel, table=True):
    """API key record for AILA REST API authentication.

    Stores bcrypt-hashed API keys issued to operators. The raw key is shown
    once on creation and never stored. The hashed_key is verified via
    pwdlib on each POST /auth/token request.

    key_id is a UUID string used as the `key_id` claim in JWTs. The token
    blacklist check (D-11) queries this table by key_id on every authenticated
    request; revoked_at being non-null means the key (and all its JWTs) are
    immediately invalid.

    key_prefix stores the first 12 characters of the raw key (e.g.
    `aila_sk_abcd`) so operators can identify which key to revoke via
    GET /auth/keys without exposing the full key.

    user_id links legacy API keys to a user account after migration (D-16/D-43).
    NULL user_id means the key predates user accounts and belongs to the
    auto-created admin user after first-boot migration.

    Written by: POST /auth/keys (API), aila create-api-key (CLI), AILA_BOOTSTRAP_KEY startup.
    Consumed by: POST /auth/token (verify), require_api_key (blacklist check).
    """

    __tablename__ = "apikeyrecord"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    hashed_key: str = Field(sa_column=Column(Text))
    key_prefix: str = Field(
        sa_column=Column(Text, index=True),
        description="First 12 chars of raw key for operator identification.",
    )
    role: str = Field(
        default="reader",
        sa_column=Column(Text, server_default="reader", index=True),
        description="admin | operator | reader",
    )
    label: str = Field(
        default="",
        sa_column=Column(Text, server_default=""),
        description="Optional human-readable label set at creation.",
    )
    created_by: str = Field(
        default="system",
        sa_column=Column(Text, server_default="system"),
        description="key_id of the admin key that created this, or 'cli' or 'bootstrap'.",
    )
    # user_id: nullable foreign reference to UserRecord. Set during first-boot migration (D-16/D-43).
    user_id: str | None = Field(default=None, sa_column=Column(Text, nullable=True, index=True))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    revoked_at: datetime | None = Field(default=None, nullable=True, sa_type=DateTime(timezone=True))


class SessionRecord(SQLModel, table=True):
    """Conversation session owned by a single API key user.

    Scoped by user_id so users never see other users' sessions (D-25).
    SSE streaming for session messages is handled via content negotiation (see api/routers/sessions.py).

    Written by: POST /sessions (API, TASK-02).
    Consumed by: GET /sessions, GET /sessions/{id}/messages (TASK-05).
    """

    __tablename__ = "session_records"
    __table_args__ = (Index("ix_sr_user_id", "user_id"),)

    id: str = Field(primary_key=True, default_factory=lambda: str(uuid4()))
    user_id: str = Field(sa_column=Column(Text, nullable=False))
    title: str = Field(default="Untitled", sa_column=Column(Text, server_default="Untitled"))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class SessionMessageRecord(SQLModel, table=True):
    """Single turn in a conversation session (user or assistant role).

    run_id is set when the assistant response triggered a background scan (D-13/TASK-06).
    Ordered by created_at for session replay (TASK-05).

    Written by: POST /sessions/{id}/messages (API, TASK-03).
    Consumed by: GET /sessions/{id}/messages (TASK-05).
    """

    __tablename__ = "session_message_records"
    __table_args__ = (Index("ix_smr_session_id", "session_id"),)

    id: str = Field(primary_key=True, default_factory=lambda: str(uuid4()))
    session_id: str = Field(sa_column=Column(Text, nullable=False))
    role: str = Field(sa_column=Column(Text, nullable=False))  # "user" | "assistant"
    content: str = Field(default="", sa_column=Column(Text, server_default=""))
    run_id: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class ExplainCacheRecord(SQLModel, table=True):
    """Cached LLM explanation for a vulnerability report.

    Cache-first pattern (D-17): GET /reports/{run_id}/explain checks this table.
    If cached, returns 200 + content. If not, enqueues explain task and returns 202.

    Written by: explain worker task on completion.
    Consumed by: GET /reports/{run_id}/explain (API).
    """

    __tablename__ = "explain_cache_records"
    __table_args__ = (Index("ix_ecr_run_id", "run_id", unique=True),)

    id: int | None = Field(default=None, primary_key=True)
    run_id: str = Field(sa_column=Column(Text, nullable=False))
    content: str = Field(default="", sa_column=Column(Text, server_default=""))
    cached_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


# ---------------------------------------------------------------------------
# Plan C endpoint support tables (D-32/D-33/D-35/D-40/D-41)
# ---------------------------------------------------------------------------


class NotificationRecord(SQLModel, table=True):
    """Platform notification record for per-user notification persistence.

    Written by: platform services that emit notifications.
    Consumed by: GET /notifications, GET /notifications/unread (RT-05).

    category is one of: info, warning, critical.
    """

    __tablename__ = "notification_records"
    __table_args__ = (
        Index("ix_notification_user_created", "user_id", "created_at"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    user_id: str = Field(index=True)
    title: str
    body: str = Field(default="", sa_column=Column(Text))
    category: str = Field(default="info", index=True)
    source_module: str | None = Field(default=None)
    source_entity_id: str | None = Field(default=None)
    is_read: bool = Field(default=False, index=True)
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    read_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))


class WidgetLayoutRecord(SQLModel, table=True):
    """Widget layout JSON blob per user (one record per user).

    Written by: PUT /widgets/layout.
    Consumed by: GET /widgets/layout (BE-04).
    """

    __tablename__ = "widget_layout_records"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    user_id: str = Field(index=True, unique=True)
    layout_json: str = Field(default="{}", sa_column=Column(Text))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class SavedFilterRecord(SQLModel, table=True):
    """User-saved filter configuration for entity list views.

    shared_with_team=True makes the filter visible to all users in the same group (D-41/D-42).
    Written by: POST /saved-filters.
    Consumed by: GET /saved-filters (BE-09).
    """

    __tablename__ = "saved_filter_records"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    user_id: str = Field(index=True)
    name: str
    entity_type: str = Field(index=True)
    filter_json: str = Field(default="{}", sa_column=Column(Text))
    is_pinned: bool = Field(default=False)
    shared_with_team: bool = Field(default=False)
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class ScheduledReportRecord(TeamScopedMixin, SQLModel, table=True):
    """Scheduled report configuration with cron expression.

    cron_expression is validated via croniter before storage (T-138-20).
    Written by: POST /scheduled-reports (admin only).
    Consumed by: GET /scheduled-reports, arq scheduler (BE-10).

    Team-scoped (#48-6): ``team_id`` is stamped from the creating
    principal. God-tier admins (team_id=NULL, TEAM-06) own NULL-team rows
    and see every row; a team-scoped admin sees and mutates only rows
    carrying its own team_id. The CRUD handlers resolve single resources
    by a team predicate, not a bare primary key.
    """

    __tablename__ = "scheduled_report_records"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    name: str
    report_type: str = Field(index=True)
    cron_expression: str
    recipient_emails_json: str = Field(default="[]", sa_column=Column(Text))
    config_json: str = Field(default="{}", sa_column=Column(Text))
    is_active: bool = Field(default=True, index=True)
    last_run_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    created_by: str = Field(index=True)
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class FindingWorkflowRecord(SQLModel, table=True):
    """Audit trail entry for finding workflow state transitions.

    State machine: new -> investigating -> mitigated -> verified -> closed.
    Written by: POST /findings/{id}/transition (operator+).
    Consumed by: GET /findings/{id}/workflow (BE-08).
    """

    __tablename__ = "finding_workflow_records"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    finding_id: str = Field(index=True)
    module_id: str = Field(index=True)
    current_state: str = Field(default="new", index=True)
    previous_state: str | None = Field(default=None)
    transitioned_by: str
    notes: str = Field(default="", sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class AssetTagVocabRecord(SQLModel, table=True):
    """Admin-managed tag key vocabulary (D-40).

    Operators may only assign tags whose tag_key exists in this vocabulary.
    Written by: POST /tags/vocabulary (admin only).
    Consumed by: POST /systems/{id}/tags (validation).
    """

    __tablename__ = "asset_tag_vocab_records"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    tag_key: str = Field(index=True, unique=True)
    description: str = Field(default="")
    is_system_default: bool = Field(default=False)
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


# ---------------------------------------------------------------------------
# Plan D network discovery tables (RADAR-01/RADAR-03/RADAR-04)
# ---------------------------------------------------------------------------


class ConfidenceDriftRecord(SQLModel, table=True):
    """Confidence drift tracking record per (target_name, task_type).

    Detects when LLM confidence for the same target drifts over time,
    indicating model degradation, prompt drift, or adversarial manipulation.
    The sliding window of recent confidence scores is stored as a JSON array
    for auditability.

    Written by: ConfidenceDriftTracker.record_and_check() after each seal step.
    Consumed by: /metrics (Prometheus gauges), operator alert review.

    drift_status is one of: "stable" (std_dev < 0.1), "degrading" (0.1-0.2),
    "volatile" (> 0.2), or "insufficient_data" (< 5 samples).
    """

    __tablename__ = "confidence_drift_records"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    target_name: str = Field(index=True)
    task_type: str = Field(index=True)
    window_size: int
    confidence_scores_json: str = Field(default="[]", sa_column=Column(Text))
    mean_confidence: float
    std_deviation: float
    drift_status: str  # "stable" | "degrading" | "volatile"
    alert_fired: bool = Field(default=False)
    computed_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class SystemPortRecord(SQLModel, table=True):
    """Open TCP/UDP listening ports per system collected via ss -tlnp.

    Written by: network_discovery_job (arq cron) via _persist_discovery_results.
    Consumed by: GET /topology (topology aggregation endpoint).

    Each scan overwrites previous results per system (D-09). is_stale=True means
    the system was unreachable during the last discovery attempt (D-10).
    """

    __tablename__ = "system_port_records"
    __table_args__ = (Index("ix_spr_system_id", "system_id"),)

    id: int | None = Field(default=None, primary_key=True)
    system_id: int = Field(index=True)
    port: int
    protocol: str = Field(default="tcp")
    local_address: str = Field(default="")
    process_name: str | None = Field(default=None)
    pid: int | None = Field(default=None)
    last_collected: datetime = Field(sa_type=DateTime(timezone=True))
    is_stale: bool = Field(default=False)


class SystemServiceRecord(SQLModel, table=True):
    """Running systemd services per system collected via systemctl list-units.

    Written by: network_discovery_job (arq cron) via _persist_discovery_results.
    Consumed by: GET /topology (topology aggregation endpoint).

    Each scan overwrites previous results per system (D-09). is_stale=True means
    the system was unreachable during the last discovery attempt (D-10).
    """

    __tablename__ = "system_service_records"
    __table_args__ = (Index("ix_ssr_system_id", "system_id"),)

    id: int | None = Field(default=None, primary_key=True)
    system_id: int = Field(index=True)
    service_name: str = Field(index=True)
    service_type: str = Field(default="systemd")
    state: str = Field(default="running")
    sub_state: str = Field(default="")
    last_collected: datetime = Field(sa_type=DateTime(timezone=True))
    is_stale: bool = Field(default=False)


class SystemConnectionRecord(SQLModel, table=True):
    """Active TCP connections between registered systems (topology edges).

    Written by: network_discovery_job (arq cron) via _persist_discovery_results.
    Consumed by: GET /topology (topology aggregation endpoint).

    Only connections between registered ManagedSystemRecords are stored (D-04).
    Each scan overwrites previous results for the source system (D-09).
    is_stale=True means the source system was unreachable (D-10).
    """

    __tablename__ = "system_connection_records"
    __table_args__ = (
        Index("ix_scr_source_id", "source_system_id"),
        Index("ix_scr_dest_id", "dest_system_id"),
    )

    id: int | None = Field(default=None, primary_key=True)
    source_system_id: int = Field(index=True)
    dest_system_id: int = Field(index=True)
    dest_ip: str = Field(default="")
    dest_port: int
    protocol: str = Field(default="tcp")
    state: str = Field(default="ESTABLISHED")
    last_collected: datetime = Field(sa_type=DateTime(timezone=True))
    is_stale: bool = Field(default=False)


class SystemMetadataRecord(SQLModel, table=True):
    """Per-system metadata collected during SSH discovery (Phase 176d).

    One row per managed system (unique on system_id). Populated by the
    network discovery job. Stores gateway info, external IP, and a
    neofetch-like system info snapshot. All fields are nullable so an
    unreachable or partially responsive host can still record what was
    collected.

    Written by: aila.platform.tasks.discovery._collect_system_network_data
    (extended in Phase 176d) during each scan cycle.
    Consumed by: GET /topology, RadarInspectPanel system detail view.
    """

    __tablename__ = "system_metadata_records"  # match migration 018
    __table_args__ = (
        UniqueConstraint("system_id", name="uq_system_metadata_record_system_id"),
    )

    id: int | None = Field(default=None, primary_key=True)
    system_id: int = Field(index=True)

    # Gateway / networking
    gateway_ip: str | None = Field(default=None)
    gateway_interface: str | None = Field(default=None)
    external_ip: str | None = Field(default=None)

    # Neofetch-like system info
    os_name: str | None = Field(default=None)
    os_pretty_name: str | None = Field(default=None)
    kernel: str | None = Field(default=None)
    cpu_cores: int | None = Field(default=None)
    memory_mb: int | None = Field(default=None)
    disk_gb: int | None = Field(default=None)
    uptime_seconds: int | None = Field(default=None)

    last_collected: datetime = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True)
    )
    is_stale: bool = Field(default=False)


# ---------------------------------------------------------------------------
# Phase 175: LLM cost intelligence models
# Re-exported here so Alembic auto-detection and SchemaRegistry see them.
# ---------------------------------------------------------------------------

from aila.platform.llm.cost_record import LLMCostRecord

# ---------------------------------------------------------------------------
# Phase 177: multi-team admin -- first-class team and member records.
# Existing team_id strings on team-scoped tables remain authoritative for
# isolation; TeamRecord exists so the admin UI can name, describe, and
# enumerate teams without scanning every table.
# ---------------------------------------------------------------------------


class TeamRecord(SQLModel, table=True):
    """A team with a stable UUID id and operator-supplied name.

    Written by: POST /admin/teams (admin only).
    Consumed by: GET/PUT/DELETE /admin/teams, TeamContext display.
    Soft-deleted via deleted_at so historical data keeps its foreign ids
    resolvable.
    """

    __tablename__ = "team_records"
    __table_args__ = (
        UniqueConstraint("name", name="uq_team_records_name"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    name: str = Field(sa_column=Column(Text, nullable=False, index=True))
    description: str = Field(default="", sa_column=Column(Text, server_default="", nullable=False))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    deleted_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))


class TeamMemberRecord(SQLModel, table=True):
    """Explicit membership edge between a user and a team.

    A user still has a primary ``team_id`` on UserRecord (used for JWT
    claims and request scoping); TeamMemberRecord additionally lets a
    user be associated with multiple teams at the admin layer.
    """

    __tablename__ = "team_member_records"
    __table_args__ = (
        UniqueConstraint("team_id", "user_id", name="uq_team_member_records_team_user"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    team_id: str = Field(sa_column=Column(Text, nullable=False, index=True))
    user_id: str = Field(sa_column=Column(Text, nullable=False, index=True))
    role: str = Field(
        default="operator",
        sa_column=Column(Text, nullable=False, server_default="operator"),
    )
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class PlatformJournalRecord(SQLModel, table=True):
    """One append-only, hash-chained event in the platform journal (C2).

    Rows are immutable: a BEFORE UPDATE OR DELETE trigger (migration 071)
    raises on any mutation. ``seq`` is monotonic within ``chain_id`` and
    orders the log; ``row_hash`` chains each row to its predecessor so a
    post-hoc rewrite is detectable via ``journal.verify_chain``.
    """

    __tablename__ = "platform_journal"
    # Composite time-ordered indexes below (ix_pj_kind_written,
    # ix_pj_team_kind_written, and the partial ix_pj_investigation /
    # ix_pj_run built in migration 071) are declared DESC on ``written_at``
    # / ``seq`` in the Alembic DDL; the Python-level Index entries here
    # cover the same column pairs ASC so SQLModel.metadata.create_all
    # (used by the test fixture) still builds a usable index. The ASC/DESC
    # divergence is benign and intentional -- mirrors the D-43 note on
    # WorkflowStateTransition.
    __table_args__ = (
        UniqueConstraint("journal_id", name="uq_platform_journal_journal_id"),
        CheckConstraint(
            # length() is portable (Postgres length(text) == char_length(text);
            # SQLite has length() but not char_length), so create_all works on
            # both the Postgres test DB and any SQLite-backed unit test.
            "length(row_hash) = 64 AND length(payload_hash) = 64",
            name="ck_platform_journal_hash_len",
        ),
        CheckConstraint(
            "chain_id LIKE 'team:%' OR chain_id = 'global'",
            name="ck_platform_journal_chain_id",
        ),
        Index("ix_pj_correlation", "correlation_id", "seq"),
        Index("ix_pj_kind_written", "kind", "written_at"),
        Index("ix_pj_team_kind_written", "team_id", "kind", "written_at"),
    )

    chain_id: str = Field(
        sa_column=Column(String(64), primary_key=True, nullable=False)
    )
    seq: int = Field(
        sa_column=Column(BigInteger, primary_key=True, autoincrement=False, nullable=False)
    )
    journal_id: str = Field(
        default_factory=lambda: str(uuid4()),
        sa_column=Column(String(36), nullable=False),
    )
    team_id: str | None = Field(
        default=None, sa_column=Column(String(36), nullable=True, index=True)
    )
    prev_hash: str | None = Field(default=None, sa_column=Column(String(64), nullable=True))
    row_hash: str = Field(sa_column=Column(String(64), nullable=False))
    payload_hash: str = Field(sa_column=Column(String(64), nullable=False))
    kind: str = Field(sa_column=Column(String(48), nullable=False))
    source: str = Field(sa_column=Column(String(128), nullable=False))
    actor_kind: str = Field(default="system", sa_column=Column(String(16), nullable=False))
    actor_id: str = Field(default="system", sa_column=Column(String(128), nullable=False))
    action: str = Field(sa_column=Column(String(128), nullable=False))
    status: str = Field(default="ok", sa_column=Column(String(16), nullable=False))
    run_id: str | None = Field(
        default=None, sa_column=Column(String(36), nullable=True)
    )
    investigation_id: str | None = Field(
        default=None, sa_column=Column(String(36), nullable=True)
    )
    branch_id: str | None = Field(
        default=None, sa_column=Column(String(36), nullable=True)
    )
    turn_number: int | None = Field(default=None, sa_column=Column(Integer, nullable=True))
    correlation_id: str = Field(sa_column=Column(String(64), nullable=False))
    parent_journal_id: str | None = Field(
        default=None, sa_column=Column(String(36), nullable=True)
    )
    payload_json: dict[str, Any] = Field(
        default_factory=dict, sa_column=Column(JSONB, nullable=False)
    )
    contains_secret: bool = Field(
        default=False,
        sa_column=Column(Boolean, nullable=False, server_default="false"),
    )
    schema_version: int = Field(
        default=1, sa_column=Column(SmallInteger, nullable=False, server_default="1")
    )
    occurred_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    written_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False, server_default=func.now()),
    )


class PlatformJournalDeadletterRecord(SQLModel, table=True):
    """Fallback destination for journal appends that could not chain (C2 0.2).

    Rows here are NOT chain-linked and NOT tamper-evident; operator review
    drains them into the main chain. Used only by ``append_or_deadletter``.
    """

    __tablename__ = "platform_journal_deadletter"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    chain_id: str = Field(sa_column=Column(String(64), nullable=False))
    team_id: str | None = Field(default=None, sa_column=Column(String(36), nullable=True))
    entry_json: dict[str, Any] = Field(
        default_factory=dict, sa_column=Column(JSONB, nullable=False)
    )
    failure_kind: str = Field(sa_column=Column(String(32), nullable=False))
    failure_detail: str = Field(sa_column=Column(Text, nullable=False))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    replayed_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    replay_seq: int | None = Field(default=None, sa_column=Column(BigInteger, nullable=True))

