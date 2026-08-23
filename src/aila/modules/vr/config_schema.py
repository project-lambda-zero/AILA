"""Configuration schema for the VR (vulnerability research) module.

Registered with ConfigRegistry under the ``vr`` namespace.
Operators can tune these values via PUT /config without code changes.

NOTE: These defaults are used as fallbacks. Per-request overrides on the
API layer take priority when explicitly set. Timeout values here define
the upper bounds for PoC execution and SSH operations on remote analysis
hosts. Changing config at runtime does NOT hot-reload into running
workflows; only new workflow runs pick up updated values.
"""
from __future__ import annotations

from pydantic import Field

from aila.platform.config_base import ModuleConfigBase

__all__ = ["VRConfigSchema", "VR_DEFAULTS"]


class VRConfigSchema(ModuleConfigBase):
    """Operator-tunable settings for the VR module.

    ``llm_model`` is inherited from :class:`ModuleConfigBase` -- the
    VR module's historical default matched the platform default
    (``PlatformConfigSchema.llm_default_model``), so no per-module
    override is needed.
    """

    nday_max_turns: int = Field(
        default=30,
        ge=5,
        le=100,
        description="Maximum agent turns per N-day PoC investigation loop.",
    )
    nday_tool_time_seconds: float = Field(
        default=14400.0,
        ge=300.0,
        description=(
            "Wall-clock budget for the N-day agent's tool-use phase, in seconds. "
            "Default 4 hours accommodates long IDA analysis and PoC iteration."
        ),
    )
    poc_max_attempts: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Maximum PoC build/run iterations before giving up.",
    )
    poc_reliability_target: str = Field(
        default="5/5",
        description=(
            "Required PoC reliability ratio (successful_runs/total_runs) before "
            "the PoC is considered acceptance-ready."
        ),
    )
    poc_timeout_seconds: float = Field(
        default=30.0,
        ge=5.0,
        le=300.0,
        description="Per-execution timeout for PoC binary runs.",
    )
    poc_memory_limit_mb: int = Field(
        default=2048,
        ge=256,
        le=16384,
        description="Memory cap for sandboxed PoC execution, in megabytes.",
    )
    poc_workspace_max_age_minutes: int = Field(
        default=60,
        ge=1,
        le=10080,
        description=(
            "Age cap on per-run workspace subdirectories under "
            "/tmp/aila_vr on the analyzer workstation. Subdirectories "
            "older than this are removed by the prune pass every "
            "compile_poc invocation so an orphaned workspace from a "
            "crashed workflow does not accumulate. Read live via "
            "ConfigRegistry so PUT /config/vr/* lands on the next "
            "compile without a worker restart."
        ),
    )
    poc_workspace_max_total_mb: int = Field(
        default=512,
        ge=1,
        le=65536,
        description=(
            "Total-size cap in megabytes on the shared /tmp/aila_vr "
            "workspace root on the analyzer workstation. The prune "
            "pass at each compile_poc removes oldest per-run "
            "subdirectories first until the tree fits under this cap. "
            "Bounds workspace growth even when individual runs never "
            "call cleanup_workspace explicitly."
        ),
    )
    ssh_command_timeout_seconds: float = Field(
        default=300.0,
        ge=10.0,
        description="Timeout for individual SSH commands on remote analysis hosts.",
    )
    audit_mcp_url: str = Field(
        default="http://127.0.0.1:18822",
        description=(
            "Base URL for the audit-mcp source-code MCP server. The platform "
            "delegates ALL clone/index/graph work to this server (D-33). Point "
            "at a dedicated Linux workstation for production."
        ),
    )
    ida_headless_url: str = Field(
        default="http://127.0.0.1:18821",
        description=(
            "Base URL for the IDA headless MCP server. The platform delegates "
            "ALL binary upload/analysis to this server (D-33). Point at the "
            "workstation that owns the IDA license + GPU."
        ),
    )
    android_mcp_url: str = Field(
        default="http://127.0.0.1:18823",
        description=(
            "Base URL for the android-mcp Android APK audit server. The "
            "platform delegates ALL apktool/jadx work to "
            "this server (D-33). Point at the workstation that owns the "
            "Android SDK build-tools."
        ),
    )

    # Investigation lifecycle caps (operator-tunable). Previously read
    # via VR_* env vars scattered across branch_manager / claim_verifier /
    # parent_reconciler / investigation_finalizers / target_analysis /
    # investigation_loop; those reads ignored PUT /config overrides.
    max_branches_per_investigation: int = Field(
        default=24,
        ge=1,
        le=256,
        description=(
            "Per-investigation ACTIVE-branch cap. Enforced inside the fork "
            "UoW so concurrent forks racing on the same investigation see "
            "each other's inserts. 24 = 6 personas * 4 fork generations."
        ),
    )
    claim_verifier_auto_promote_floor: float = Field(
        default=0.70,
        ge=0.0,
        le=1.0,
        description=(
            "Confidence floor for auto-promoting a verifier-confirmed "
            "ASSESSMENT_REPORT to DIRECT_FINDING. 0.70 matches the "
            "synthesis pipeline's medium/high threshold."
        ),
    )
    investigation_total_turn_cap: int = Field(
        default=200,
        ge=50,
        description=(
            "Total turn cap per audit child investigation (sum across "
            "branches). Children whose sum exceeds this are force-closed "
            "by the parent reconciler."
        ),
    )
    stale_branch_frozen_min: int = Field(
        default=30,
        ge=1,
        description=(
            "Minutes of inactivity before an ACTIVE branch with "
            "turn_count < 5 is abandoned as dead-from-birth."
        ),
    )
    stale_branch_halted_min: int = Field(
        default=120,
        ge=1,
        description=(
            "Minutes of inactivity before an ACTIVE branch with "
            "turn_count >= 5 is abandoned as halted mid-run."
        ),
    )
    ingestion_poll_timeout_s: float = Field(
        default=14400.0,
        ge=60.0,
        description=(
            "Wall-clock timeout for ingestion polling (IDA analysis + "
            "audit_mcp index build). Default 4h fits chromium / firefox / "
            "large monorepos; smaller targets finish long before."
        ),
    )
    max_turns_per_task: int = Field(
        default=70,
        ge=1,
        description=(
            "Per-ARQ-task turn budget for state_investigation_loop. Loop "
            "returns on this cap; investigation_emit re-enqueues another "
            "task until the investigation-level turn cap is reached."
        ),
    )
    oracle_specialist_adjudication: int = Field(
        default=1,
        ge=0,
        le=1,
        description=(
            "When 1, the oracle LLM-judges open request_specialist entries "
            "each spawn cycle and ratifies the warranted ones itself, so a "
            "specialist spawns even when no distinct sibling branch casts "
            "the ratifying vote. Set 0 to require a sibling vote (the prior "
            "RFC-13 behavior)."
        ),
    )

    # --- Agent submit-gate caps (operator-tunable) -----------------------
    # Resolved at the USE site via ConfigRegistry (namespace=vr) so a PUT
    # /config override lands on the next turn without a worker restart. The
    # prior code read raw VR_* env vars at import; those names are retired,
    # replaced by the standard AILA_VR_<KEY> env form.
    variant_hunt_reject_cap: int = Field(
        default=8,
        ge=1,
        description=(
            "Consecutive variant-hunt submit rejections on a branch before "
            "the gate forces the submit through with a variant_hunt_advisory "
            "flag stamped on the payload. Raised from 3 to 8: the prior cap "
            "let a submit-happy agent exit after ~2-3 probes; branches were "
            "measured emitting ~4 empty submits per real tool call. The extra "
            "runway keeps the branch active long enough to reach the "
            "investigation depth floor below."
        ),
    )
    variant_hunt_min_tool_investigations: int = Field(
        default=8,
        ge=0,
        description=(
            "Minimum number of successful audit/binary tool probes "
            "(audit_mcp / ida_headless / knowledge readings recorded on the "
            "branch case_state) a variant-hunt branch is expected to have run "
            "before a no-finding / empty-orders submit is credible. Below "
            "this floor the submit gate injects an INVESTIGATION-TOO-SHALLOW "
            "directive naming the current probe count and instructing the "
            "agent's next action to be a concrete tool_run on an unprobed "
            "candidate. It does not hard-block (the reject_cap force-through "
            "still bounds the loop); it re-weights the agent away from "
            "premature exit. 0 disables the depth check."
        ),
    )
    unresolved_hyp_reject_cap: int = Field(
        default=10,
        ge=1,
        description=(
            "Consecutive unresolved-live-hypothesis submit rejections before "
            "the graceful-stop gate forces the submit through, stamping the "
            "surviving hypothesis ids on the payload as an advisory. Raised "
            "from 3 to 10: a branch must not be able to stop by out-waiting "
            "the gate -- the escape is to resolve each hypothesis (reject "
            "with evidence or fold into the finding), not to retry submit."
        ),
    )
    draft_pending_reject_cap: int = Field(
        default=3,
        ge=1,
        description=(
            "Consecutive draft-pending submit rejections on a branch before "
            "the gate forces the submit through, stamping the unvoted draft "
            "ids on the payload as a draft_pending_advisory. Without this "
            "cap the same branch can be rejected forever if the pending "
            "draft never assembles quorum, burning its whole turn budget."
        ),
    )
    sibling_open_hyp_reject_cap: int = Field(
        default=3,
        ge=1,
        description=(
            "Consecutive no_finding / inconclusive submit rejections on a "
            "branch while a sibling still holds a live hypothesis no branch "
            "has rejected. Above the cap the gate forces the submit through, "
            "stamping ``payload.sibling_open_hyp_advisory`` with the sibling "
            "branch id(s) + open hypothesis id(s) so the operator can audit "
            "the closure gap. Without this cap a branch that genuinely has "
            "nothing left to hunt could be blocked forever by a slow "
            "sibling that never resolves its own hypothesis."
        ),
    )
    tool_executor_hard_block_repeat: int = Field(
        default=3,
        ge=1,
        description=(
            "Identical-args tool-call failures before the executor "
            "hard-blocks the dispatch pre-call. Retries below this still "
            "reach the bridge."
        ),
    )
    core_persona_siblings: str = Field(
        default="maddie,renzo",
        description=(
            "Comma-separated persona voices spawned as the core panel "
            "siblings, in addition to the halvar primary (researcher). The "
            "baseline is the 3-role spine: maddie (critic) + renzo "
            "(implementer). Optional specialist agents are spawned on demand "
            "via the oracle, not listed here. Unknown names are skipped."
        ),
    )

    # --- Cap-exceeded reaper (operator-tunable) --------------------------
    # The four caps below drive aila.modules.vr.services.investigation_reaper
    # (which now routes through ConfigRegistry so PUT /config overrides land
    # on the next tick without a worker restart). The prior code read raw
    # VR_* env vars and ignored operator overrides; those names are
    # retired, replaced by the standard AILA_VR_<KEY> env form.
    overall_turn_cap: int = Field(
        default=500,
        ge=10,
        le=10000,
        description=(
            "Per-branch cap on cumulative turns across task boundaries. "
            "The emit auto-continue stops re-enqueuing a branch once its "
            "turn_count reaches this. Read live via ConfigRegistry "
            "(env AILA_VR_OVERALL_TURN_CAP -> DB -> this default), "
            "replacing the retired module-load VR_OVERALL_TURN_CAP env."
        ),
    )
    investigation_turn_cap: int = Field(
        default=300,
        ge=10,
        le=10000,
        description=(
            "Investigation-wide cap on cumulative reasoning turns "
            "(sum across branches). Trips the cap-exceeded path in the "
            "periodic reaper + workflow finalize chokepoint."
        ),
    )
    investigation_message_cap: int = Field(
        default=1000,
        ge=10,
        le=100000,
        description=(
            "Investigation-wide hard cap on messages emitted across all "
            "branches. Trips the cap-exceeded path in workflow finalize."
        ),
    )
    investigation_wall_clock_hours: float = Field(
        default=144.0,
        ge=0.5,
        le=336.0,
        description=(
            "Investigation-wide wall-clock budget in hours before the "
            "finalize chokepoint flips the investigation to a cap-exceeded "
            "terminal."
        ),
    )
    wall_clock_idle_grace_s: float = Field(
        default=900.0,
        ge=30.0,
        le=86400.0,
        description=(
            "Idle-grace window in seconds the finalize chokepoint waits "
            "after the wall-clock cap is hit before terminating, so an "
            "investigation that is actively producing work doesn't get "
            "killed for a slow turn."
        ),
    )

    # --- Filesystem paths for MCP output storage (RFC-04 C11e) ------------
    # Previously read from raw ``VR_TARGET_ARTIFACT_DIR`` /
    # ``ANDROID_MCP_WORKDIR`` env vars at module import. Now routed
    # through ConfigRegistry so PUT /config overrides land without a
    # worker restart and the env form is standardised to
    # ``AILA_VR_TARGET_ARTIFACT_DIR`` / ``AILA_VR_ANDROID_MCP_WORKDIR``.
    target_artifact_dir: str = Field(
        default="",
        description=(
            "Root dir for heavy per-target MCP output payloads (currently "
            "the android-mcp static summary written by target_analysis). "
            "Empty string falls back to ``~/.aila/vr_target_artifacts``; "
            "set to a shared path when multiple workers must resolve the "
            "same artifact pointers stored in ``mcp_handles_json``."
        ),
    )
    android_mcp_workdir: str = Field(
        default="~/.android-mcp/work",
        description=(
            "android-mcp working directory the VR module builds unified "
            "APK staging trees under (``apk-unified-<sha>/`` with links "
            "to the jadx + RN + apktool outputs). ``~`` is expanded at "
            "read time. Change per-workstation to move staging off the "
            "default home-dir location."
        ),
    )

    # --- Upload guard (#57: input-size DoS on target/APK uploads) ---------
    upload_max_bytes: int = Field(
        default=512 * 1024 * 1024,  # 512 MiB
        ge=1024,
        le=16 * 1024 * 1024 * 1024,  # hard ceiling 16 GiB
        description=(
            "Per-request byte cap the VR upload endpoints enforce while "
            "streaming the body (POST /vr/targets/{id}/upload for raw "
            "binaries; POST /vr/targets/upload-apk for APKs). Bodies past "
            "this cap fail with HTTP 413 mid-stream so a chunked upload "
            "that omits Content-Length cannot OOM the worker (the global "
            "Content-Length middleware misses those). Env: "
            "AILA_VR_UPLOAD_MAX_BYTES."
        ),
    )


    # --- RFC-07 #31 stuck-investigation healer ---------------------------
    stuck_healer_idle_grace_s: int = Field(
        default=600,
        ge=30,
        description=(
            "Idle grace before an investigation stuck at ``running`` is a "
            "candidate for the RFC-07 stuck-investigation healer, in "
            "seconds. Rows whose ``updated_at`` is fresher than this are "
            "never touched so a slow turn is not mistaken for a stall. "
            "Env: AILA_VR_STUCK_HEALER_IDLE_GRACE_S."
        ),
    )
    stuck_healer_max_heals_per_tick: int = Field(
        default=5,
        ge=1,
        le=50,
        description=(
            "Per-tick cap on stuck-investigation re-enqueues so a mass "
            "backlog cannot saturate the task queue in one sweep. "
            "Env: AILA_VR_STUCK_HEALER_MAX_HEALS_PER_TICK."
        ),
    )

    # --- Fuzz -> source-investigation feedback loop (#173/#148) ----------
    fuzz_coverage_emit_delta_pct: float = Field(
        default=5.0,
        ge=0.1,
        le=100.0,
        description=(
            "Coverage-percentage delta (in percentage points) that "
            "patch_campaign must observe against the campaign's "
            "``last_coverage_emitted_pct`` before a fuzz.coverage_delta "
            "event is posted to the source investigation. Default 5.0 "
            "keeps the reasoning loop from being spammed on noisy sub- "
            "percent jitter. Env: AILA_VR_FUZZ_COVERAGE_EMIT_DELTA_PCT."
        ),
    )
    fuzz_reproducer_local_root: str = Field(
        default="",
        description=(
            "Absolute local directory that the fuzz-crash ingest is "
            "permitted to read reproducer bytes from (issue #183). The "
            "``POST /vr/fuzz/crashes`` handler stores the first 4 KiB of "
            "the reproducer as a hex preview; without a configured root "
            "the file open would follow any local path an authenticated "
            "caller supplies. When empty the head-preview is disabled "
            "fail-closed (the crash still records, only the hex preview "
            "is empty). When set, ``reproducer_path`` is resolved via "
            "``Path.resolve()`` (following symlinks) and MUST land under "
            "this root; anything else is refused and logged. "
            "Env: AILA_VR_FUZZ_REPRODUCER_LOCAL_ROOT."
        ),
    )
    fuzz_crash_spawn_child: bool = Field(
        default=False,
        description=(
            "When True AND a SECURITY_RELEVANT crash lands on a campaign "
            "linked back to a source investigation, register_crash also "
            "enqueues a child VR investigation targeting the crash's "
            "reproducer (parent_investigation_id = the source). The "
            "primary loop-closer stays the steering message; this knob "
            "is opt-in because auto-spawn multiplies the fan-out of the "
            "child investigation graph. Default OFF. Env: "
            "AILA_VR_FUZZ_CRASH_SPAWN_CHILD."
        ),
    )

    # fix #132 -- knobs previously read via bare ``os.environ.get`` at
    # the ``vr/api_router.py`` and ``vr/reporting/pdf_report.py`` call
    # sites. Routing them through this schema unlocks ``PUT /config``
    # and audit logging; the env spellings become ``AILA_VR_*`` per
    # the standard ConfigRegistry layered lookup.
    masvs_audit_batch_size: int = Field(
        default=5,
        ge=1,
        le=200,
        description=(
            "MASVS audit fan-out ceiling per parent. Enqueues at most "
            "this many child audits at once for APK targets to protect "
            "the shared LLM proxy from OOM; the parent reconciler "
            "enqueues the next slice as slots free. Env: "
            "AILA_VR_MASVS_AUDIT_BATCH_SIZE."
        ),
    )
    android_mcp_upload_dir: str = Field(
        default="",
        description=(
            "Root directory for android-mcp APK uploads. Empty (default) "
            "resolves to ``~/.android-mcp/uploads``. Team subdirs are "
            "created lazily under this root. Env: "
            "AILA_VR_ANDROID_MCP_UPLOAD_DIR."
        ),
    )
    audit_mcp_clone_dir: str = Field(
        default="",
        description=(
            "Root directory holding audit-mcp source clones consumed by "
            "the VR PDF reporter. Empty (default) resolves to "
            "``~/.cache/audit-mcp/clones``. Env: "
            "AILA_VR_AUDIT_MCP_CLONE_DIR."
        ),
    )


VR_DEFAULTS = VRConfigSchema()
