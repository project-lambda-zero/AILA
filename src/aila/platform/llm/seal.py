"""Audit sealing pipeline step for LLM calls.

Computes an HMAC-SHA256 seal over the full pipeline chain output for every
LLM call that reaches the seal step.  The seal covers classification,
validation, confidence, and response data in a single cryptographic digest.

The seal step is purely observational: it reads ctx and messages but never
modifies them.  It writes ctx["seal_id"] and persists an AuditSealRecord
to the database.

Expired seal records are pruned on each write using a single DELETE WHERE
clause -- no background job needed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import sqlalchemy.exc
from cryptography.exceptions import InvalidTag

if TYPE_CHECKING:
    from ..events.emitter import EventEmitter
    from .config import LLMConfigProvider, LLMRouting

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pure function: HMAC-SHA256 seal computation (D-01, D-02, D-03)
# ---------------------------------------------------------------------------


def compute_key_id(hmac_key: str) -> str:
    """Derive a short key identifier from the HMAC key.

    Returns the first 8 hex characters of SHA-256(key).  This allows
    matching seal records to the key version that produced them without
    exposing the key itself, enabling key rotation auditing.
    """
    return hashlib.sha256(hmac_key.encode()).hexdigest()[:8]


def compute_seal(
    *,
    messages: list[dict[str, Any]],
    response_content: str,
    model_id: str,
    timestamp: str,
    classification: str | None,
    confidence: str | None,
    evidence_validation_pass: bool | None,
    task_type: str,
    hmac_key: str,
    posture_mode: str = "standard",
    key_id: str | None = None,
) -> tuple[str, str, str]:
    """Compute HMAC-SHA256 seal over canonical payload.

    Args:
        messages: OpenAI-format message list (input to the LLM call).
        response_content: Raw text content of the LLM response.
        model_id: The model_id used for the call.
        timestamp: ISO 8601 UTC timestamp string.
        classification: Classification level from classify step (may be None).
        confidence: Confidence level from gate step (may be None).
        evidence_validation_pass: Boolean from validate step (may be None).
        task_type: The task_type routing key.
        hmac_key: Hex-encoded HMAC secret key.
        posture_mode: Data posture mode active during this call (Phase 173).
        key_id: Short identifier of the HMAC key used (first 8 hex of SHA-256).

    Returns:
        Tuple of (seal_hash, input_hash, output_hash).
    """
    input_hash = hashlib.sha256(
        json.dumps(messages, sort_keys=True).encode()
    ).hexdigest()

    output_hash = hashlib.sha256(
        response_content.encode()
    ).hexdigest()

    payload = {
        "classification": classification,
        "confidence": confidence,
        "evidence_validation_pass": evidence_validation_pass,
        "input_hash": input_hash,
        "key_id": key_id,
        "model_id": model_id,
        "output_hash": output_hash,
        "posture_mode": posture_mode,
        "task_type": task_type,
        "timestamp": timestamp,
    }

    canonical = json.dumps(payload, sort_keys=True).encode()
    seal_hash = hmac.new(
        hmac_key.encode("utf-8"),
        canonical,
        hashlib.sha256,
    ).hexdigest()

    return seal_hash, input_hash, output_hash


# ---------------------------------------------------------------------------
# Config helpers (D-04, D-12)
# ---------------------------------------------------------------------------


async def _resolve_hmac_key(config_provider: LLMConfigProvider) -> str:
    """Read or auto-generate the HMAC key from ConfigRegistry.

    If no key is set, generates a 32-byte random key via secrets.token_hex(32)
    and stores it in ConfigRegistry for persistence across restarts.
    """
    registry = config_provider._registry
    val = await registry.get("platform", "llm_seal_hmac_key")
    if val is not None and str(val).strip():
        return str(val)
    # Auto-generate and store (D-04)
    key = secrets.token_hex(32)
    await registry.set("platform", "llm_seal_hmac_key", key)
    return key


async def _resolve_retention_days(config_provider: LLMConfigProvider) -> int:
    """Read retention days from ConfigRegistry. Default: 90."""
    registry = config_provider._registry
    val = await registry.get("platform", "llm_seal_retention_days")
    if val is not None:
        try:
            return int(val)
        except (ValueError, TypeError):
            pass
    return 90


# ---------------------------------------------------------------------------
# Audit event emission (D-20)
# ---------------------------------------------------------------------------


def _emit_seal_event(
    ctx: dict[str, Any],
    routing: LLMRouting,
    seal_hash: str,
    content_stored: bool,
    emitter: EventEmitter | None,
) -> None:
    """Emit llm_audit_seal audit event."""
    if emitter is None:
        return

    from ..events.event import PlatformEvent

    emitter.emit(
        PlatformEvent(
            stage="llm_audit_seal",
            action="seal",
            key=f"llm.seal.{ctx['task_type']}",
            message=f"Seal computed: {seal_hash[:16]}...",
            details={
                "task_type": ctx["task_type"],
                "model_id": routing.model_id,
                "seal_hash": seal_hash,
                "content_stored": content_stored,
                "posture_mode": ctx.get("posture_mode", "standard"),
                "run_id": ctx.get("run_id", ""),
            },
        )
    )


# ---------------------------------------------------------------------------
# Pipeline step factory (D-18, D-19)
# ---------------------------------------------------------------------------


def make_seal_step(
    config_provider: LLMConfigProvider,
    emitter: EventEmitter | None = None,
) -> Any:
    """Create the seal pipeline step closure.

    The returned async callable matches the StepFn protocol:
    ``async def step(ctx, messages, routing) -> None``.

    The seal step is purely observational -- it computes a cryptographic
    seal over the pipeline chain output and stores it.  It never modifies
    ctx["response"] or messages.

    Args:
        config_provider: LLMConfigProvider for HMAC key and retention config.
        emitter: Optional EventEmitter for audit logging.

    Returns:
        Async step function for pipeline registration.
    """

    async def _seal_step(
        ctx: dict[str, Any],
        messages: list[dict[str, Any]],
        routing: LLMRouting,
    ) -> None:
        # Guard: no response to seal
        response = ctx.get("response")
        if response is None:
            logger.warning("Seal step: no response in ctx, skipping")
            return

        response_content = response.content if response.content else ""

        # Resolve HMAC key (read from config on each call, no caching)
        key = await _resolve_hmac_key(config_provider)

        # Build timestamp
        ts = datetime.now(UTC).isoformat()

        # Read pipeline chain outputs from ctx (D-08, D-09)
        posture_mode = ctx.get("posture_mode", "standard")
        classification = ctx.get("classification")

        # Extract evidence_validation_pass from validation dict
        evidence_validation = ctx.get("evidence_validation")
        evidence_validation_pass: bool | None = None
        if isinstance(evidence_validation, dict):
            # EvidenceValidationReport serialized via dataclasses.asdict()
            # has "overall_pass" key
            evidence_validation_pass = evidence_validation.get("overall_pass")

        confidence = ctx.get("confidence")

        # Derive key_id for rotation tracking (LLM-SEC-02)
        kid = compute_key_id(key)

        # Compute seal (D-01, D-02, D-03)
        seal_hash, input_hash, output_hash = compute_seal(
            messages=messages,
            response_content=response_content,
            model_id=routing.model_id,
            timestamp=ts,
            classification=classification,
            confidence=confidence,
            evidence_validation_pass=evidence_validation_pass,
            task_type=ctx["task_type"],
            hmac_key=key,
            posture_mode=posture_mode,
            key_id=kid,
        )

        # Check content storage opt-in (D-10)
        store_content_val = await config_provider._registry.get(
            "platform",
            f"llm_seal_store_content_{ctx['task_type']}",
        )
        content_stored = (
            store_content_val is not None
            and str(store_content_val).strip().lower() == "true"
        )

        # Encrypt content if storage is opted-in and HMAC key is available (LLM-SEC-03)
        # Encrypt-on-write only: new records get encrypted content, old plaintext stays.
        # Graceful degradation: if encryption fails, fall back to plaintext storage.
        prompt_text = json.dumps(messages, sort_keys=True) if content_stored else None
        response_text = response_content if content_stored else None
        prompt_encrypted: str | None = None
        response_encrypted: str | None = None

        if content_stored and key:
            try:
                from .encrypt import derive_encryption_key, encrypt_content

                enc_key = derive_encryption_key(key)
                if prompt_text:
                    prompt_encrypted = encrypt_content(prompt_text, enc_key)
                if response_text:
                    response_encrypted = encrypt_content(response_text, enc_key)
                # Clear plaintext when encryption succeeds
                prompt_text = None
                response_text = None
            except (ValueError, InvalidTag):
                # Graceful degradation: store plaintext if encryption fails
                logger.warning(
                    "Seal step: content encryption failed, falling back to plaintext",
                    exc_info=True,
                )
                prompt_encrypted = None
                response_encrypted = None

        # Build AuditSealRecord
        from ...storage.db_models import AuditSealRecord
        from .correlation import current_prompt_content_hash

        record = AuditSealRecord(
            run_id=ctx.get("run_id", ""),
            seal_hash=seal_hash,
            input_hash=input_hash,
            output_hash=output_hash,
            model_id=routing.model_id,
            task_type=ctx["task_type"],
            prompt_content_hash=current_prompt_content_hash(),
            timestamp=datetime.fromisoformat(ts),
            classification=classification,
            confidence=confidence,
            evidence_validation_pass=evidence_validation_pass,
            content_stored=content_stored,
            prompt_content=prompt_text,
            response_content=response_text,
            prompt_content_encrypted=prompt_encrypted,
            response_content_encrypted=response_encrypted,
            posture_mode=posture_mode,
            key_id=kid,
        )

        # Write to DB and prune expired records (D-13, D-14)
        retention_days = await _resolve_retention_days(config_provider)

        from sqlmodel import delete as sqlmodel_delete

        from ...storage.database import async_session_scope

        async with async_session_scope() as session:
            session.add(record)
            # Prune expired records in same session
            cutoff = datetime.now(UTC) - timedelta(days=retention_days)
            stmt = sqlmodel_delete(AuditSealRecord).where(
                AuditSealRecord.created_at < cutoff  # type: ignore[operator]
            )
            await session.exec(stmt)  # type: ignore[call-overload]
            await session.commit()

        # Write seal_id to ctx (D-19) -- flows to LLMResponse.seal_id via _enrich_response
        ctx["seal_id"] = seal_hash

        # Emit audit event (D-20)
        _emit_seal_event(ctx, routing, seal_hash, content_stored, emitter)

        # Confidence drift tracking (LLM-SEC-04)
        # Runs after seal record is committed.  Failure must NOT break the
        # seal step -- drift tracking is observational only.
        try:
            from .drift import ConfidenceDriftTracker

            # Read numeric confidence_score from gate step's pipeline_metadata
            # (ctx["pipeline_metadata"]["confidence_gating"]["confidence_score"])
            drift_score = 0.0
            pipeline_meta = ctx.get("pipeline_metadata")
            if isinstance(pipeline_meta, dict):
                gating = pipeline_meta.get("confidence_gating")
                if isinstance(gating, dict):
                    raw = gating.get("confidence_score")
                    if raw is not None:
                        drift_score = float(raw)

            if drift_score > 0:
                target_name = ctx.get("target_name", "") or ctx.get("run_id", "")
                tracker = ConfidenceDriftTracker()
                drift_result = await tracker.record_and_check(
                    target_name=target_name,
                    task_type=ctx["task_type"],
                    confidence_score=drift_score,
                )
                ctx["drift_status"] = drift_result.status
        except sqlalchemy.exc.SQLAlchemyError:
            logger.debug("Drift tracking failed, continuing", exc_info=True)

    return _seal_step
