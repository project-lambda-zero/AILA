"""Persist investigation findings as first-class ``ArtifactRecord`` rows.

When an investigation submits an answer the agent has accumulated:

  - ``observables``  -- free-form structured key/value findings the
    agent recorded across turns (e.g. ``trigger_file=musk.jpg.lnk``,
    ``capa_capabilities=[...]``, ``c2_endpoint=10.26.33.40``).
  - ``provenance``   -- ``primary_artifact`` path + ``corroboration``
    list pointing at the evidence that backs the answer.
  - ``contract``     -- answer_type / answer_format / evidence_domain.

This module classifies those observables into a small, fixed set of
artifact types and writes them into ``forensics_artifacts`` so the
Artifacts tab can show "what each investigation discovered" alongside
intake/full-analysis findings.

Rules:
  * Only types whose required keys are present are emitted (no guessing).
  * One ``investigation_summary`` row per submitted answer (always).
  * Each row carries ``source_tool="investigator"`` and
    ``source_investigation_id=<inv id>`` so the API can filter on it.
  * Persistence runs in its own UoW with broad exception suppression so
    a write failure NEVER kills the investigation.
  * Idempotent within a project: ``(artifact_type, sha256(data_json))``
    duplicates are skipped.

Public surface:
  - :func:`persist_investigation_artifacts`
"""
from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from sqlmodel import select

from aila.modules.forensics.db_models.artifact import ArtifactRecord
from aila.platform.exceptions import AILAError
from aila.platform.uow import UnitOfWork

__all__ = ["persist_investigation_artifacts"]

_log = logging.getLogger(__name__)


def _sanitize(s: str | None) -> str | None:
    if s is None:
        return None
    if "\x00" not in s:
        return s
    return s.replace("\x00", "\ufffd")


def _stringify(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return _sanitize(v) or ""
    if isinstance(v, (int, float, bool)):
        return str(v)
    try:
        return _sanitize(json.dumps(v, ensure_ascii=False, default=str)) or ""
    except (TypeError, ValueError):
        return _sanitize(str(v)) or ""


def _data_json(payload: dict[str, Any]) -> str:
    """Serialize ``payload`` to a sanitized, deterministic JSON string."""
    cleaned: dict[str, Any] = {}
    for k, v in payload.items():
        if v is None or v == "" or v == [] or v == {}:
            continue
        cleaned[str(k)] = v
    raw = json.dumps(cleaned, sort_keys=True, ensure_ascii=False, default=str)
    return _sanitize(raw) or "{}"


def _content_hash(artifact_type: str, data_json: str) -> str:
    h = hashlib.sha256()
    h.update(artifact_type.encode("utf-8"))
    h.update(b"\x1f")
    h.update(data_json.encode("utf-8"))
    return h.hexdigest()


def _get(observables: dict[str, Any], *keys: str) -> Any:
    """Return first non-empty observable value matching any of ``keys``."""
    for k in keys:
        if k in observables:
            v = observables[k]
            if v not in (None, "", [], {}):
                return v
    return None


def _classify(
    *,
    question: str,
    answer: str,
    confidence: str,
    observables: dict[str, Any],
    provenance: dict[str, Any],
    contract: dict[str, Any],
    include_summary: bool,
) -> list[tuple[str, str, dict[str, Any]]]:
    """Return ``[(artifact_family, artifact_type, payload), ...]``.

    When ``include_summary`` is True an ``investigation_summary`` row is
    prepended (only meaningful at answer-submission time). Domain-
    specific rows are appended only when their required observable keys
    exist.
    """
    rows: list[tuple[str, str, dict[str, Any]]] = []

    if include_summary:
        # -- investigation_summary (only on submit) --
        summary_payload: dict[str, Any] = {
            "question": question,
            "answer": answer,
            "confidence": confidence,
            "answer_type": contract.get("answer_type") if contract else None,
            "answer_format": contract.get("answer_format") if contract else None,
            "primary_artifact": provenance.get("primary_artifact"),
            "corroboration": list(provenance.get("corroboration") or []),
        }
        rows.append(("host", "investigation_summary", summary_payload))

    # -- malware: trigger_artifact --
    trigger_file = _get(observables, "trigger_file", "trigger_path")
    trigger_magic = _get(observables, "trigger_magic")
    if trigger_file and trigger_magic:
        rows.append((
            "malware",
            "trigger_artifact",
            {
                "path": trigger_file,
                "magic": trigger_magic,
                "target": _get(observables, "trigger_target"),
                "sha256": _get(observables, "trigger_sha256"),
                "double_extension": bool(
                    _get(observables, "double_extension")
                    or (
                        isinstance(trigger_file, str)
                        and trigger_file.count(".") >= 2
                    )
                ),
            },
        ))

    # -- malware: lnk_dropper --
    lnk_target = _get(observables, "lnk_target")
    lnk_arguments = _get(observables, "lnk_arguments", "lnk_command_line")
    if lnk_target or lnk_arguments:
        rows.append((
            "malware",
            "lnk_dropper",
            {
                "lnk_path": _get(observables, "lnk_path", "trigger_file"),
                "target": lnk_target,
                "arguments": lnk_arguments,
                "working_dir": _get(observables, "lnk_working_dir"),
                "icon_location": _get(observables, "lnk_icon_location"),
            },
        ))

    # -- malware: capa_findings --
    capa_caps = _get(observables, "capa_capabilities", "capa_matches")
    if isinstance(capa_caps, (list, tuple)) and capa_caps:
        rows.append((
            "malware",
            "capa_findings",
            {
                "binary_path": _get(observables, "capa_binary", "trigger_file"),
                "capabilities": list(capa_caps),
                "att_ck_ids": list(_get(observables, "att_ck_ids") or []),
                "rules_matched": _get(observables, "capa_rules_matched"),
            },
        ))

    # -- malware: process_injection --
    injection = _get(observables, "injection_technique")
    if injection:
        rows.append((
            "malware",
            "process_injection",
            {
                "technique": injection,
                "target_process": _get(observables, "injection_target_process"),
                "apis_used": list(_get(observables, "injection_apis") or []),
                "att_ck_ids": list(_get(observables, "att_ck_ids") or []),
            },
        ))

    # -- network: ioc_observation --
    # Match the canonical key names AND any user-coined variant
    # whose key name implies a network indicator. The agent's actual
    # vocabulary is open ("c2_image_server", "suspect_domain",
    # "callback_url"...) so we widen by prefix/suffix.
    ioc_candidates: list[tuple[str, Any]] = []
    canonical_iocs = _get(observables, "c2_endpoint", "ioc_value", "c2_ip", "c2_domain")
    if canonical_iocs:
        ioc_candidates.append(("ioc", canonical_iocs))
    for k, v in observables.items():
        if v in (None, "", [], {}):
            continue
        kl = k.lower()
        if (
            kl.startswith(("c2_", "ioc_", "callback_"))
            or kl.endswith(("_url", "_endpoint", "_domain", "_ip", "_host", "_server"))
            or "suspect_domain" in kl
            or "suspect_url" in kl
            or "exfil" in kl
        ) and k not in ("c2_endpoint", "ioc_value", "c2_ip", "c2_domain"):
            ioc_candidates.append((k, v))

    seen_ioc_values: set[str] = set()
    for source_key, raw_value in ioc_candidates:
        v_str = str(raw_value)
        if v_str in seen_ioc_values:
            continue
        seen_ioc_values.add(v_str)
        kind = _get(observables, "ioc_kind")
        if not kind:
            v = v_str
            if v.startswith(("http://", "https://")):
                kind = "url"
            elif v.replace(".", "").isdigit():
                kind = "ip"
            elif "." in v:
                kind = "domain"
            else:
                kind = "unknown"
        rows.append((
            "network",
            "ioc_observation",
            {
                "value": raw_value,
                "kind": kind,
                "source_key": source_key,
                "context": _get(observables, "ioc_context"),
                "confidence": confidence,
            },
        ))

    # -- execution: persistence_finding --
    persistence_mech = _get(observables, "persistence_mechanism", "persistence_kind")
    if persistence_mech:
        rows.append((
            "execution",
            "persistence_finding",
            {
                "mechanism": persistence_mech,
                "location": _get(observables, "persistence_location"),
                "value": _get(observables, "persistence_value"),
                "user": _get(observables, "persistence_user"),
            },
        ))

    # -- malware: lnk_dropper (loose detection) --
    # Catch the agent's natural keys when canonical lnk_target wasn't set.
    if not (lnk_target or lnk_arguments):
        for k, v in observables.items():
            if v in (None, "", [], {}):
                continue
            v_str = str(v)
            kl = k.lower()
            if (
                "shortcut" in kl
                or kl.endswith("_lnk")
                or kl.endswith(".lnk")
                or v_str.lower().endswith(".lnk")
            ):
                rows.append((
                    "malware",
                    "lnk_dropper",
                    {
                        "lnk_path": v_str,
                        "source_key": k,
                        "target": None,
                        "arguments": None,
                    },
                ))
                break  # one catch-all row is enough

    # -- catch-all: observables_snapshot --
    # The typed rows above only fire when canonical key names are
    # present. The agent's actual vocabulary is open and rich
    # (`suspect_exe`, `xor_key`, `installer_magic`, `package_version`,
    # `ipc_handlers`, `app_archive`, ...). Without a generic snapshot
    # row those discoveries vanish from the Artifacts tab. This row
    # captures the FULL observables map -- verbatim -- so nothing the
    # agent learned is silently dropped.
    if observables:
        meaningful = {
            k: v for k, v in observables.items()
            if v not in (None, "", [], {})
        }
        if meaningful:
            rows.append((
                "host",
                "observables_snapshot",
                {
                    "n_keys": len(meaningful),
                    "observables": meaningful,
                },
            ))

    return rows


async def persist_investigation_artifacts(
    *,
    project_id: str,
    investigation_id: str,
    question: str,
    answer: str,
    confidence: str,
    observables: dict[str, Any],
    provenance: dict[str, Any] | None,
    contract: dict[str, Any] | None,
    include_summary: bool = True,
) -> int:
    """Insert artifact rows derived from the investigation's findings.

    Returns the number of rows inserted (excluding de-dup skips).
    Never raises -- a write failure is logged at WARNING and swallowed
    so the investigation completion path is not destabilised.

    Set ``include_summary=False`` for per-step calls during the agent
    loop. Per-step mode emits only domain-specific rows (capa,
    lnk_dropper, etc.) and skips the always-on summary row, which is
    only meaningful once an answer has been submitted.
    """
    if not investigation_id:
        return 0

    classified = _classify(
        question=question or "",
        answer=answer or "",
        confidence=confidence or "unknown",
        observables=observables or {},
        provenance=provenance or {},
        contract=contract or {},
        include_summary=include_summary,
    )
    if not classified:
        return 0

    inserted = 0
    try:
        async with UnitOfWork() as uow:
            existing_rows = (await uow.session.exec(
                select(ArtifactRecord).where(
                    ArtifactRecord.project_id == project_id,
                    ArtifactRecord.source_tool == "investigator",
                )
            )).all()
            existing_hashes: set[str] = {
                _content_hash(r.artifact_type, r.data_json)
                for r in existing_rows
            }

            for family, atype, payload in classified:
                payload_json = _data_json(payload)
                fingerprint = _content_hash(atype, payload_json)
                if fingerprint in existing_hashes:
                    continue
                existing_hashes.add(fingerprint)
                uow.session.add(ArtifactRecord(
                    project_id=project_id,
                    artifact_family=family,
                    artifact_type=atype,
                    source_tool="investigator",
                    source_investigation_id=investigation_id,
                    data_json=payload_json,
                ))
                inserted += 1
            if inserted:
                await uow.commit()
    except (OSError, RuntimeError, AILAError) as exc:
        _log.warning(
            "persist_investigation_artifacts failed for inv %s: %s",
            investigation_id, exc,
        )
        return 0

    if inserted:
        _log.info(
            "persisted %d investigation artifacts (inv=%s, project=%s)",
            inserted, investigation_id, project_id,
        )
    return inserted
