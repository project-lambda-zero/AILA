"""Mitigation analyzer (M3.T-2).

Per-target service that:
  1. Loads a ``VRTargetRecord`` by id
  2. Extracts the MCP-side ``binary_id`` from the target's descriptor
  3. Invokes a checksec callable (IDA Headless MCP, audit-mcp, or a
     local parser injected at construction time)
  4. Maps the raw checksec response into ``MitigationFlags``
  5. Persists the flags into ``capability_profile_json.mitigations``
     and the provenance into ``capability_profile_json.mitigation_provenance``
  6. Updates ``enrichment_status`` (``running`` -> ``complete`` / ``failed``)
  7. Returns a ``MitigationReport`` for the caller

The checksec call is passed in as a callable so the analyzer is unit-
testable without standing up an MCP server. In production the
``mitigation_worker`` ARQ task wires in the real IDABridgeTool call.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from sqlmodel import select as _select

from aila.modules.vr.contracts.enrichment import MitigationFlags
from aila.modules.vr.db_models import VRTargetRecord
from aila.modules.vr.enrichment.contracts import (
    MitigationReport,
    MitigationSource,
)
from aila.platform.contracts._common import utc_now
from aila.platform.uow import UnitOfWork

__all__ = [
    "ChecksecCallable",
    "MitigationAnalysisError",
    "MitigationAnalyzer",
]

_log = logging.getLogger(__name__)


ChecksecCallable = Callable[[str], Awaitable[dict[str, Any]]]
"""Async callable that takes a binary_id and returns the raw checksec dict.

The dict shape mirrors what IDA Headless MCP's ``checksec`` tool returns:
``{"status": "ready", "binary_id": "...", "nx": bool, "aslr": bool,
"canary": bool, "cet": bool, "cfi": bool, "relro": "no"|"partial"|"full",
"pie": bool, ...}``. Status ``error`` indicates the MCP call failed.
"""


# Mapping from a checksec raw key to a MitigationFlags field name. Keys
# absent from the raw response are left as None on the output (tristate).
_CHECKSEC_KEY_MAP: dict[str, str] = {
    "nx": "nx",
    "aslr": "aslr",
    "canary": "canary",
    "cet": "cet",
    "cfi": "cfi",
    "pie": "pie",
}


class MitigationAnalysisError(Exception):
    """Raised when mitigation analysis fails fatally (no report producible)."""


class MitigationAnalyzer:
    """Per-target mitigation analyzer service.

    Construction injects a checksec callable so the analyzer can be
    tested in isolation. The mitigation_worker ARQ task wires in the
    IDABridgeTool-backed callable at runtime.
    """

    def __init__(
        self,
        checksec: ChecksecCallable,
        *,
        source: MitigationSource = MitigationSource.IDA_CHECKSEC,
        analyzer_version: str = "0.3.0",
    ) -> None:
        self._checksec = checksec
        self._source = source
        self._analyzer_version = analyzer_version

    async def analyze(self, target_id: str) -> MitigationReport:
        """Analyze one target's mitigations and persist the report.

        Sets ``enrichment_status='running'`` at entry; transitions to
        ``complete`` on success or ``failed`` if the checksec call
        returned an error. Raises ``MitigationAnalysisError`` for fatal
        infrastructure failures (target not found, descriptor missing
        binary_id, DB unreachable).
        """
        target_row = await self._load_and_mark_running(target_id)

        descriptor = json.loads(target_row.descriptor_json or "{}")
        binary_id = descriptor.get("binary_id")
        if not binary_id:
            await self._mark_failed(target_id, "descriptor.binary_id missing")
            raise MitigationAnalysisError(
                f"target {target_id} has no binary_id in descriptor — cannot run checksec",
            )

        try:
            raw = await self._checksec(str(binary_id))
        except (OSError, TimeoutError, RuntimeError) as exc:
            await self._mark_failed(target_id, f"checksec call raised: {exc}")
            raise MitigationAnalysisError(
                f"checksec call failed for binary_id={binary_id}: {exc}",
            ) from exc

        if raw.get("status") != "ready":
            err = raw.get("error") or "checksec returned non-ready status"
            await self._mark_failed(target_id, err)
            raise MitigationAnalysisError(
                f"checksec returned status={raw.get('status')!r}: {err}",
            )

        flags, errors = _flags_from_checksec(raw)
        report = MitigationReport(
            target_id=target_id,
            binary_id=str(binary_id),
            binary_sha256=raw.get("sha256"),
            source=self._source,
            analyzer_version=self._analyzer_version,
            analyzed_at=utc_now(),
            flags=flags,
            errors=errors,
        )

        await self._persist(target_id, report)
        _log.info(
            "mitigation_analyzer COMPLETE target_id=%s binary_id=%s flags_set=%d errors=%d",
            target_id,
            binary_id,
            sum(1 for v in flags.model_dump().values() if v not in (None, [], "")),
            len(errors),
        )
        return report

    async def _load_and_mark_running(self, target_id: str) -> VRTargetRecord:
        async with UnitOfWork() as uow:
            row = (
                await uow.session.exec(
                    _select(VRTargetRecord).where(VRTargetRecord.id == target_id)
                )
            ).first()
            if row is None:
                raise MitigationAnalysisError(f"target {target_id} not found")
            row.enrichment_status = "running"
            row.updated_at = utc_now()
            uow.session.add(row)
            await uow.commit()
            await uow.session.refresh(row)
            return row

    async def _mark_failed(self, target_id: str, message: str) -> None:
        async with UnitOfWork() as uow:
            row = (
                await uow.session.exec(
                    _select(VRTargetRecord).where(VRTargetRecord.id == target_id)
                )
            ).first()
            if row is None:
                return
            capability = json.loads(row.capability_profile_json or "{}")
            errors = capability.setdefault("enrichment_errors", [])
            errors.append({"step": "mitigation_analyzer", "message": message})
            row.capability_profile_json = json.dumps(capability)
            row.enrichment_status = "failed"
            row.updated_at = utc_now()
            uow.session.add(row)
            await uow.commit()

    async def _persist(self, target_id: str, report: MitigationReport) -> None:
        async with UnitOfWork() as uow:
            row = (
                await uow.session.exec(
                    _select(VRTargetRecord).where(VRTargetRecord.id == target_id)
                )
            ).first()
            if row is None:
                raise MitigationAnalysisError(
                    f"target {target_id} disappeared during analysis",
                )
            capability = json.loads(row.capability_profile_json or "{}")
            capability["mitigations"] = report.flags.model_dump(mode="json")
            capability["mitigation_provenance"] = {
                "source": report.source.value,
                "analyzer_version": report.analyzer_version,
                "analyzed_at": report.analyzed_at.isoformat(),
                "binary_id": report.binary_id,
                "binary_sha256": report.binary_sha256,
                "errors": report.errors,
            }
            row.capability_profile_json = json.dumps(capability)
            row.enrichment_status = "complete"
            row.last_enriched_at = utc_now()
            row.updated_at = utc_now()
            uow.session.add(row)
            await uow.commit()


def _flags_from_checksec(raw: dict[str, Any]) -> tuple[MitigationFlags, list[str]]:
    """Map a raw checksec response dict into MitigationFlags + non-fatal errors.

    Tristate semantics: a flag is True/False if the response carries a
    bool, None if the key is missing or the value isn't coercible.
    RELRO needs special handling because checksec emits a string
    ('no'|'partial'|'full') that maps to two flag booleans.
    """
    errors: list[str] = []
    field_values: dict[str, Any] = {}

    for raw_key, field_name in _CHECKSEC_KEY_MAP.items():
        if raw_key not in raw:
            continue
        value = raw[raw_key]
        if isinstance(value, bool):
            field_values[field_name] = value
        else:
            errors.append(f"checksec key {raw_key!r}: expected bool, got {type(value).__name__}")

    relro = raw.get("relro")
    if isinstance(relro, str):
        normalized = relro.strip().lower()
        if normalized in {"no", "none", "false", ""}:
            field_values["relro_partial"] = False
            field_values["relro_full"] = False
        elif normalized == "partial":
            field_values["relro_partial"] = True
            field_values["relro_full"] = False
        elif normalized == "full":
            field_values["relro_partial"] = True
            field_values["relro_full"] = True
        else:
            errors.append(f"checksec relro: unknown value {relro!r}")
    elif relro is not None:
        errors.append(f"checksec relro: expected string, got {type(relro).__name__}")

    sanitizers_raw = raw.get("sanitizers")
    if isinstance(sanitizers_raw, list):
        sanitizers = [str(s) for s in sanitizers_raw if isinstance(s, str)]
        field_values["sanitizers"] = sanitizers
    elif sanitizers_raw is not None:
        errors.append(f"checksec sanitizers: expected list, got {type(sanitizers_raw).__name__}")

    notes = raw.get("notes")
    if isinstance(notes, str):
        field_values["notes"] = notes

    return MitigationFlags(**field_values), errors
