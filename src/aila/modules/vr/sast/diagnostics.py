"""Project persisted detector outcomes into source-workbench diagnostics."""
from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import PurePosixPath
from typing import Any

from ..contracts import OutcomeKind
from ..db_models import VRInvestigationOutcomeRecord
from .contracts import SastDiagnostic, SastDiagnosticLocation
from .models import SastPhase, SastSkill

__all__ = ["extract_sast_diagnostics", "normalize_diagnostic_path"]

_REF = re.compile(r"^(?P<path>.+?):(?P<start>\d+)(?:-(?P<end>\d+))?(?:\s+\[[^]]+\])?$")


def normalize_diagnostic_path(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        return None
    path = value.strip().replace("\\", "/")
    if path.startswith("file://"):
        path = path[7:]
    if path.startswith("/") or re.match(r"^[A-Za-z]:/", path):
        return None
    parts = [part for part in path.split("/") if part not in {"", "."}]
    if not parts or any(part == ".." for part in parts):
        return None
    return str(PurePosixPath(*parts))


def _line(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, str) and value.isdigit() and int(value) > 0:
        return int(value)
    return None


def _text(*values: Any) -> str | None:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _payload(row: VRInvestigationOutcomeRecord) -> dict[str, Any]:
    if isinstance(row.payload_json, dict):
        return dict(row.payload_json)
    if isinstance(row.payload_json, str):
        try:
            value = json.loads(row.payload_json)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Outcome {row.id} has malformed payload JSON") from exc
        return dict(value) if isinstance(value, dict) else {}
    return {}


def _ref(value: Any) -> SastDiagnosticLocation | None:
    if isinstance(value, dict):
        value = value.get("ref") or value.get("path")
    if not isinstance(value, str):
        return None
    match = _REF.match(value.strip())
    if not match:
        return None
    path = normalize_diagnostic_path(match.group("path"))
    if path is None:
        return None
    start = int(match.group("start"))
    end = int(match.group("end") or start)
    return SastDiagnosticLocation(path=path, line_start=start, line_end=max(start, end))


def _location(raw: dict[str, Any]) -> SastDiagnosticLocation:
    nested_value = raw.get("location")
    nested: dict[str, Any] = nested_value if isinstance(nested_value, dict) else {}
    region_value = nested.get("region")
    region: dict[str, Any] = region_value if isinstance(region_value, dict) else {}
    path = normalize_diagnostic_path(
        raw.get("path") or raw.get("file_path") or raw.get("artifact_path")
        or nested.get("path") or nested.get("file_path") or nested.get("uri"),
    )
    start = _line(
        raw.get("line_start") or raw.get("start_line") or raw.get("line")
        or nested.get("line_start") or nested.get("line")
        or region.get("start_line") or region.get("line"),
    )
    end = _line(raw.get("line_end") or raw.get("end_line") or nested.get("line_end") or region.get("end_line")) or start
    column_start = _line(raw.get("column_start") or raw.get("start_column") or region.get("start_column"))
    column_end = _line(raw.get("column_end") or raw.get("end_column") or region.get("end_column"))
    return SastDiagnosticLocation(
        path=path,
        line_start=start if path else None,
        line_end=max(start, end) if path and start and end else start if path else None,
        column_start=column_start if path and start else None,
        column_end=column_end if path and start else None,
    )


def _location_key(location: SastDiagnosticLocation) -> tuple[Any, ...]:
    return (
        location.path, location.line_start, location.line_end,
        location.column_start, location.column_end,
    )


def _entries(payload: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    for key in ("diagnostics", "findings"):
        value = payload.get(key)
        if isinstance(value, list):
            return [dict(item) for item in value if isinstance(item, dict)]
    if kind == OutcomeKind.DIRECT_FINDING.value:
        return [payload]
    return []


def extract_sast_diagnostics(
    outcomes: Iterable[VRInvestigationOutcomeRecord],
    specs_by_investigation: dict[str, SastSkill],
) -> list[SastDiagnostic]:
    """Extract only persisted evidence; never parse line numbers from prose."""
    diagnostics: list[SastDiagnostic] = []
    for outcome in sorted(outcomes, key=lambda row: row.created_at):
        spec = specs_by_investigation.get(outcome.investigation_id)
        if spec is None or spec.phase != SastPhase.DETECTION:
            continue
        payload = _payload(outcome)
        entries = _entries(payload, outcome.outcome_kind)
        for index, raw in enumerate(entries):
            primary = _location(raw)
            if primary.path is None:
                primary = _ref(raw.get("source_ref")) or primary
            related: list[SastDiagnosticLocation] = []
            sink = _ref(raw.get("sink_ref"))
            if sink:
                if primary.path is None:
                    primary = sink
                elif _location_key(sink) != _location_key(primary):
                    related.append(sink)
            raw_related = raw.get("related_locations")
            if isinstance(raw_related, list):
                related.extend(
                    _location(item) for item in raw_related if isinstance(item, dict)
                )
            evidence_refs = raw.get("evidence_refs")
            if isinstance(evidence_refs, list):
                related.extend(ref for item in evidence_refs if (ref := _ref(item)) is not None)
            if primary.path is None:
                cited = next((ref for ref in related if ref.path and ref.line_start), None)
                if cited is not None:
                    primary = cited
            unique_related: list[SastDiagnosticLocation] = []
            seen = {_location_key(primary)}
            for location in related:
                key = _location_key(location)
                if location.path and location.line_start and key not in seen:
                    seen.add(key)
                    unique_related.append(location)
            confidence = _text(raw.get("confidence"), payload.get("confidence"), outcome.confidence)
            message = _text(
                raw.get("message"), raw.get("title"), raw.get("summary"),
                raw.get("cwe_id"), payload.get("answer"), payload.get("summary"),
                "SAST detector finding",
            )
            description = _text(
                raw.get("description"), raw.get("explanation"), raw.get("answer"),
                payload.get("description"), payload.get("answer"), payload.get("summary"),
            ) or ""
            severity = _text(raw.get("severity"), payload.get("severity")) or "unknown"
            diagnostics.append(SastDiagnostic(
                id=f"{outcome.id}:{index}",
                skill_id=spec.id,
                investigation_id=outcome.investigation_id,
                outcome_id=outcome.id,
                message=message or "SAST detector finding",
                description=description,
                severity=severity,
                confidence=confidence,
                **primary.model_dump(),
                related_locations=unique_related,
            ))
    return diagnostics
