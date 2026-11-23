"""Internal helpers for SAST secondary-target reference tags."""
from __future__ import annotations

import json

from aila.modules.vr.db_models import VRInvestigationRecord


def skill_id(record: VRInvestigationRecord) -> str | None:
    try:
        refs = json.loads(record.secondary_target_refs_json or "[]")
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid SAST skill references on investigation {record.id}") from exc
    if not isinstance(refs, list):
        return None
    for ref in refs:
        if isinstance(ref, dict) and isinstance(ref.get("sast_skill_id"), str):
            return ref["sast_skill_id"]
    return None
