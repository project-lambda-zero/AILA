"""Read-side projection for VR target records."""
from __future__ import annotations

import json
from typing import Any

from aila.modules.vr.contracts.target import (
    AnalysisState,
    TargetKind,
    TargetStatus,
    TargetTag,
    TargetTagSource,
    VRTargetSummary,
)

__all__ = ["build_target_summary"]


def build_target_summary(record: Any) -> VRTargetSummary:
    """Project a VRTargetRecord row to the public VRTargetSummary."""
    raw_tags = json.loads(record.tags_json or "[]")
    tags: list[TargetTag] = []
    for entry in raw_tags:
        if isinstance(entry, dict) and "tag" in entry:
            try:
                tags.append(TargetTag(
                    tag=str(entry["tag"]),
                    source=TargetTagSource(entry.get("source", "operator")),
                ))
            except ValueError:
                continue
        elif isinstance(entry, str):
            tags.append(TargetTag(tag=entry, source=TargetTagSource.OPERATOR))

    handles = json.loads(record.mcp_handles_json or "{}")
    uploaded_filename = handles.get("uploaded_filename")
    if not isinstance(uploaded_filename, str):
        uploaded_filename = None
    android_package_name = handles.get("android_mcp_package_name")
    if not isinstance(android_package_name, str) or not android_package_name:
        android_package_name = None

    # Roll up the Android pipeline handles into the bounded public overview.
    apk_overview: dict[str, Any] | None = None
    if record.kind == TargetKind.ANDROID_APK.value:
        overview: dict[str, Any] = {}
        for handle_key, out_key in (
            ("android_mcp_apk_sha256", "sha256"),
            ("android_mcp_decoded_dir", "decoded_dir"),
            ("android_mcp_manifest_path", "manifest_path"),
            ("android_mcp_decompiled_dir", "decompiled_dir"),
            ("android_mcp_jadx_root", "jadx_root"),
            ("android_mcp_jadx_class_count", "jadx_class_count"),
            ("audit_mcp_decompiled_index_id", "audit_mcp_index_id"),
            ("audit_mcp_decompiled_indexed_at", "audit_mcp_indexed_at"),
        ):
            value = handles.get(handle_key)
            if value is not None:
                overview[out_key] = value

        # Keep only the load-bearing static-summary fields. Both the current
        # digest shape and older inline list values remain readable.
        static_full = handles.get("android_mcp_static_summary") or {}
        if isinstance(static_full, dict) and static_full:
            digest: dict[str, Any] = {}
            for key in (
                "package", "version_name", "version_code",
                "min_sdk", "target_sdk", "signing_scheme",
            ):
                if static_full.get(key) is not None:
                    digest[key] = static_full[key]
            for key in (
                "permissions", "dangerous_permissions", "exported_activities",
                "exported_services", "exported_receivers", "exported_providers",
                "native_libs", "certificates",
            ):
                count_key = f"{key}_count"
                value = static_full.get(key)
                if isinstance(value, list):
                    digest[count_key] = len(value)
                elif isinstance(static_full.get(count_key), int):
                    digest[count_key] = static_full[count_key]
            for sub_key in ("native_analysis", "sbom"):
                sub_value = static_full.get(sub_key)
                if isinstance(sub_value, dict):
                    digest[sub_key] = sub_value
            overview["static_summary"] = digest

        if overview:
            apk_overview = overview

    stages_payload: dict[str, Any] | None = None
    try:
        if record.analysis_stages_json and record.analysis_stages_json != "{}":
            stages_payload = json.loads(record.analysis_stages_json)
    except (ValueError, TypeError):
        stages_payload = None

    return VRTargetSummary(
        id=record.id,
        workspace_id=record.workspace_id,
        display_name=record.display_name,
        kind=TargetKind(record.kind),
        descriptor=json.loads(record.descriptor_json or "{}"),
        uploaded_filename=uploaded_filename,
        android_package_name=android_package_name,
        apk_overview=apk_overview,
        primary_language=record.primary_language,
        secondary_languages=json.loads(record.secondary_languages_json or "[]"),
        status=TargetStatus(record.status),
        analysis_state=AnalysisState(record.analysis_state),
        analysis_state_message=record.analysis_state_message,
        analysis_started_at=(
            record.analysis_started_at.isoformat()
            if record.analysis_started_at else None
        ),
        analysis_completed_at=(
            record.analysis_completed_at.isoformat()
            if record.analysis_completed_at else None
        ),
        analysis_stages=stages_payload,
        tags=tags,
        created_at=record.created_at.isoformat() if record.created_at else None,
        updated_at=record.updated_at.isoformat() if record.updated_at else None,
    )
