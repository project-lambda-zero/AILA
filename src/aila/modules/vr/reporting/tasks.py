"""Operator-triggered VR PDF reporting tasks."""
from __future__ import annotations

import json
from typing import Any

from sqlmodel import select

from aila.modules.vr.contracts import InvestigationKind, VRTargetSummary
from aila.modules.vr.db_models import VRInvestigationRecord, VRTargetRecord
from aila.modules.vr.reporting.masvs_report import build_pdf, collect_findings
from aila.modules.vr.reporting.pdf_report import render_investigation_pdf
from aila.modules.vr.services.target_summary import build_target_summary
from aila.platform.tasks.artifacts import store_task_json_result, store_task_pdf
from aila.platform.tasks.context import TaskContext
from aila.platform.tasks.template import platform_task
from aila.platform.uow import UnitOfWork

__all__ = ["run_vr_investigation_report", "run_vr_masvs_report"]


def _sanitize_filename_part(text: str, *, fallback: str) -> str:
    """Fold a free-form label into a Content-Disposition-safe slug."""
    if not text:
        return fallback
    out_chars = [
        ch if (ch.isascii() and (ch.isalnum() or ch in "._-")) else "_"
        for ch in text
    ]
    cleaned = "".join(out_chars).strip("._-")
    if not cleaned:
        return fallback
    return cleaned[:64]


def _masvs_report_filename(
    target_summary: VRTargetSummary,
    generated_at_yyyymmdd: str,
) -> str:
    """Build ``masvs_<package>_<YYYYMMDD>.pdf`` using the APK identity."""
    package_label = ""
    overview = target_summary.apk_overview
    if isinstance(overview, dict):
        static_summary = overview.get("static_summary")
        if isinstance(static_summary, dict):
            maybe_package = static_summary.get("package")
            if isinstance(maybe_package, str):
                package_label = maybe_package.strip()
    if not package_label and target_summary.android_package_name:
        package_label = target_summary.android_package_name.strip()
    sanitized = _sanitize_filename_part(
        package_label,
        fallback="android-apk",
    )
    return f"masvs_{sanitized}_{generated_at_yyyymmdd}.pdf"


def _investigation_report_filename(
    title: str | None,
    investigation_id: str,
) -> str:
    safe_title = (title or "investigation").replace(" ", "_")[:80]
    return f"AILA_VR_{safe_title}_{investigation_id[:8]}.pdf"


async def _investigation_title(
    investigation_id: str,
    team_id: str | None,
) -> str | None:
    stmt = select(VRInvestigationRecord).where(
        VRInvestigationRecord.id == investigation_id,
    )
    if team_id is not None:
        stmt = stmt.where(VRInvestigationRecord.team_id == team_id)
    async with UnitOfWork() as uow:
        investigation = (await uow.session.exec(stmt)).first()
        if investigation is None:
            raise ValueError(f"Investigation {investigation_id} not found")
        return investigation.title


async def _render_masvs_report(
    target_id: str,
    audit_id: str | None,
    team_id: str | None,
) -> tuple[bytes, str]:
    """Collect and render one MASVS report on the reporting worker."""
    async with UnitOfWork() as uow:
        target_stmt = select(VRTargetRecord).where(VRTargetRecord.id == target_id)
        if team_id is not None:
            target_stmt = target_stmt.where(VRTargetRecord.team_id == team_id)
        target = (await uow.session.exec(target_stmt)).first()
        if target is None:
            raise ValueError(f"Target {target_id} not found")

        if audit_id is None:
            parent_stmt = (
                select(VRInvestigationRecord)
                .where(VRInvestigationRecord.target_id == target_id)
                .where(
                    VRInvestigationRecord.kind
                    == InvestigationKind.MASVS_AUDIT.value,
                )
                .order_by(VRInvestigationRecord.created_at.desc())
            )
            if team_id is not None:
                parent_stmt = parent_stmt.where(
                    VRInvestigationRecord.team_id == team_id,
                )
            parent = (await uow.session.exec(parent_stmt)).first()
            if parent is None:
                raise ValueError(f"No MASVS audit found for target {target_id}")
        else:
            parent_stmt = select(VRInvestigationRecord).where(
                VRInvestigationRecord.id == audit_id,
            )
            if team_id is not None:
                parent_stmt = parent_stmt.where(
                    VRInvestigationRecord.team_id == team_id,
                )
            parent = (await uow.session.exec(parent_stmt)).first()
            if parent is None:
                raise ValueError(f"MASVS audit {audit_id} not found")
            if parent.kind != InvestigationKind.MASVS_AUDIT.value:
                raise ValueError(
                    f"Investigation {audit_id} kind={parent.kind!r}; "
                    "expected 'masvs_audit'.",
                )
            if parent.target_id != target_id:
                raise ValueError(
                    f"MASVS audit {audit_id} does not belong to target {target_id}",
                )
        resolved_audit_id = parent.id
        target_summary = build_target_summary(target)
        handles_json = target.mcp_handles_json

    aggregate = await collect_findings(resolved_audit_id)
    handles: dict[str, Any] = {}
    try:
        if handles_json:
            handles = json.loads(handles_json)
    except (ValueError, TypeError):
        handles = {}

    pdf_bytes = build_pdf(aggregate, target_summary, handles=handles)
    filename = _masvs_report_filename(
        target_summary,
        aggregate.generated_at.strftime("%Y%m%d"),
    )
    return pdf_bytes, filename


async def _store_report(
    ctx: TaskContext,
    *,
    filename: str,
    content: bytes,
) -> dict[str, Any]:
    artifact_id = await store_task_pdf(
        task_id=ctx.task_id,
        content=content,
        team_id=ctx.team_id,
    )
    payload = {"filename": filename, "artifact_id": artifact_id}
    await store_task_json_result(
        task_id=ctx.task_id,
        module_id="vr",
        payload=payload,
        team_id=ctx.team_id,
    )
    return payload


@platform_task(track="reporting", module_id="vr", max_tries=1, timeout_s=1800.0)
async def run_vr_investigation_report(
    ctx: TaskContext,
    investigation_id: str,
) -> dict[str, Any]:
    """Render and persist an investigation PDF without inline API work."""
    title = await _investigation_title(investigation_id, ctx.team_id)
    pdf_bytes = await render_investigation_pdf(
        investigation_id,
        run_id=ctx.task_id,
    )
    return await _store_report(
        ctx,
        filename=_investigation_report_filename(title, investigation_id),
        content=pdf_bytes,
    )


@platform_task(track="reporting", module_id="vr", max_tries=1, timeout_s=600.0)
async def run_vr_masvs_report(
    ctx: TaskContext,
    target_id: str,
    audit_id: str | None = None,
) -> dict[str, Any]:
    """Render and persist a MASVS PDF, optionally resolving the latest audit."""
    pdf_bytes, filename = await _render_masvs_report(
        target_id,
        audit_id,
        ctx.team_id,
    )
    return await _store_report(ctx, filename=filename, content=pdf_bytes)
