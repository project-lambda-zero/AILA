"""ARQ job for scheduled report generation and email delivery.

Phase 147 EXEC-02: scheduled report execution via arq task queue.

Loads a ScheduledReportRecord, generates the appropriate report PDF,
and delivers it via email if SMTP is configured in ConfigRegistry.

SMTP config keys (namespace="platform"):
  smtp_host     — SMTP server hostname (required for email; if absent, skips delivery)
  smtp_port     — SMTP server port (default: 587)
  smtp_from     — From address (default: "aila@localhost")
  smtp_username — SMTP auth username (optional)
  smtp_password — SMTP auth password (optional)

Security:
  T-147-01: SMTP config loaded from ConfigRegistry only, never from request body.
  T-147-02: Email recipients come only from ScheduledReportRecord.recipient_emails_json,
             which is admin-set via the API; never from user-submitted content.
"""
from __future__ import annotations

import asyncio
import json
import logging
import smtplib
from datetime import UTC, datetime
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from sqlmodel import select

from aila.platform.runtime import get_worker_platform
from aila.storage.database import async_session_scope
from aila.storage.db_models import ScheduledReportRecord
from aila.storage.registry import ConfigRegistry

__all__ = ["generate_scheduled_report_job"]

_log = logging.getLogger(__name__)


async def generate_scheduled_report_job(
    ctx: dict,
    report_id: str,
    triggered_by: str,
) -> dict:
    """ARQ job: generate a scheduled report and deliver via email.

    Args:
        ctx: ARQ job context dict (worker state).
        report_id: ID of the ScheduledReportRecord to run.
        triggered_by: User ID who triggered the job (for audit logging).

    Returns:
        Result dict with status, recipients count, and report_id.

    Raises:
        Never raises — exceptions are logged and reflected in the return dict
        so ARQ does not retry on business logic failures.
    """
    _log.info(
        "generate_scheduled_report_job: starting report_id=%r triggered_by=%r",
        report_id,
        triggered_by,
    )

    # Load the scheduled report config
    async with async_session_scope() as session:
        stmt = select(ScheduledReportRecord).where(ScheduledReportRecord.id == report_id)
        record = (await session.exec(stmt)).first()
        if record is None:
            _log.error("generate_scheduled_report_job: report_id=%r not found", report_id)
            return {"status": "failed", "reason": "not_found", "report_id": report_id}
        if not record.is_active:
            _log.warning("generate_scheduled_report_job: report_id=%r is not active", report_id)
            return {"status": "skipped", "reason": "inactive", "report_id": report_id}

        report_type = record.report_type
        recipient_emails_raw = record.recipient_emails_json or "[]"
        report_name = record.name

    # Parse recipient emails (set by admin via API — trusted source)
    try:
        recipient_emails: list[str] = json.loads(recipient_emails_raw)
        if not isinstance(recipient_emails, list):
            recipient_emails = []
    except (json.JSONDecodeError, ValueError):
        recipient_emails = []

    # Generate the report PDF bytes
    pdf_bytes: bytes | None = None
    if report_type == "risk_summary":
        try:
            pdf_bytes = await _generate_risk_summary_pdf()
        except Exception as exc:
            _log.error(
                "generate_scheduled_report_job: PDF generation failed for report_id=%r: %s",
                report_id,
                exc,
                exc_info=True,
            )
            await _update_last_run_at(report_id)
            return {"status": "failed", "reason": "pdf_generation_error", "report_id": report_id}
    elif report_type == "compliance":
        _log.info(
            "generate_scheduled_report_job: compliance reports are system-scoped; "
            "use the evidence-package endpoint for per-system exports. Skipping email."
        )
        await _update_last_run_at(report_id)
        return {
            "status": "skipped",
            "reason": "compliance_reports_are_system_scoped",
            "report_id": report_id,
        }
    else:
        _log.warning(
            "generate_scheduled_report_job: unknown report_type=%r for report_id=%r",
            report_type,
            report_id,
        )
        await _update_last_run_at(report_id)
        return {"status": "skipped", "reason": "unknown_report_type", "report_id": report_id}

    # Load SMTP config from ConfigRegistry (T-147-01: never from request body)
    registry = ConfigRegistry()
    smtp_host = await registry.get("platform", "smtp_host")

    if not smtp_host or pdf_bytes is None:
        _log.info(
            "generate_scheduled_report_job: smtp_host not configured — skipping email delivery "
            "for report_id=%r. Configure platform.smtp_host to enable delivery.",
            report_id,
        )
        await _update_last_run_at(report_id)
        return {
            "status": "completed_no_smtp",
            "recipients": 0,
            "report_id": report_id,
        }

    smtp_port_raw = await registry.get("platform", "smtp_port")
    smtp_port = int(smtp_port_raw) if smtp_port_raw else 587
    smtp_from = await registry.get("platform", "smtp_from") or "aila@localhost"
    smtp_username = await registry.get("platform", "smtp_username")
    smtp_password = await registry.get("platform", "smtp_password")

    # Send email to each recipient
    date_str = datetime.now(UTC).strftime("%Y-%m-%d")
    sent_count = 0

    for recipient in recipient_emails:
        if not recipient or "@" not in recipient:
            _log.warning(
                "generate_scheduled_report_job: skipping invalid recipient email %r",
                recipient,
            )
            continue
        try:
            await asyncio.to_thread(
                _send_report_email,
                smtp_host=str(smtp_host),
                smtp_port=smtp_port,
                smtp_from=str(smtp_from),
                smtp_username=str(smtp_username) if smtp_username else None,
                smtp_password=str(smtp_password) if smtp_password else None,
                recipient=recipient,
                report_name=report_name,
                date_str=date_str,
                pdf_bytes=pdf_bytes,
            )
            sent_count += 1
            _log.info(
                "generate_scheduled_report_job: report_id=%r delivered to %r",
                report_id,
                recipient,
            )
        except Exception as exc:
            _log.error(
                "generate_scheduled_report_job: email delivery failed for %r: %s",
                recipient,
                exc,
                exc_info=True,
            )

    await _update_last_run_at(report_id)

    return {
        "status": "completed",
        "recipients": sent_count,
        "report_id": report_id,
    }


async def _generate_risk_summary_pdf() -> bytes:
    """Generate the fleet-wide executive risk summary PDF.

    Reuses the same logic as the executive API endpoint to avoid duplication.
    Runs PDF conversion in a thread pool to avoid blocking the event loop.
    """
    platform = await get_worker_platform()
    module = platform.runtime.module_registry.require("vulnerability")
    async with async_session_scope() as session:
        findings = await module.latest_findings(session)
    return await asyncio.to_thread(module.build_risk_pdf_bytes, findings)


async def _update_last_run_at(report_id: str) -> None:
    """Update ScheduledReportRecord.last_run_at to utc_now()."""
    from sqlmodel import select

    from aila.platform.contracts._common import utc_now
    from aila.storage.database import async_session_scope
    from aila.storage.db_models import ScheduledReportRecord

    try:
        async with async_session_scope() as session:
            stmt = select(ScheduledReportRecord).where(ScheduledReportRecord.id == report_id)
            record = (await session.exec(stmt)).first()
            if record is not None:
                record.last_run_at = utc_now()
                session.add(record)
                await session.commit()
    except Exception as exc:
        _log.error(
            "_update_last_run_at: failed to update last_run_at for report_id=%r: %s",
            report_id,
            exc,
        )


def _send_report_email(
    *,
    smtp_host: str,
    smtp_port: int,
    smtp_from: str,
    smtp_username: str | None,
    smtp_password: str | None,
    recipient: str,
    report_name: str,
    date_str: str,
    pdf_bytes: bytes,
) -> None:
    """Send a report email with the PDF attached.

    Runs synchronously — always called via asyncio.to_thread().
    Uses stdlib smtplib; no external dependencies required.

    Args:
        smtp_host: SMTP server hostname.
        smtp_port: SMTP server port (typically 587 for STARTTLS).
        smtp_from: From email address.
        smtp_username: SMTP auth username (None = no auth).
        smtp_password: SMTP auth password (None = no auth).
        recipient: Recipient email address (admin-set, trusted).
        report_name: Human-readable report name for the email subject.
        date_str: Date string for the filename (YYYY-MM-DD).
        pdf_bytes: PDF file bytes to attach.
    """
    msg = MIMEMultipart()
    msg["From"] = smtp_from
    msg["To"] = recipient
    msg["Subject"] = f"AILA Security Report: {report_name} — {date_str}"

    body = MIMEText(
        f"Please find attached the scheduled security report: {report_name}.\n\n"
        f"Generated: {date_str}\n"
        f"Source: AILA — AI Lab Assistant\n",
        "plain",
    )
    msg.attach(body)

    attachment = MIMEApplication(pdf_bytes, _subtype="pdf")
    attachment.add_header(
        "Content-Disposition",
        "attachment",
        filename=f"aila-report-{date_str}.pdf",
    )
    msg.attach(attachment)

    with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
        server.ehlo()
        server.starttls()
        if smtp_username and smtp_password:
            server.login(smtp_username, smtp_password)
        server.sendmail(smtp_from, [recipient], msg.as_string())
