"""Report-email TLS verification test for #48 / #45.

Scheduled report emails carry security findings. STARTTLS was called with
no SSL context, so the server certificate was not verified (a MITM path).
The send path now passes a verifying default context.
"""
from __future__ import annotations

import ssl
from unittest.mock import MagicMock

from aila.platform.tasks import report_tasks


def test_send_report_email_uses_verifying_tls(monkeypatch) -> None:
    server = MagicMock()
    smtp_cm = MagicMock()
    smtp_cm.__enter__.return_value = server
    smtp_cm.__exit__.return_value = False
    monkeypatch.setattr(report_tasks.smtplib, "SMTP", MagicMock(return_value=smtp_cm))

    report_tasks._send_report_email(
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_from="from@example.com",
        smtp_username=None,
        smtp_password=None,
        recipient="to@example.com",
        report_name="Test Report",
        date_str="2026-07-20",
        pdf_bytes=b"%PDF-1.4 test",
    )

    server.starttls.assert_called_once()
    context = server.starttls.call_args.kwargs.get("context")
    assert isinstance(context, ssl.SSLContext)
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    server.sendmail.assert_called_once()
