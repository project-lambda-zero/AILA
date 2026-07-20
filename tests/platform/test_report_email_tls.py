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


def test_send_report_email_implicit_tls_uses_smtps(monkeypatch) -> None:
    """With implicit TLS the send path connects over SMTPS (SMTP_SSL) with a
    verifying context and never falls back to plaintext SMTP + STARTTLS."""
    server = MagicMock()
    smtps_cm = MagicMock()
    smtps_cm.__enter__.return_value = server
    smtps_cm.__exit__.return_value = False
    smtp_ssl = MagicMock(return_value=smtps_cm)
    monkeypatch.setattr(report_tasks.smtplib, "SMTP_SSL", smtp_ssl)
    monkeypatch.setattr(
        report_tasks.smtplib,
        "SMTP",
        MagicMock(side_effect=AssertionError("plaintext SMTP used in implicit-TLS mode")),
    )

    report_tasks._send_report_email(
        smtp_host="smtp.example.com",
        smtp_port=465,
        smtp_from="from@example.com",
        smtp_username="user",
        smtp_password="pass",
        recipient="to@example.com",
        report_name="Test Report",
        date_str="2026-07-20",
        pdf_bytes=b"%PDF-1.4 test",
        use_implicit_tls=True,
    )

    smtp_ssl.assert_called_once()
    context = smtp_ssl.call_args.kwargs.get("context")
    assert isinstance(context, ssl.SSLContext)
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    server.starttls.assert_not_called()
    server.login.assert_called_once_with("user", "pass")
    server.sendmail.assert_called_once()


def test_send_report_email_uses_admin_ca_bundle(monkeypatch) -> None:
    """An admin-configured CA bundle path is passed to the TLS context so a
    private-CA SMTP server can be verified instead of downgrading trust."""
    server = MagicMock()
    smtp_cm = MagicMock()
    smtp_cm.__enter__.return_value = server
    smtp_cm.__exit__.return_value = False
    monkeypatch.setattr(report_tasks.smtplib, "SMTP", MagicMock(return_value=smtp_cm))

    captured: dict[str, object] = {}
    real_ctx = ssl.create_default_context()

    def _fake_ctx(*_args, **kwargs):
        captured["cafile"] = kwargs.get("cafile")
        return real_ctx

    monkeypatch.setattr(report_tasks.ssl, "create_default_context", _fake_ctx)

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
        ca_bundle_path="/etc/ssl/custom-ca.pem",
    )

    assert captured["cafile"] == "/etc/ssl/custom-ca.pem"
    server.starttls.assert_called_once()
