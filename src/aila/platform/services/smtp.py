"""Shared SMTP transport: one place that opens, upgrades, authenticates, and sends.

Callers build the message; this module owns the socket: implicit TLS or STARTTLS with
certificate verification on in both modes, an optional admin-managed CA bundle, optional
AUTH, and a bounded timeout. Exceptions from smtplib propagate unchanged so callers can
map them to their own outcomes.
"""
from __future__ import annotations

import smtplib
import ssl
from collections.abc import Sequence
from email.message import Message
from typing import Literal

__all__ = ["TlsMode", "send_smtp_email"]

TlsMode = Literal["implicit", "starttls", "none"]


def send_smtp_email(
    message: Message,
    *,
    host: str,
    port: int,
    sender: str,
    recipients: Sequence[str],
    timeout: float,
    tls_mode: TlsMode = "starttls",
    username: str | None = None,
    password: str | None = None,
    ca_bundle_path: str | None = None,
) -> dict[str, tuple[int, bytes]]:
    """Send ``message`` and return the server's refused-recipient map (empty when all accepted).

    ``tls_mode`` is ``implicit`` (SMTPS), ``starttls`` (plaintext then upgrade), or ``none``.
    Login runs only when both ``username`` and ``password`` are set, and never without TLS.
    ``ca_bundle_path`` None uses the system trust store; an invalid path raises.
    """
    if bool(username) != bool(password):
        raise ValueError("SMTP username and password must be provided together")
    if username and password and tls_mode == "none":
        raise ValueError("SMTP credentials require implicit TLS or STARTTLS")
    context = ssl.create_default_context(cafile=ca_bundle_path or None)
    if tls_mode == "implicit":
        server: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
    else:
        server = smtplib.SMTP(host, port, timeout=timeout)
    with server as connection:
        connection.ehlo()
        if tls_mode == "starttls":
            connection.starttls(context=context)
        if username and password:
            connection.login(username, password)
        return connection.sendmail(sender, list(recipients), message.as_string())
