"""Provider-error redaction boundary tests (#44).

Provider exception strings raised by upstream HTTP clients (openai,
anthropic) can echo request material that carries credentials -- an
``Authorization: Bearer sk-...`` header, an ``api_key=sk-...`` query
parameter, or a bare ``sk-`` prefixed key inline in error prose. The
LLM client's ``_call_with_retry`` routes those strings through
:func:`aila.platform.services.log_redact.redact_secrets` before they
land in a re-raised ``LLMError`` message or a warning log line. These
tests pin the redactor's coverage against every shape the provider
adapter has been observed to emit, and verify that the exact
``f``-string composed by the client wrap site produces a redacted
message.

Pure unit tests: no DB, no network, no real provider client.
"""
from __future__ import annotations

from aila.platform.llm.errors import LLMError
from aila.platform.services.log_redact import (
    redact_command_line,
    redact_secrets,
)

_SECRET = "sk-live-abc123"
_ANTHROPIC_SECRET = "sk-ant-api03-deadbeefcafe1234"


def test_redacts_authorization_bearer_header() -> None:
    text = f"401 Unauthorized -- Authorization: Bearer {_SECRET} rejected"
    out = redact_secrets(text)
    assert _SECRET not in out
    assert "[REDACTED]" in out


def test_redacts_bare_bearer_without_authorization_prefix() -> None:
    # Provider clients sometimes echo just ``Bearer <token>`` without
    # the ``Authorization:`` framing.
    text = f"invalid credentials: Bearer {_SECRET}"
    out = redact_secrets(text)
    assert _SECRET not in out
    assert "[REDACTED]" in out


def test_redacts_api_key_query_parameter() -> None:
    text = f"HTTPError GET https://api.example.com/v1/chat?api_key={_SECRET}"
    out = redact_secrets(text)
    assert _SECRET not in out
    assert "[REDACTED]" in out


def test_redacts_bare_openai_key_inline() -> None:
    # No preceding marker at all; the raw key appears in prose.
    text = f"invalid api key provided: {_SECRET} (org: default)"
    out = redact_secrets(text)
    assert _SECRET not in out
    assert "[REDACTED]" in out


def test_redacts_bare_anthropic_key_inline() -> None:
    text = f"forbidden -- key {_ANTHROPIC_SECRET} is disabled"
    out = redact_secrets(text)
    assert _ANTHROPIC_SECRET not in out
    assert "[REDACTED]" in out


def test_redacts_multiple_shapes_in_one_string() -> None:
    text = (
        f"provider error: Authorization: Bearer {_SECRET} "
        f"and api_key={_ANTHROPIC_SECRET} both rejected"
    )
    out = redact_secrets(text)
    assert _SECRET not in out
    assert _ANTHROPIC_SECRET not in out
    assert out.count("[REDACTED]") >= 2


def test_non_secret_text_passes_through_unchanged() -> None:
    text = "provider error: 503 Service Unavailable -- upstream timeout"
    assert redact_secrets(text) == text


def test_empty_input_unchanged() -> None:
    assert redact_secrets("") == ""


def test_short_sk_prefix_not_over_redacted() -> None:
    # ``sk-abc`` is below the 6-char floor of the bare-key regex, so a
    # short identifier that happens to start with ``sk-`` is preserved.
    text = "note: sk-abc is not a real key"
    assert redact_secrets(text) == text


def test_command_line_helper_still_covers_original_markers() -> None:
    # Regression: extending log_redact.py must not break the C6
    # command-line boundary already relied on by SSH and process
    # execution paths.
    assert redact_command_line("mysql -p hunter2 -h db") == (
        "mysql -p [REDACTED] -h db"
    )
    assert redact_command_line("psql password=hunter2 host=db") == (
        "psql password=[REDACTED] host=db"
    )


def test_client_wrap_site_message_composition() -> None:
    # Reproduces the exact ``f``-string composed at
    # ``client._call_with_retry`` when the retry ceiling is hit. A
    # provider exception carrying an Authorization header is passed as
    # ``last_error``; the resulting ``LLMError`` message must not
    # contain the secret token.
    class UpstreamAuthError(Exception):
        pass

    last_error = UpstreamAuthError(
        f"401 Unauthorized -- Authorization: Bearer {_SECRET}",
    )
    max_retries = 3
    wrapped = LLMError(
        f"LLM API failed after {max_retries} retries: "
        f"{redact_secrets(str(last_error))}",
        retryable=True,
    )
    assert _SECRET not in wrapped.message
    assert "[REDACTED]" in wrapped.message
    assert wrapped.retryable is True
    # The propagated exception type is preserved -- only the message
    # text is redacted.
    assert isinstance(wrapped, LLMError)


def test_client_warning_log_composition_truncated() -> None:
    # Reproduces the warning-log site: ``redact_secrets(str(exc))[:200]``.
    # Redaction must run BEFORE truncation so a secret straddling the
    # 200-char boundary is still masked.
    padding = "x" * 150
    exc_text = f"{padding} Authorization: Bearer {_SECRET} tail"
    redacted = redact_secrets(exc_text)[:200]
    assert _SECRET not in redacted
    assert "[REDACTED]" in redacted
