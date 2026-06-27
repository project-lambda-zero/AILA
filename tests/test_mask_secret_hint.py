"""Tests for mask_secret_hint() -- D-05 prefix+mask / length-only contract."""
from __future__ import annotations

import pytest

from aila.storage.secrets import mask_secret_hint


@pytest.mark.parametrize(
    "value, expected",
    [
        # Empty -> literal "empty"
        ("", "empty"),
        # Short secrets (< 4 chars) -> length-only, no chars revealed
        ("a", "[1 chars]"),
        ("ab", "[2 chars]"),
        ("abc", "[3 chars]"),
        # 4+ chars -> first 2 + mask
        ("abcd", "ab**"),
        ("secret123", "se**"),
        ("mysupersecretapikey", "my**"),
        ("x" * 100, "xx**"),
    ],
)
def test_mask_secret_hint(value: str, expected: str) -> None:
    assert mask_secret_hint(value) == expected


def test_no_suffix_exposure() -> None:
    """No output must contain any character from position 2 onward."""
    secret = "secret123"
    result = mask_secret_hint(secret)
    # Only first 2 chars ("se") are allowed; the rest must not appear
    for ch in secret[2:]:
        assert ch not in result or result == "se**", (
            f"mask_secret_hint leaked suffix character '{ch}' in {result!r}"
        )


def test_old_format_gone() -> None:
    """The old 'len=N ending=XXXX' format must never appear."""
    secret = "secret123"
    result = mask_secret_hint(secret)
    assert "ending=" not in result
    assert "len=" not in result
