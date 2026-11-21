"""Spreadsheet formula neutralisation for CSV cells built from untrusted data."""

from __future__ import annotations

from typing import Any

__all__ = ["csv_safe_cell"]

_FORMULA_PREFIXES = ("=", "+", "-", "@")


def csv_safe_cell(value: Any) -> str:
    """Render a CSV cell as text, prefixing a single quote when a spreadsheet would read it as a formula."""
    text = str(value if value is not None else "")
    return "'" + text if text.lstrip(" \t\r\n").startswith(_FORMULA_PREFIXES) else text
