"""Tests for Debian architecture suffix stripping in inventory parser (25-03).

RED phase: These tests verify that:
  1. strip_debian_arch_suffix correctly identifies and strips valid arch suffixes.
  2. Invalid (non-arch) suffixes are left untouched.
  3. parse_tab_separated_line applies the strip when parsing Debian package lines.
  4. parse_space_separated_line is unaffected.
"""
from __future__ import annotations

from aila.modules.vulnerability.adapters.inventory import (
    parse_space_separated_line,
    parse_tab_separated_line,
    strip_debian_arch_suffix,
)

# ---------------------------------------------------------------------------
# strip_debian_arch_suffix — all 8 behavior cases from plan
# ---------------------------------------------------------------------------

def test_strip_amd64_suffix() -> None:
    """strip_debian_arch_suffix('libssl1.1:amd64') returns 'libssl1.1'."""
    assert strip_debian_arch_suffix("libssl1.1:amd64") == "libssl1.1"


def test_strip_arm64_suffix() -> None:
    """strip_debian_arch_suffix('curl:arm64') returns 'curl'."""
    assert strip_debian_arch_suffix("curl:arm64") == "curl"


def test_no_colon_unchanged() -> None:
    """strip_debian_arch_suffix('python3') returns 'python3' (no colon)."""
    assert strip_debian_arch_suffix("python3") == "python3"


def test_dash_in_suffix_unchanged() -> None:
    """strip_debian_arch_suffix('libfoo:bar-baz') returns unchanged (dash in suffix is not arch)."""
    assert strip_debian_arch_suffix("libfoo:bar-baz") == "libfoo:bar-baz"


def test_uppercase_in_suffix_unchanged() -> None:
    """strip_debian_arch_suffix('libfoo:Bar64') returns unchanged (uppercase in suffix is not arch)."""
    assert strip_debian_arch_suffix("libfoo:Bar64") == "libfoo:Bar64"


def test_empty_string_unchanged() -> None:
    """strip_debian_arch_suffix('') returns ''."""
    assert strip_debian_arch_suffix("") == ""


def test_empty_suffix_unchanged() -> None:
    """strip_debian_arch_suffix('libfoo:') returns 'libfoo:' (empty suffix is not an arch token)."""
    assert strip_debian_arch_suffix("libfoo:") == "libfoo:"


def test_i386_suffix() -> None:
    """strip_debian_arch_suffix strips i386 suffix."""
    assert strip_debian_arch_suffix("libpam0g:i386") == "libpam0g"


# ---------------------------------------------------------------------------
# parse_tab_separated_line with arch suffix
# ---------------------------------------------------------------------------

def test_parse_tab_separated_line_strips_arch_suffix() -> None:
    """parse_tab_separated_line('libssl1.1:amd64\t1.1.1-1') returns ('libssl1.1', '1.1.1-1')."""
    result = parse_tab_separated_line("libssl1.1:amd64\t1.1.1-1")
    assert result == ("libssl1.1", "1.1.1-1")


def test_parse_tab_separated_line_no_arch_suffix_unchanged() -> None:
    """parse_tab_separated_line('curl\t7.68.0') returns ('curl', '7.68.0') (no colon, unchanged)."""
    result = parse_tab_separated_line("curl\t7.68.0")
    assert result == ("curl", "7.68.0")


# ---------------------------------------------------------------------------
# parse_space_separated_line is NOT modified
# ---------------------------------------------------------------------------

def test_parse_space_separated_line_colon_unchanged() -> None:
    """parse_space_separated_line does not strip arch suffixes (used by Alpine/Arch, not Debian)."""
    result = parse_space_separated_line("libssl1.1:amd64 1.1.1-1")
    # Space-separated parser should NOT strip arch suffix — unmodified
    assert result == ("libssl1.1:amd64", "1.1.1-1")
