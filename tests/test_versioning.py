"""Comprehensive tests for package version comparison utilities.

Covers all public and internal functions in
``aila.modules.vulnerability.versioning``:

- ``VersionScheme`` enum values
- ``version_scheme_for_distribution`` mapping
- ``normalize_generic_version`` tokenization
- ``compare_generic_versions`` ordering
- ``split_release_version`` RPM-style parsing
- ``compare_release_versions`` RPM-style ordering
- ``split_debian_version`` dpkg-style parsing
- ``compare_debian_part`` dpkg character-level ordering
- ``compare_debian_non_digit_run`` non-digit subsequence ordering
- ``debian_non_digit_order`` single-character weight
- ``compare_debian_digit_run`` numeric subsequence ordering
- ``consume_non_digits`` / ``consume_digits`` scanners
- ``compare_versions`` top-level dispatcher
"""
from __future__ import annotations

import pytest

from aila.modules.vulnerability.versioning import (
    VersionScheme,
    compare_debian_digit_run,
    compare_debian_non_digit_run,
    compare_debian_part,
    compare_debian_versions,
    compare_generic_versions,
    compare_release_versions,
    compare_versions,
    consume_digits,
    consume_non_digits,
    debian_non_digit_order,
    normalize_generic_version,
    split_debian_version,
    split_release_version,
    version_scheme_for_distribution,
)


# ---------------------------------------------------------------------------
# VersionScheme enum
# ---------------------------------------------------------------------------


class TestVersionScheme:
    """VersionScheme string enum has exactly three members."""

    def test_generic_value(self) -> None:
        assert VersionScheme.GENERIC == "generic"

    def test_debian_value(self) -> None:
        assert VersionScheme.DEBIAN == "debian"

    def test_release_value(self) -> None:
        assert VersionScheme.RELEASE == "release"

    def test_member_count(self) -> None:
        assert len(VersionScheme) == 3

    def test_is_str_subclass(self) -> None:
        assert isinstance(VersionScheme.GENERIC, str)


# ---------------------------------------------------------------------------
# version_scheme_for_distribution
# ---------------------------------------------------------------------------


class TestVersionSchemeForDistribution:
    """Map distribution names to comparison schemes."""

    @pytest.mark.parametrize("dist", ["ubuntu", "Ubuntu", "UBUNTU", "  ubuntu  "])
    def test_ubuntu_returns_debian(self, dist: str) -> None:
        assert version_scheme_for_distribution(dist) == VersionScheme.DEBIAN

    @pytest.mark.parametrize("dist", ["debian", "Debian", "DEBIAN", "  debian  "])
    def test_debian_returns_debian(self, dist: str) -> None:
        assert version_scheme_for_distribution(dist) == VersionScheme.DEBIAN

    @pytest.mark.parametrize("dist", ["arch", "Arch", "ARCH", "  arch  "])
    def test_arch_returns_release(self, dist: str) -> None:
        assert version_scheme_for_distribution(dist) == VersionScheme.RELEASE

    @pytest.mark.parametrize("dist", ["alpine", "Alpine", "ALPINE", "  alpine  "])
    def test_alpine_returns_release(self, dist: str) -> None:
        assert version_scheme_for_distribution(dist) == VersionScheme.RELEASE

    @pytest.mark.parametrize("dist", ["fedora", "centos", "rhel", "windows", "macos", ""])
    def test_other_returns_generic(self, dist: str) -> None:
        assert version_scheme_for_distribution(dist) == VersionScheme.GENERIC

    def test_none_returns_generic(self) -> None:
        assert version_scheme_for_distribution(None) == VersionScheme.GENERIC


# ---------------------------------------------------------------------------
# normalize_generic_version
# ---------------------------------------------------------------------------


class TestNormalizeGenericVersion:
    """Tokenize version strings into int/str parts."""

    def test_simple_dotted(self) -> None:
        assert normalize_generic_version("1.2.3") == [1, 2, 3]

    def test_colon_separator(self) -> None:
        assert normalize_generic_version("1:2.3") == [1, 2, 3]

    def test_hyphen_separator(self) -> None:
        assert normalize_generic_version("1.2-3") == [1, 2, 3]

    def test_plus_separator(self) -> None:
        assert normalize_generic_version("1.2+3") == [1, 2, 3]

    def test_underscore_separator(self) -> None:
        assert normalize_generic_version("1.2_3") == [1, 2, 3]

    def test_mixed_separators(self) -> None:
        """All separator types normalize to dots: '1:2.3-4+5_6'."""
        assert normalize_generic_version("1:2.3-4+5_6") == [1, 2, 3, 4, 5, 6]

    def test_alpha_tokens_are_strings(self) -> None:
        assert normalize_generic_version("1.2.3alpha") == [1, 2, 3, "alpha"]

    def test_mixed_alpha_numeric(self) -> None:
        assert normalize_generic_version("1.2a3") == [1, 2, "a", 3]

    def test_uppercase_lowered(self) -> None:
        """Uppercase letters are lowered before tokenization."""
        result = normalize_generic_version("1.2.RC1")
        assert result == [1, 2, "rc", 1]

    def test_empty_string(self) -> None:
        assert normalize_generic_version("") == []

    def test_pure_numeric(self) -> None:
        assert normalize_generic_version("42") == [42]

    def test_pure_alpha(self) -> None:
        assert normalize_generic_version("beta") == ["beta"]

    def test_leading_zeros_as_int(self) -> None:
        """Numeric tokens with leading zeros become plain ints (009 -> 9)."""
        assert normalize_generic_version("01.009.3") == [1, 9, 3]


# ---------------------------------------------------------------------------
# compare_generic_versions
# ---------------------------------------------------------------------------


class TestCompareGenericVersions:
    """Tokenized dot-separated version comparison."""

    def test_equal_simple(self) -> None:
        assert compare_generic_versions("1.2.3", "1.2.3") == 0

    def test_left_less_than(self) -> None:
        assert compare_generic_versions("1.2.3", "1.2.4") == -1

    def test_left_greater_than(self) -> None:
        assert compare_generic_versions("1.2.4", "1.2.3") == 1

    def test_different_lengths_shorter_less(self) -> None:
        """'1.2' < '1.2.1' because the missing token fills as 0."""
        assert compare_generic_versions("1.2", "1.2.1") == -1

    def test_different_lengths_shorter_equal_with_zero(self) -> None:
        """'1.2' == '1.2.0' because trailing zero is the fill value."""
        assert compare_generic_versions("1.2", "1.2.0") == 0

    def test_major_version_difference(self) -> None:
        assert compare_generic_versions("2.0.0", "1.99.99") == 1

    def test_numeric_beats_string(self) -> None:
        """Numeric token sorts higher than string token at same position."""
        assert compare_generic_versions("1.2.3", "1.2.beta") == 1

    def test_string_loses_to_numeric(self) -> None:
        assert compare_generic_versions("1.2.beta", "1.2.3") == -1

    def test_string_vs_string_lexicographic(self) -> None:
        """String tokens compared lexicographically."""
        assert compare_generic_versions("1.2.alpha", "1.2.beta") == -1

    def test_string_vs_string_equal(self) -> None:
        assert compare_generic_versions("1.2.rc", "1.2.rc") == 0

    def test_string_vs_string_greater(self) -> None:
        assert compare_generic_versions("1.2.beta", "1.2.alpha") == 1

    def test_both_empty(self) -> None:
        assert compare_generic_versions("", "") == 0

    def test_empty_vs_nonempty(self) -> None:
        """Empty string is less than any version with content."""
        assert compare_generic_versions("", "1") == -1

    def test_nonempty_vs_empty(self) -> None:
        assert compare_generic_versions("1", "") == 1

    def test_separator_normalization(self) -> None:
        """Different separators yield equal comparison."""
        assert compare_generic_versions("1:2-3", "1.2.3") == 0

    def test_large_numbers(self) -> None:
        assert compare_generic_versions("1.100.0", "1.99.0") == 1

    def test_fill_value_zero_against_string(self) -> None:
        """When one side is exhausted (fill=0, int) and other has a string token, int > string."""
        assert compare_generic_versions("1.2", "1.2.beta") == 1


# ---------------------------------------------------------------------------
# split_release_version
# ---------------------------------------------------------------------------


class TestSplitReleaseVersion:
    """Parse RPM-style epoch:version-release strings."""

    def test_full_format(self) -> None:
        assert split_release_version("1:2.3.4-5") == (1, "2.3.4", "5")

    def test_no_epoch_no_release(self) -> None:
        assert split_release_version("2.3.4") == (0, "2.3.4", "0")

    def test_epoch_no_release(self) -> None:
        assert split_release_version("3:1.0") == (3, "1.0", "0")

    def test_no_epoch_with_release(self) -> None:
        assert split_release_version("1.0-2") == (0, "1.0", "2")

    def test_epoch_zero_explicit(self) -> None:
        assert split_release_version("0:1.0-1") == (0, "1.0", "1")

    def test_non_numeric_epoch_ignored(self) -> None:
        """Non-numeric epoch part keeps epoch as 0, colon stays in remainder."""
        epoch, version, release = split_release_version("abc:1.0-1")
        assert epoch == 0

    def test_multiple_hyphens_uses_last(self) -> None:
        """rsplit('-', 1) means only the last hyphen separates the release."""
        assert split_release_version("1.0-beta-2") == (0, "1.0-beta", "2")

    def test_empty_release_after_hyphen(self) -> None:
        """Trailing hyphen: tail is empty, so release stays '0' and hyphen stays."""
        epoch, version, release = split_release_version("1.0-")
        assert release == "0"

    def test_empty_string(self) -> None:
        assert split_release_version("") == (0, "", "0")

    def test_large_epoch(self) -> None:
        assert split_release_version("99:5.0-3") == (99, "5.0", "3")


# ---------------------------------------------------------------------------
# compare_release_versions
# ---------------------------------------------------------------------------


class TestCompareReleaseVersions:
    """RPM-style epoch:version-release comparison."""

    def test_equal(self) -> None:
        assert compare_release_versions("1:1.0-1", "1:1.0-1") == 0

    def test_epoch_wins(self) -> None:
        assert compare_release_versions("2:1.0-1", "1:9.9-9") == 1

    def test_epoch_lower(self) -> None:
        assert compare_release_versions("1:9.9-9", "2:1.0-1") == -1

    def test_version_differs_same_epoch(self) -> None:
        assert compare_release_versions("1:1.1-1", "1:1.0-1") == 1

    def test_release_differs_same_epoch_and_version(self) -> None:
        assert compare_release_versions("1:1.0-2", "1:1.0-1") == 1

    def test_no_epoch_treated_as_zero(self) -> None:
        """Both without epoch are equal in epoch component."""
        assert compare_release_versions("1.0-1", "0:1.0-1") == 0

    def test_no_release_treated_as_zero(self) -> None:
        assert compare_release_versions("1.0", "1.0-0") == 0

    def test_version_less(self) -> None:
        assert compare_release_versions("1.0-1", "1.1-1") == -1

    def test_release_less(self) -> None:
        assert compare_release_versions("1.0-1", "1.0-2") == -1


# ---------------------------------------------------------------------------
# split_debian_version
# ---------------------------------------------------------------------------


class TestSplitDebianVersion:
    """Parse Debian epoch:upstream-revision strings."""

    def test_full_format(self) -> None:
        assert split_debian_version("2:1.5.3-4ubuntu1") == (2, "1.5.3", "4ubuntu1")

    def test_no_epoch_no_revision(self) -> None:
        assert split_debian_version("1.2.3") == (0, "1.2.3", "0")

    def test_epoch_no_revision(self) -> None:
        assert split_debian_version("1:2.3") == (1, "2.3", "0")

    def test_no_epoch_with_revision(self) -> None:
        assert split_debian_version("1.2.3-4") == (0, "1.2.3", "4")

    def test_non_numeric_epoch_stays_zero(self) -> None:
        epoch, upstream, revision = split_debian_version("abc:1.0-1")
        assert epoch == 0

    def test_multiple_hyphens_last_wins(self) -> None:
        """rsplit('-', 1): last hyphen separates revision."""
        assert split_debian_version("1.0-beta-2") == (0, "1.0-beta", "2")

    def test_multiple_colons_first_wins(self) -> None:
        """split(':', 1): first colon separates epoch."""
        assert split_debian_version("1:2:3-4") == (1, "2:3", "4")

    def test_empty_string(self) -> None:
        assert split_debian_version("") == (0, "", "0")

    def test_zero_epoch_explicit(self) -> None:
        assert split_debian_version("0:1.0-1") == (0, "1.0", "1")

    def test_complex_ubuntu_version(self) -> None:
        assert split_debian_version("2:8.2.3995-1ubuntu3.2") == (2, "8.2.3995", "1ubuntu3.2")


# ---------------------------------------------------------------------------
# consume_non_digits / consume_digits
# ---------------------------------------------------------------------------


class TestConsumeNonDigits:
    """Scan non-digit characters from a starting index."""

    def test_start_of_alpha(self) -> None:
        assert consume_non_digits("abc123", 0) == ("abc", 3)

    def test_start_at_digit(self) -> None:
        assert consume_non_digits("123abc", 0) == ("", 0)

    def test_middle_of_string(self) -> None:
        assert consume_non_digits("12abc34", 2) == ("abc", 5)

    def test_empty_string(self) -> None:
        assert consume_non_digits("", 0) == ("", 0)

    def test_all_non_digits(self) -> None:
        assert consume_non_digits("abc", 0) == ("abc", 3)

    def test_tilde_consumed(self) -> None:
        """Tilde is non-digit and consumed."""
        assert consume_non_digits("~beta", 0) == ("~beta", 5)

    def test_special_chars(self) -> None:
        assert consume_non_digits(".+~a", 0) == (".+~a", 4)

    def test_at_end(self) -> None:
        assert consume_non_digits("abc", 3) == ("", 3)


class TestConsumeDigits:
    """Scan digit characters from a starting index."""

    def test_start_of_digits(self) -> None:
        assert consume_digits("123abc", 0) == ("123", 3)

    def test_start_at_alpha(self) -> None:
        assert consume_digits("abc123", 0) == ("", 0)

    def test_middle_of_string(self) -> None:
        assert consume_digits("abc123def", 3) == ("123", 6)

    def test_empty_string(self) -> None:
        assert consume_digits("", 0) == ("", 0)

    def test_all_digits(self) -> None:
        assert consume_digits("9876", 0) == ("9876", 4)

    def test_at_end(self) -> None:
        assert consume_digits("123", 3) == ("", 3)


# ---------------------------------------------------------------------------
# debian_non_digit_order
# ---------------------------------------------------------------------------


class TestDebianNonDigitOrder:
    """Dpkg ordering weight for a single character."""

    def test_tilde_is_negative(self) -> None:
        """Tilde sorts before everything, including empty."""
        assert debian_non_digit_order("~") == -1

    def test_empty_is_zero(self) -> None:
        assert debian_non_digit_order("") == 0

    def test_alpha_returns_ord(self) -> None:
        assert debian_non_digit_order("a") == ord("a")
        assert debian_non_digit_order("Z") == ord("Z")

    def test_non_alpha_non_tilde_non_empty(self) -> None:
        """Non-alpha characters (like '.', '+', '-') get ord + 256."""
        assert debian_non_digit_order(".") == ord(".") + 256
        assert debian_non_digit_order("+") == ord("+") + 256
        assert debian_non_digit_order("-") == ord("-") + 256

    def test_ordering_hierarchy(self) -> None:
        """Tilde < empty < alpha < non-alpha-non-tilde."""
        tilde = debian_non_digit_order("~")
        empty = debian_non_digit_order("")
        alpha = debian_non_digit_order("a")
        dot = debian_non_digit_order(".")
        assert tilde < empty < alpha < dot


# ---------------------------------------------------------------------------
# compare_debian_non_digit_run
# ---------------------------------------------------------------------------


class TestCompareDebianNonDigitRun:
    """Compare two non-digit subsequences using Debian ordering."""

    def test_equal_strings(self) -> None:
        assert compare_debian_non_digit_run("abc", "abc") == 0

    def test_both_empty(self) -> None:
        assert compare_debian_non_digit_run("", "") == 0

    def test_tilde_less_than_empty(self) -> None:
        """'~' sorts before end-of-string."""
        assert compare_debian_non_digit_run("~", "") == -1

    def test_empty_greater_than_tilde(self) -> None:
        assert compare_debian_non_digit_run("", "~") == 1

    def test_tilde_less_than_alpha(self) -> None:
        assert compare_debian_non_digit_run("~", "a") == -1

    def test_alpha_less_than_dot(self) -> None:
        """Letters sort before non-alpha punctuation in Debian."""
        assert compare_debian_non_digit_run("a", ".") == -1

    def test_dot_greater_than_alpha(self) -> None:
        assert compare_debian_non_digit_run(".", "a") == 1

    def test_longer_left_with_tilde(self) -> None:
        """Left has trailing tilde which sorts below empty on right."""
        assert compare_debian_non_digit_run("a~", "a") == -1

    def test_character_by_character(self) -> None:
        """Second character decides when first is equal."""
        assert compare_debian_non_digit_run("ab", "ac") == -1
        assert compare_debian_non_digit_run("ac", "ab") == 1


# ---------------------------------------------------------------------------
# compare_debian_digit_run
# ---------------------------------------------------------------------------


class TestCompareDebianDigitRun:
    """Compare two digit subsequences as Debian-normalized integers."""

    def test_equal(self) -> None:
        assert compare_debian_digit_run("123", "123") == 0

    def test_less(self) -> None:
        assert compare_debian_digit_run("12", "123") == -1

    def test_greater(self) -> None:
        assert compare_debian_digit_run("123", "12") == 1

    def test_leading_zeros_ignored(self) -> None:
        """Leading zeros are stripped: '007' == '7'."""
        assert compare_debian_digit_run("007", "7") == 0

    def test_both_empty(self) -> None:
        """Both empty normalize to '0', so equal."""
        assert compare_debian_digit_run("", "") == 0

    def test_empty_vs_zero(self) -> None:
        assert compare_debian_digit_run("", "0") == 0

    def test_empty_vs_nonzero(self) -> None:
        assert compare_debian_digit_run("", "1") == -1

    def test_nonzero_vs_empty(self) -> None:
        assert compare_debian_digit_run("1", "") == 1

    def test_same_length_different_values(self) -> None:
        assert compare_debian_digit_run("456", "789") == -1
        assert compare_debian_digit_run("789", "456") == 1

    def test_all_zeros(self) -> None:
        assert compare_debian_digit_run("0000", "0") == 0

    def test_large_numbers(self) -> None:
        assert compare_debian_digit_run("99999", "100000") == -1


# ---------------------------------------------------------------------------
# compare_debian_part
# ---------------------------------------------------------------------------


class TestCompareDebianPart:
    """Full Debian part comparison (alternating non-digit and digit runs)."""

    def test_equal(self) -> None:
        assert compare_debian_part("1.2.3", "1.2.3") == 0

    def test_less(self) -> None:
        assert compare_debian_part("1.2.3", "1.2.4") == -1

    def test_greater(self) -> None:
        assert compare_debian_part("1.2.4", "1.2.3") == 1

    def test_tilde_prerelease_sorts_before(self) -> None:
        """'1.0~beta1' < '1.0' because tilde sorts before end-of-string."""
        assert compare_debian_part("1.0~beta1", "1.0") == -1

    def test_tilde_prerelease_ordering(self) -> None:
        """'1.0~alpha' < '1.0~beta'."""
        assert compare_debian_part("1.0~alpha", "1.0~beta") == -1

    def test_both_empty(self) -> None:
        assert compare_debian_part("", "") == 0

    def test_alpha_suffix(self) -> None:
        """'1.0a' vs '1.0b': non-digit run 'a' < 'b'."""
        assert compare_debian_part("1.0a", "1.0b") == -1

    def test_numeric_difference_in_run(self) -> None:
        """'1.10' > '1.9' — numeric comparison, not lexicographic."""
        assert compare_debian_part("1.10", "1.9") == 1

    def test_only_non_digit(self) -> None:
        assert compare_debian_part("abc", "abd") == -1

    def test_leading_non_digit_vs_digit(self) -> None:
        """Non-digit run precedes digit run in the alternation."""
        assert compare_debian_part("a1", "b1") == -1
        assert compare_debian_part("a1", "a2") == -1


# ---------------------------------------------------------------------------
# compare_debian_versions (full epoch:upstream-revision)
# ---------------------------------------------------------------------------


class TestCompareDebianVersions:
    """End-to-end Debian version comparison including epoch and revision."""

    def test_equal(self) -> None:
        assert compare_debian_versions("1:1.0-1", "1:1.0-1") == 0

    def test_epoch_wins(self) -> None:
        assert compare_debian_versions("2:1.0-1", "1:99.99-99") == 1

    def test_epoch_lower(self) -> None:
        assert compare_debian_versions("1:99.99-99", "2:1.0-1") == -1

    def test_upstream_differs(self) -> None:
        assert compare_debian_versions("1:1.1-1", "1:1.0-1") == 1

    def test_revision_differs(self) -> None:
        assert compare_debian_versions("1:1.0-2", "1:1.0-1") == 1

    def test_no_epoch_equals_zero_epoch(self) -> None:
        assert compare_debian_versions("1.0-1", "0:1.0-1") == 0

    def test_no_revision_equals_zero_revision(self) -> None:
        assert compare_debian_versions("1.0", "1.0-0") == 0

    def test_tilde_in_upstream(self) -> None:
        """'1.0~rc1-1' < '1.0-1' due to tilde."""
        assert compare_debian_versions("1.0~rc1-1", "1.0-1") == -1

    def test_tilde_in_revision(self) -> None:
        """Tilde in revision: '1.0-1~exp' < '1.0-1'."""
        assert compare_debian_versions("1.0-1~exp", "1.0-1") == -1

    def test_complex_ubuntu_pair(self) -> None:
        """Real-world Ubuntu version pair."""
        assert compare_debian_versions("2:8.2.3995-1ubuntu3.1", "2:8.2.3995-1ubuntu3.2") == -1

    def test_ubuntu_vs_debian_revision(self) -> None:
        """'1.0-1ubuntu1' > '1.0-1' because 'ubuntu1' extends the revision."""
        assert compare_debian_versions("1.0-1ubuntu1", "1.0-1") == 1


# ---------------------------------------------------------------------------
# compare_versions (top-level dispatcher)
# ---------------------------------------------------------------------------


class TestCompareVersions:
    """Top-level compare_versions dispatches to the correct scheme."""

    def test_debian_distribution(self) -> None:
        """Dispatches to Debian comparison for 'debian'."""
        assert compare_versions("1.0~rc1", "1.0", distribution="debian") == -1

    def test_ubuntu_distribution(self) -> None:
        """Dispatches to Debian comparison for 'ubuntu'."""
        assert compare_versions("1.0~rc1", "1.0", distribution="ubuntu") == -1

    def test_arch_distribution(self) -> None:
        """Dispatches to release comparison for 'arch'."""
        assert compare_versions("1:1.0-1", "1:1.0-2", distribution="arch") == -1

    def test_alpine_distribution(self) -> None:
        """Dispatches to release comparison for 'alpine'."""
        assert compare_versions("1:1.0-1", "1:1.0-2", distribution="alpine") == -1

    def test_generic_distribution(self) -> None:
        """Dispatches to generic comparison for unknown distro."""
        assert compare_versions("1.2.3", "1.2.4", distribution="fedora") == -1

    def test_none_distribution(self) -> None:
        """None distribution uses generic comparison."""
        assert compare_versions("1.2.3", "1.2.3", distribution=None) == 0

    def test_no_distribution_argument(self) -> None:
        """Omitted distribution defaults to None -> generic."""
        assert compare_versions("2.0", "1.0") == 1

    def test_equal_all_schemes(self) -> None:
        """Equal versions return 0 regardless of scheme."""
        assert compare_versions("1.0", "1.0", distribution="debian") == 0
        assert compare_versions("1.0", "1.0", distribution="arch") == 0
        assert compare_versions("1.0", "1.0", distribution="fedora") == 0

    def test_real_world_openssl_debian(self) -> None:
        """Real-world: openssl Debian version comparison."""
        installed = "1.1.1n-0+deb11u4"
        fixed = "1.1.1n-0+deb11u5"
        assert compare_versions(installed, fixed, distribution="debian") == -1

    def test_real_world_curl_ubuntu(self) -> None:
        """Real-world: curl Ubuntu version comparison."""
        installed = "7.81.0-1ubuntu1.15"
        fixed = "7.81.0-1ubuntu1.16"
        assert compare_versions(installed, fixed, distribution="ubuntu") == -1

    def test_real_world_equal_versions(self) -> None:
        """When installed == fixed, not vulnerable."""
        v = "2:8.2.3995-1ubuntu3.2"
        assert compare_versions(v, v, distribution="ubuntu") == 0

    def test_real_world_newer_installed(self) -> None:
        """When installed > fixed, already patched."""
        installed = "7.81.0-1ubuntu1.17"
        fixed = "7.81.0-1ubuntu1.16"
        assert compare_versions(installed, fixed, distribution="ubuntu") == 1


# ---------------------------------------------------------------------------
# Edge cases and cross-cutting concerns
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Boundary conditions and unusual inputs."""

    def test_single_digit_versions(self) -> None:
        assert compare_versions("1", "2") == -1
        assert compare_versions("2", "1") == 1
        assert compare_versions("1", "1") == 0

    def test_very_long_version(self) -> None:
        """Version strings with many components."""
        left = "1.2.3.4.5.6.7.8.9.10"
        right = "1.2.3.4.5.6.7.8.9.11"
        assert compare_generic_versions(left, right) == -1

    def test_debian_double_tilde(self) -> None:
        """Multiple tildes: '~~' should sort before '~'."""
        assert compare_debian_part("1.0~~", "1.0~") == -1

    def test_debian_tilde_vs_letter(self) -> None:
        """Tilde sorts before any letter."""
        assert compare_debian_part("1.0~a", "1.0a") == -1

    def test_generic_case_insensitive(self) -> None:
        """Generic comparison lowercases, so 'RC' == 'rc'."""
        assert compare_generic_versions("1.0.RC1", "1.0.rc1") == 0

    def test_only_separators(self) -> None:
        """String of only separator chars normalizes to empty tokens."""
        assert normalize_generic_version("...") == []

    def test_debian_pure_digits(self) -> None:
        """Pure numeric upstream comparison."""
        assert compare_debian_versions("100", "99") == 1

    def test_release_epoch_only_difference(self) -> None:
        """Epoch alone determines the result."""
        assert compare_release_versions("2:0.1-1", "1:99.99-99") == 1

    def test_generic_prerelease_vs_release(self) -> None:
        """In generic scheme, alpha token after number loses to numeric fillvalue 0."""
        # "1.0.alpha" tokens: [1, 0, "alpha"]
        # "1.0" tokens: [1, 0] -> fills to [1, 0, 0]
        # comparing "alpha"(str) vs 0(int): int wins
        assert compare_generic_versions("1.0.alpha", "1.0") == -1

    def test_split_debian_version_no_hyphen(self) -> None:
        """No hyphen means revision defaults to '0'."""
        assert split_debian_version("1.0")[2] == "0"

    def test_split_release_version_no_hyphen(self) -> None:
        """No hyphen means release defaults to '0'."""
        assert split_release_version("1.0")[2] == "0"
