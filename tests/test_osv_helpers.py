"""Tests for OSV helper functions — pure data-transformation functions that parse
OSV advisory payloads, extract fixed versions, vendor semantics, ecosystem
priorities, and batch response validation.

Covers every public and private function in
aila.modules.vulnerability.adapters._osv_helpers with realistic OSV-shaped dicts.
"""
from __future__ import annotations

import pytest

from aila.modules.vulnerability.adapters._osv_helpers import (
    _candidate_release_tokens,
    _extract_osv_vendor_urgency,
    build_osv_ecosystem_preferences,
    build_osv_query_ecosystems,
    chunked,
    extract_osv_cves,
    extract_osv_fixed_version,
    extract_osv_matching_ecosystems,
    extract_osv_support_channel,
    extract_osv_vendor_semantics,
    normalize_osv_ecosystem,
    osv_ecosystem_priority,
    select_osv_affected_entries,
    validate_osv_batch_response,
)
from aila.modules.vulnerability.contracts import (
    DistributionProfile,
    InventoryArtifact,
)

# ---------------------------------------------------------------------------
# Helpers to build realistic OSV-shaped test data
# ---------------------------------------------------------------------------

def _make_inventory(**overrides) -> InventoryArtifact:
    """Build a minimal InventoryArtifact for tests."""
    defaults = {
        "system_id": 1,
        "system_name": "test-host",
        "host": "10.0.0.1",
        "username": "root",
        "distribution": "ubuntu",
        "kernel": "5.15.0-generic",
        "os_release": {"VERSION_ID": "22.04"},
    }
    defaults.update(overrides)
    return InventoryArtifact(**defaults)


def _make_profile(**overrides) -> DistributionProfile:
    """Build a minimal DistributionProfile for tests."""
    defaults = {
        "distro_key": "ubuntu",
        "display_name": "Ubuntu",
        "os_release_ids": ["ubuntu"],
        "inventory_command": "uname -a && __OS_RELEASE__ && __PKGS__",
        "package_parser": "tab_separated",
        "advisory_strategy": "osv",
        "advisory_ecosystem": "Ubuntu",
    }
    defaults.update(overrides)
    return DistributionProfile(**defaults)


def _make_affected(
    package_name: str,
    ecosystem: str,
    *,
    fixed_versions: list[str] | None = None,
    ecosystem_specific: dict | None = None,
    database_specific: dict | None = None,
) -> dict:
    """Build a single OSV 'affected' entry."""
    entry: dict = {
        "package": {"name": package_name, "ecosystem": ecosystem},
    }
    if fixed_versions is not None:
        events = [{"fixed": v} for v in fixed_versions]
        entry["ranges"] = [{"type": "ECOSYSTEM", "events": events}]
    if ecosystem_specific is not None:
        entry["ecosystem_specific"] = ecosystem_specific
    if database_specific is not None:
        entry["database_specific"] = database_specific
    return entry


def _make_payload(
    *,
    affected: list[dict] | None = None,
    aliases: list[str] | None = None,
    upstream: list[str] | None = None,
) -> dict:
    """Build a minimal OSV advisory payload."""
    payload: dict = {}
    if affected is not None:
        payload["affected"] = affected
    if aliases is not None:
        payload["aliases"] = aliases
    if upstream is not None:
        payload["upstream"] = upstream
    return payload


# ===========================================================================
# normalize_osv_ecosystem
# ===========================================================================

class TestNormalizeOsvEcosystem:
    def test_lowercase(self) -> None:
        assert normalize_osv_ecosystem("Ubuntu") == "ubuntu"

    def test_strip_whitespace(self) -> None:
        assert normalize_osv_ecosystem("  Debian  ") == "debian"

    def test_strip_lts_suffix(self) -> None:
        assert normalize_osv_ecosystem("Ubuntu:22.04:LTS") == "ubuntu:22.04"

    def test_strip_lts_suffix_case_insensitive(self) -> None:
        assert normalize_osv_ecosystem("ubuntu:22.04:lts") == "ubuntu:22.04"

    def test_none_returns_empty(self) -> None:
        assert normalize_osv_ecosystem(None) == ""

    def test_empty_string(self) -> None:
        assert normalize_osv_ecosystem("") == ""

    def test_no_lts_suffix_unchanged(self) -> None:
        assert normalize_osv_ecosystem("Alpine:v3.18") == "alpine:v3.18"

    def test_lts_in_middle_not_stripped(self) -> None:
        """':lts' in the middle of the string is not stripped."""
        assert normalize_osv_ecosystem("ubuntu:lts:22.04") == "ubuntu:lts:22.04"


# ===========================================================================
# osv_ecosystem_priority
# ===========================================================================

class TestOsvEcosystemPriority:
    def test_no_preferences_returns_1(self) -> None:
        """Without preferences, all non-empty ecosystems get rank 1."""
        assert osv_ecosystem_priority("Ubuntu:22.04", None) == 1

    def test_empty_preferences_returns_1(self) -> None:
        assert osv_ecosystem_priority("Ubuntu:22.04", []) == 1

    def test_exact_match_highest_priority(self) -> None:
        prefs = ["Ubuntu:22.04", "Ubuntu:22", "Ubuntu"]
        result = osv_ecosystem_priority("Ubuntu:22.04", prefs)
        assert result == 4  # len(3) - index(0) + 1

    def test_later_match_lower_priority(self) -> None:
        prefs = ["Ubuntu:22.04", "Ubuntu:22", "Ubuntu"]
        result = osv_ecosystem_priority("Ubuntu", prefs)
        assert result == 2  # len(3) - index(2) + 1

    def test_no_match_returns_negative(self) -> None:
        prefs = ["Ubuntu:22.04", "Ubuntu"]
        assert osv_ecosystem_priority("Debian:12", prefs) == -1

    def test_ubuntu_pro_excluded_without_pro_preference(self) -> None:
        prefs = ["Ubuntu:22.04", "Ubuntu"]
        assert osv_ecosystem_priority("Ubuntu:Pro:22.04:LTS", prefs) == -1

    def test_ubuntu_pro_included_with_pro_preference(self) -> None:
        prefs = ["Ubuntu:Pro:22.04", "Ubuntu:22.04"]
        result = osv_ecosystem_priority("Ubuntu:Pro:22.04", prefs)
        assert result > 0

    def test_none_ecosystem_returns_0(self) -> None:
        prefs = ["Ubuntu:22.04"]
        assert osv_ecosystem_priority(None, prefs) == 0

    def test_empty_string_ecosystem_returns_0(self) -> None:
        prefs = ["Ubuntu:22.04"]
        assert osv_ecosystem_priority("", prefs) == 0

    def test_case_insensitive_matching(self) -> None:
        """Ecosystem comparison is case-insensitive via normalize."""
        prefs = ["Ubuntu:22.04"]
        result = osv_ecosystem_priority("ubuntu:22.04", prefs)
        assert result > 0

    def test_lts_suffix_ignored_in_matching(self) -> None:
        """LTS suffix is stripped, so 'Ubuntu:22.04:LTS' matches 'Ubuntu:22.04'."""
        prefs = ["Ubuntu:22.04"]
        result = osv_ecosystem_priority("Ubuntu:22.04:LTS", prefs)
        assert result > 0


# ===========================================================================
# extract_osv_cves
# ===========================================================================

class TestExtractOsvCves:
    def test_cves_from_aliases(self) -> None:
        payload = _make_payload(aliases=["CVE-2023-1234", "GHSA-xxxx"])
        assert extract_osv_cves(payload) == ["CVE-2023-1234"]

    def test_cves_from_upstream(self) -> None:
        payload = _make_payload(upstream=["CVE-2023-5678"])
        assert extract_osv_cves(payload) == ["CVE-2023-5678"]

    def test_cves_from_both_deduplicated(self) -> None:
        payload = _make_payload(
            upstream=["CVE-2023-1234"],
            aliases=["CVE-2023-1234", "CVE-2023-9999"],
        )
        result = extract_osv_cves(payload)
        assert result == ["CVE-2023-1234", "CVE-2023-9999"]

    def test_upstream_first_ordering(self) -> None:
        """upstream is checked before aliases; upstream CVEs come first."""
        payload = _make_payload(
            upstream=["CVE-2023-0001"],
            aliases=["CVE-2023-0002"],
        )
        assert extract_osv_cves(payload) == ["CVE-2023-0001", "CVE-2023-0002"]

    def test_non_cve_entries_excluded(self) -> None:
        payload = _make_payload(aliases=["GHSA-xxxx", "USN-1234-1"])
        assert extract_osv_cves(payload) == []

    def test_empty_payload(self) -> None:
        assert extract_osv_cves({}) == []

    def test_no_aliases_no_upstream(self) -> None:
        payload = _make_payload(affected=[])
        assert extract_osv_cves(payload) == []

    def test_non_string_values_skipped(self) -> None:
        payload = {"aliases": [123, None, "CVE-2023-1111"]}
        assert extract_osv_cves(payload) == ["CVE-2023-1111"]

    def test_multiple_cves_preserves_order(self) -> None:
        payload = _make_payload(
            aliases=["CVE-2023-9999", "CVE-2023-0001", "CVE-2023-5555"],
        )
        assert extract_osv_cves(payload) == [
            "CVE-2023-9999",
            "CVE-2023-0001",
            "CVE-2023-5555",
        ]


# ===========================================================================
# extract_osv_matching_ecosystems
# ===========================================================================

class TestExtractOsvMatchingEcosystems:
    def test_single_match(self) -> None:
        payload = _make_payload(affected=[
            _make_affected("curl", "Ubuntu:22.04"),
        ])
        result = extract_osv_matching_ecosystems(payload, "curl", ["Ubuntu:22.04"])
        assert result == ["Ubuntu:22.04"]

    def test_multiple_ecosystems_ordered_by_priority(self) -> None:
        payload = _make_payload(affected=[
            _make_affected("curl", "Ubuntu"),
            _make_affected("curl", "Ubuntu:22.04"),
        ])
        prefs = ["Ubuntu:22.04", "Ubuntu"]
        result = extract_osv_matching_ecosystems(payload, "curl", prefs)
        assert result == ["Ubuntu:22.04", "Ubuntu"]

    def test_wrong_package_name_excluded(self) -> None:
        payload = _make_payload(affected=[
            _make_affected("openssl", "Ubuntu:22.04"),
        ])
        result = extract_osv_matching_ecosystems(payload, "curl", ["Ubuntu:22.04"])
        assert result == []

    def test_ubuntu_pro_excluded_without_preference(self) -> None:
        payload = _make_payload(affected=[
            _make_affected("curl", "Ubuntu:Pro:22.04"),
            _make_affected("curl", "Ubuntu:22.04"),
        ])
        prefs = ["Ubuntu:22.04"]
        result = extract_osv_matching_ecosystems(payload, "curl", prefs)
        assert result == ["Ubuntu:22.04"]

    def test_no_preferences_returns_all(self) -> None:
        payload = _make_payload(affected=[
            _make_affected("curl", "Ubuntu:22.04"),
            _make_affected("curl", "Debian:12"),
        ])
        result = extract_osv_matching_ecosystems(payload, "curl", None)
        assert set(result) == {"Ubuntu:22.04", "Debian:12"}

    def test_empty_affected_list(self) -> None:
        payload = _make_payload(affected=[])
        result = extract_osv_matching_ecosystems(payload, "curl", ["Ubuntu:22.04"])
        assert result == []

    def test_no_affected_key(self) -> None:
        result = extract_osv_matching_ecosystems({}, "curl")
        assert result == []

    def test_duplicate_ecosystem_deduplicated(self) -> None:
        payload = _make_payload(affected=[
            _make_affected("curl", "Ubuntu:22.04"),
            _make_affected("curl", "Ubuntu:22.04"),
        ])
        result = extract_osv_matching_ecosystems(payload, "curl", ["Ubuntu:22.04"])
        assert result == ["Ubuntu:22.04"]


# ===========================================================================
# extract_osv_fixed_version
# ===========================================================================

class TestExtractOsvFixedVersion:
    def test_single_fix_event(self) -> None:
        payload = _make_payload(affected=[
            _make_affected("curl", "Ubuntu:22.04", fixed_versions=["7.81.0-1ubuntu1.7"]),
        ])
        result = extract_osv_fixed_version(
            payload, "curl", distribution="ubuntu", preferred_ecosystems=["Ubuntu:22.04"],
        )
        assert result == "7.81.0-1ubuntu1.7"

    def test_no_fixed_events_returns_none(self) -> None:
        payload = _make_payload(affected=[
            _make_affected("curl", "Ubuntu:22.04"),
        ])
        result = extract_osv_fixed_version(payload, "curl", preferred_ecosystems=["Ubuntu:22.04"])
        assert result is None

    def test_highest_priority_ecosystem_wins(self) -> None:
        """When two ecosystems have fix events, the higher-priority one is selected."""
        payload = _make_payload(affected=[
            _make_affected("curl", "Ubuntu", fixed_versions=["7.80.0-1"]),
            _make_affected("curl", "Ubuntu:22.04", fixed_versions=["7.81.0-1ubuntu1.7"]),
        ])
        prefs = ["Ubuntu:22.04", "Ubuntu"]
        result = extract_osv_fixed_version(payload, "curl", preferred_ecosystems=prefs)
        assert result == "7.81.0-1ubuntu1.7"

    def test_multiple_fixes_same_ecosystem_picks_greatest(self) -> None:
        """Within the same ecosystem, the greatest version string wins."""
        payload = _make_payload(affected=[
            _make_affected("curl", "Ubuntu:22.04", fixed_versions=["7.81.0-1", "7.81.0-2"]),
        ])
        result = extract_osv_fixed_version(
            payload, "curl", distribution="ubuntu", preferred_ecosystems=["Ubuntu:22.04"],
        )
        assert result == "7.81.0-2"

    def test_wrong_package_returns_none(self) -> None:
        payload = _make_payload(affected=[
            _make_affected("openssl", "Ubuntu:22.04", fixed_versions=["1.1.1n-0ubuntu0.22.04.2"]),
        ])
        result = extract_osv_fixed_version(payload, "curl", preferred_ecosystems=["Ubuntu:22.04"])
        assert result is None

    def test_empty_payload(self) -> None:
        assert extract_osv_fixed_version({}, "curl") is None

    def test_no_preferred_ecosystems(self) -> None:
        """Without preferences all ecosystems rank equally; the greatest version wins."""
        payload = _make_payload(affected=[
            _make_affected("curl", "Ubuntu:22.04", fixed_versions=["7.81.0-1"]),
        ])
        result = extract_osv_fixed_version(payload, "curl", distribution="ubuntu")
        assert result == "7.81.0-1"


# ===========================================================================
# select_osv_affected_entries
# ===========================================================================

class TestSelectOsvAffectedEntries:
    def test_returns_highest_priority_entries(self) -> None:
        affected_high = _make_affected("curl", "Ubuntu:22.04")
        affected_low = _make_affected("curl", "Ubuntu")
        payload = _make_payload(affected=[affected_low, affected_high])
        prefs = ["Ubuntu:22.04", "Ubuntu"]
        result = select_osv_affected_entries(payload, "curl", preferred_ecosystems=prefs)
        assert len(result) == 1
        assert result[0]["package"]["ecosystem"] == "Ubuntu:22.04"

    def test_ties_return_all_at_top_priority(self) -> None:
        a1 = _make_affected("curl", "Ubuntu:22.04")
        a2 = _make_affected("curl", "Ubuntu:22.04")
        payload = _make_payload(affected=[a1, a2])
        prefs = ["Ubuntu:22.04"]
        result = select_osv_affected_entries(payload, "curl", preferred_ecosystems=prefs)
        assert len(result) == 2

    def test_no_matching_package_returns_empty(self) -> None:
        payload = _make_payload(affected=[
            _make_affected("openssl", "Ubuntu:22.04"),
        ])
        result = select_osv_affected_entries(payload, "curl", preferred_ecosystems=["Ubuntu:22.04"])
        assert result == []

    def test_empty_affected(self) -> None:
        result = select_osv_affected_entries({"affected": []}, "curl")
        assert result == []

    def test_no_affected_key(self) -> None:
        result = select_osv_affected_entries({}, "curl")
        assert result == []

    def test_excluded_ecosystem_skipped(self) -> None:
        """Ubuntu Pro entries are excluded when prefs don't include Pro."""
        payload = _make_payload(affected=[
            _make_affected("curl", "Ubuntu:Pro:22.04"),
        ])
        result = select_osv_affected_entries(payload, "curl", preferred_ecosystems=["Ubuntu:22.04"])
        assert result == []


# ===========================================================================
# extract_osv_support_channel
# ===========================================================================

class TestExtractOsvSupportChannel:
    def test_ubuntu_pro(self) -> None:
        assert extract_osv_support_channel(["Ubuntu:Pro:22.04"]) == "ubuntu-pro"

    def test_ubuntu_standard(self) -> None:
        assert extract_osv_support_channel(["Ubuntu:22.04"]) == "ubuntu-standard"

    def test_ubuntu_bare(self) -> None:
        assert extract_osv_support_channel(["Ubuntu"]) == "ubuntu-standard"

    def test_pro_wins_over_standard(self) -> None:
        """Pro channel takes precedence when both are present."""
        ecosystems = ["Ubuntu:22.04", "Ubuntu:Pro:22.04"]
        assert extract_osv_support_channel(ecosystems) == "ubuntu-pro"

    def test_non_ubuntu_returns_none(self) -> None:
        assert extract_osv_support_channel(["Debian:12"]) is None

    def test_empty_list(self) -> None:
        assert extract_osv_support_channel([]) is None

    def test_none_input(self) -> None:
        assert extract_osv_support_channel(None) is None

    def test_case_insensitive(self) -> None:
        assert extract_osv_support_channel(["UBUNTU:22.04"]) == "ubuntu-standard"

    def test_lts_suffix_stripped_before_check(self) -> None:
        assert extract_osv_support_channel(["Ubuntu:22.04:LTS"]) == "ubuntu-standard"


# ===========================================================================
# _extract_osv_vendor_urgency
# ===========================================================================

class TestExtractOsvVendorUrgency:
    def test_urgency_from_ecosystem_specific(self) -> None:
        affected = {"ecosystem_specific": {"urgency": "medium"}}
        assert _extract_osv_vendor_urgency(affected) == "medium"

    def test_urgency_from_database_specific(self) -> None:
        affected = {"database_specific": {"urgency": "high"}}
        assert _extract_osv_vendor_urgency(affected) == "high"

    def test_ecosystem_specific_takes_precedence(self) -> None:
        affected = {
            "ecosystem_specific": {"urgency": "low"},
            "database_specific": {"urgency": "high"},
        }
        assert _extract_osv_vendor_urgency(affected) == "low"

    def test_no_urgency_returns_none(self) -> None:
        assert _extract_osv_vendor_urgency({}) is None

    def test_empty_urgency_returns_none(self) -> None:
        affected = {"ecosystem_specific": {"urgency": ""}}
        assert _extract_osv_vendor_urgency(affected) is None

    def test_whitespace_urgency_returns_none(self) -> None:
        affected = {"ecosystem_specific": {"urgency": "   "}}
        assert _extract_osv_vendor_urgency(affected) is None

    def test_none_ecosystem_specific(self) -> None:
        affected = {"ecosystem_specific": None, "database_specific": {"urgency": "low"}}
        assert _extract_osv_vendor_urgency(affected) == "low"

    def test_urgency_stripped(self) -> None:
        affected = {"ecosystem_specific": {"urgency": "  medium  "}}
        assert _extract_osv_vendor_urgency(affected) == "medium"


# ===========================================================================
# extract_osv_vendor_semantics
# ===========================================================================

class TestExtractOsvVendorSemantics:
    def test_basic_affected_status(self) -> None:
        payload = _make_payload(affected=[
            _make_affected("curl", "Debian:12"),
        ])
        result = extract_osv_vendor_semantics(
            payload, "curl", preferred_ecosystems=["Debian:12"],
        )
        assert result["vendor_status"] == "affected"
        assert result["vendor_fix_state"] == "no_vendor_fix_published"

    def test_with_fixed_version(self) -> None:
        payload = _make_payload(affected=[
            _make_affected("curl", "Debian:12"),
        ])
        result = extract_osv_vendor_semantics(
            payload, "curl",
            preferred_ecosystems=["Debian:12"],
            fixed_version="7.88.1-10+deb12u4",
        )
        assert result["vendor_fix_state"] == "fixed_version_available"
        assert "fixed package version" in (result["vendor_status_note"] or "")

    def test_ubuntu_pro_channel_status(self) -> None:
        payload = _make_payload(affected=[
            _make_affected("curl", "Ubuntu:Pro:22.04"),
        ])
        result = extract_osv_vendor_semantics(
            payload, "curl",
            preferred_ecosystems=["Ubuntu:Pro:22.04"],
        )
        assert result["vendor_status"] == "affected_in_ubuntu_pro_channel"
        assert result["vendor_support_channel"] == "ubuntu-pro"

    def test_ubuntu_standard_channel_status(self) -> None:
        payload = _make_payload(affected=[
            _make_affected("curl", "Ubuntu:22.04"),
        ])
        result = extract_osv_vendor_semantics(
            payload, "curl",
            preferred_ecosystems=["Ubuntu:22.04"],
        )
        assert result["vendor_status"] == "affected_in_standard_ubuntu_channel"
        assert result["vendor_support_channel"] == "ubuntu-standard"

    def test_unimportant_urgency_status(self) -> None:
        payload = _make_payload(affected=[
            _make_affected(
                "curl", "Debian:12",
                ecosystem_specific={"urgency": "unimportant"},
            ),
        ])
        result = extract_osv_vendor_semantics(
            payload, "curl",
            preferred_ecosystems=["Debian:12"],
        )
        assert result["vendor_status"] == "affected_vendor_marked_unimportant"
        assert result["vendor_urgency"] == "unimportant"

    def test_urgency_in_status_note(self) -> None:
        payload = _make_payload(affected=[
            _make_affected(
                "curl", "Debian:12",
                ecosystem_specific={"urgency": "medium"},
            ),
        ])
        result = extract_osv_vendor_semantics(
            payload, "curl",
            preferred_ecosystems=["Debian:12"],
        )
        assert "medium" in result["vendor_status_note"]

    def test_no_matching_package_returns_empty(self) -> None:
        payload = _make_payload(affected=[
            _make_affected("openssl", "Debian:12"),
        ])
        result = extract_osv_vendor_semantics(
            payload, "curl", preferred_ecosystems=["Debian:12"],
        )
        assert result == {}

    def test_no_affected_returns_empty(self) -> None:
        result = extract_osv_vendor_semantics({}, "curl")
        assert result == {}

    def test_all_keys_present(self) -> None:
        """Result always contains the five expected keys."""
        payload = _make_payload(affected=[
            _make_affected("curl", "Debian:12"),
        ])
        result = extract_osv_vendor_semantics(
            payload, "curl", preferred_ecosystems=["Debian:12"],
        )
        expected_keys = {
            "vendor_status",
            "vendor_status_note",
            "vendor_urgency",
            "vendor_fix_state",
            "vendor_support_channel",
        }
        assert set(result.keys()) == expected_keys

    def test_no_fix_published_note(self) -> None:
        payload = _make_payload(affected=[
            _make_affected("curl", "Debian:12"),
        ])
        result = extract_osv_vendor_semantics(
            payload, "curl", preferred_ecosystems=["Debian:12"],
        )
        assert "does not publish" in (result["vendor_status_note"] or "")


# ===========================================================================
# validate_osv_batch_response
# ===========================================================================

class TestValidateOsvBatchResponse:
    def _inventory(self) -> InventoryArtifact:
        return _make_inventory()

    def test_valid_response(self) -> None:
        batch = [{"package": {"name": "curl"}}, {"package": {"name": "openssl"}}]
        response = {"results": [{}, {}]}
        result = validate_osv_batch_response(
            response=response, batch=batch, inventory=self._inventory(), ecosystem="Ubuntu",
        )
        assert result == [{}, {}]

    def test_missing_results_key_raises(self) -> None:
        with pytest.raises(RuntimeError, match="did not include a results list"):
            validate_osv_batch_response(
                response={}, batch=[{"package": {"name": "curl"}}],
                inventory=self._inventory(), ecosystem="Ubuntu",
            )

    def test_results_not_list_raises(self) -> None:
        with pytest.raises(RuntimeError, match="did not include a results list"):
            validate_osv_batch_response(
                response={"results": "invalid"}, batch=[{"package": {"name": "curl"}}],
                inventory=self._inventory(), ecosystem="Ubuntu",
            )

    def test_count_mismatch_raises(self) -> None:
        batch = [{"package": {"name": "curl"}}, {"package": {"name": "openssl"}}]
        response = {"results": [{}]}
        with pytest.raises(RuntimeError, match="returned 1 results for 2 queries"):
            validate_osv_batch_response(
                response=response, batch=batch,
                inventory=self._inventory(), ecosystem="Ubuntu",
            )

    def test_error_message_includes_context(self) -> None:
        inv = _make_inventory(system_name="web-server", host="10.0.0.5")
        batch = [{"package": {"name": "curl"}}]
        with pytest.raises(RuntimeError, match="web-server") as exc_info:
            validate_osv_batch_response(
                response={}, batch=batch, inventory=inv, ecosystem="Ubuntu:22.04",
            )
        assert "10.0.0.5" in str(exc_info.value)
        assert "Ubuntu:22.04" in str(exc_info.value)

    def test_count_mismatch_lists_packages(self) -> None:
        batch = [{"package": {"name": "curl"}}, {"package": {"name": "openssl"}}]
        response = {"results": [{}]}
        with pytest.raises(RuntimeError, match="curl.*openssl"):
            validate_osv_batch_response(
                response=response, batch=batch,
                inventory=self._inventory(), ecosystem="Ubuntu",
            )


# ===========================================================================
# chunked
# ===========================================================================

class TestChunked:
    def test_exact_division(self) -> None:
        items = [{"a": 1}, {"b": 2}, {"c": 3}, {"d": 4}]
        chunks = list(chunked(items, 2))
        assert chunks == [[{"a": 1}, {"b": 2}], [{"c": 3}, {"d": 4}]]

    def test_remainder(self) -> None:
        items = [{"a": 1}, {"b": 2}, {"c": 3}]
        chunks = list(chunked(items, 2))
        assert chunks == [[{"a": 1}, {"b": 2}], [{"c": 3}]]

    def test_single_chunk(self) -> None:
        items = [{"a": 1}]
        chunks = list(chunked(items, 5))
        assert chunks == [[{"a": 1}]]

    def test_empty_list(self) -> None:
        assert list(chunked([], 3)) == []

    def test_chunk_size_equals_length(self) -> None:
        items = [{"a": 1}, {"b": 2}]
        assert list(chunked(items, 2)) == [items]

    def test_chunk_size_one(self) -> None:
        items = [{"x": 1}, {"y": 2}]
        assert list(chunked(items, 1)) == [[{"x": 1}], [{"y": 2}]]


# ===========================================================================
# build_osv_ecosystem_preferences
# ===========================================================================

class TestBuildOsvEcosystemPreferences:
    def test_ubuntu_with_version_id(self) -> None:
        inventory = _make_inventory(os_release={"VERSION_ID": "22.04"})
        profile = _make_profile(advisory_ecosystem="Ubuntu")
        result = build_osv_ecosystem_preferences(inventory, profile)
        assert result == ["Ubuntu:22.04", "Ubuntu:22", "Ubuntu"]

    def test_no_version_id(self) -> None:
        inventory = _make_inventory(os_release={})
        profile = _make_profile(advisory_ecosystem="Ubuntu")
        result = build_osv_ecosystem_preferences(inventory, profile)
        assert result == ["Ubuntu"]

    def test_empty_advisory_ecosystem(self) -> None:
        inventory = _make_inventory()
        profile = _make_profile(
            advisory_ecosystem="",
            advisory_strategy="arch-security",
            distro_key="arch",
            os_release_ids=["arch"],
        )
        result = build_osv_ecosystem_preferences(inventory, profile)
        assert result == []

    def test_none_advisory_ecosystem(self) -> None:
        inventory = _make_inventory()
        profile = _make_profile(
            advisory_ecosystem=None,
            advisory_strategy="arch-security",
            distro_key="arch",
            os_release_ids=["arch"],
        )
        result = build_osv_ecosystem_preferences(inventory, profile)
        assert result == []

    def test_alpine_includes_release_branch(self) -> None:
        inventory = _make_inventory(
            distribution="alpine",
            os_release={"VERSION_ID": "3.18.4"},
        )
        profile = _make_profile(
            advisory_ecosystem="Alpine",
            distro_key="alpine",
            os_release_ids=["alpine"],
            advisory_strategy="osv",
        )
        result = build_osv_ecosystem_preferences(inventory, profile)
        assert "Alpine:v3.18" in result
        assert result[0] == "Alpine:v3.18"

    def test_three_part_version_generates_tokens(self) -> None:
        inventory = _make_inventory(os_release={"VERSION_ID": "12.1.3"})
        profile = _make_profile(advisory_ecosystem="Debian")
        result = build_osv_ecosystem_preferences(inventory, profile)
        assert "Debian:12.1.3" in result
        assert "Debian:12.1" in result
        assert "Debian:12" in result
        assert "Debian" in result

    def test_single_part_version(self) -> None:
        inventory = _make_inventory(os_release={"VERSION_ID": "12"})
        profile = _make_profile(advisory_ecosystem="Debian")
        result = build_osv_ecosystem_preferences(inventory, profile)
        assert result == ["Debian:12", "Debian"]


# ===========================================================================
# build_osv_query_ecosystems
# ===========================================================================

class TestBuildOsvQueryEcosystems:
    def test_base_appended_if_missing(self) -> None:
        result = build_osv_query_ecosystems(["Ubuntu:22.04"], "Ubuntu")
        assert result == ["Ubuntu:22.04", "Ubuntu"]

    def test_base_not_duplicated(self) -> None:
        result = build_osv_query_ecosystems(["Ubuntu:22.04", "Ubuntu"], "Ubuntu")
        assert result == ["Ubuntu:22.04", "Ubuntu"]

    def test_empty_preferences(self) -> None:
        result = build_osv_query_ecosystems([], "Ubuntu")
        assert result == ["Ubuntu"]

    def test_empty_base_not_added(self) -> None:
        result = build_osv_query_ecosystems(["Ubuntu:22.04"], "")
        assert result == ["Ubuntu:22.04"]

    def test_whitespace_base_not_added(self) -> None:
        result = build_osv_query_ecosystems(["Ubuntu:22.04"], "  ")
        assert result == ["Ubuntu:22.04"]

    def test_preserves_order(self) -> None:
        result = build_osv_query_ecosystems(["A", "B", "C"], "D")
        assert result == ["A", "B", "C", "D"]

    def test_deduplicates_preferences(self) -> None:
        result = build_osv_query_ecosystems(["Ubuntu:22.04", "Ubuntu:22.04"], "Ubuntu")
        assert result == ["Ubuntu:22.04", "Ubuntu"]

    def test_empty_items_in_preferences_skipped(self) -> None:
        result = build_osv_query_ecosystems(["", "  ", "Ubuntu:22.04"], "Ubuntu")
        assert result == ["Ubuntu:22.04", "Ubuntu"]


# ===========================================================================
# _candidate_release_tokens
# ===========================================================================

class TestCandidateReleaseTokens:
    def test_two_part_version(self) -> None:
        result = _candidate_release_tokens("22.04", "ubuntu")
        assert result == ["22.04", "22"]

    def test_three_part_version(self) -> None:
        result = _candidate_release_tokens("3.18.4", "debian")
        assert result == ["3.18.4", "3.18", "3"]

    def test_single_part_version(self) -> None:
        result = _candidate_release_tokens("12", "debian")
        assert result == ["12"]

    def test_empty_version(self) -> None:
        assert _candidate_release_tokens("", "ubuntu") == []

    def test_whitespace_only(self) -> None:
        assert _candidate_release_tokens("   ", "ubuntu") == []

    def test_alpine_prepends_release_branch(self) -> None:
        result = _candidate_release_tokens("3.18.4", "alpine")
        assert result[0] == "v3.18"
        assert "3.18.4" in result
        assert "3.18" in result
        assert "3" in result

    def test_alpine_no_duplicate_branch(self) -> None:
        """The alpine release branch token should appear exactly once."""
        result = _candidate_release_tokens("3.18.4", "alpine")
        assert result.count("v3.18") == 1

    def test_alpine_single_part_no_branch(self) -> None:
        """Alpine with a single-part version cannot form a branch token."""
        result = _candidate_release_tokens("3", "alpine")
        assert result == ["3"]

    def test_leading_trailing_whitespace_stripped(self) -> None:
        result = _candidate_release_tokens("  22.04  ", "ubuntu")
        assert result == ["22.04", "22"]
