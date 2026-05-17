"""Unit tests for scoring candidate assembly (candidates.py).

Pure data-transformation tests — no DB, no network, no mocking of external
services.  Constructs realistic VulnerabilityMatch, CVEKnowledge, and
NVDEvidence objects to verify build_scoring_candidates, clip_text,
unique_values, select_candidate_fixed_versions, derive_nvd_fixed_version_fallback,
select_nvd_boundary_versions, extract_cpe_product, normalize_package_token,
package_tokens_from_name, and nvd_product_match_rank.
"""
from __future__ import annotations

from aila.modules.vulnerability.agents.scoring.candidates import (
    build_scoring_candidates,
    clip_text,
    derive_nvd_fixed_version_fallback,
    extract_cpe_product,
    normalize_package_token,
    nvd_product_match_rank,
    package_tokens_from_name,
    select_candidate_fixed_versions,
    select_nvd_boundary_versions,
    unique_values,
)
from aila.modules.vulnerability.agents.scoring.models import ScoringCandidate
from aila.modules.vulnerability.contracts import (
    CVEKnowledge,
    NVDCpeMatch,
    NVDEvidence,
    VulnerabilityMatch,
)

# ---------------------------------------------------------------------------
# Factories — keep test fixtures compact
# ---------------------------------------------------------------------------

def _match(
    *,
    system_id: int = 1,
    system_name: str = "arch-vm",
    host: str = "10.0.0.1",
    distribution: str = "arch",
    package_name: str = "openssl",
    installed_version: str = "3.1.0",
    cve_id: str | None = "CVE-2023-0001",
    advisory_id: str | None = "ASA-2023-1",
    source: str = "arch-security",
    fixed_version: str | None = "3.1.1",
    advisory_severity: str | None = "High",
    advisory_type: str | None = "security",
    vendor_status: str | None = None,
    vendor_status_note: str | None = None,
    vendor_urgency: str | None = None,
    vendor_fix_state: str | None = None,
    vendor_support_channel: str | None = None,
    advisory_source_mode: str | None = "live",
    advisory_last_synced_at: str | None = "2024-01-01T00:00:00Z",
    advisory_current_version: str | None = None,
) -> VulnerabilityMatch:
    return VulnerabilityMatch(
        system_id=system_id,
        system_name=system_name,
        host=host,
        distribution=distribution,
        package_name=package_name,
        installed_version=installed_version,
        cve_id=cve_id,
        advisory_id=advisory_id,
        source=source,
        fixed_version=fixed_version,
        advisory_severity=advisory_severity,
        advisory_type=advisory_type,
        vendor_status=vendor_status,
        vendor_status_note=vendor_status_note,
        vendor_urgency=vendor_urgency,
        vendor_fix_state=vendor_fix_state,
        vendor_support_channel=vendor_support_channel,
        advisory_source_mode=advisory_source_mode,
        advisory_last_synced_at=advisory_last_synced_at,
        advisory_current_version=advisory_current_version,
    )


def _intel(
    *,
    cve_id: str = "CVE-2023-0001",
    description: str = "A buffer overflow in openssl.",
    base_severity: str | None = "HIGH",
    cvss_score: float | None = 8.1,
    attack_vector: str | None = "NETWORK",
    privileges_required: str | None = "NONE",
    user_interaction: str | None = "NONE",
    epss_score: float | None = 0.42,
    epss_percentile: float | None = 0.95,
    kev_listed: bool = False,
    kev_date_added: str | None = None,
    nvd_url: str = "https://nvd.nist.gov/vuln/detail/CVE-2023-0001",
    published_at: str | None = "2023-06-01T00:00:00Z",
    notes: list[str] | None = None,
    intel_source_mode: str | None = "live",
    intel_last_synced_at: str | None = "2024-01-01T00:00:00Z",
    nvd_evidence: NVDEvidence | None = None,
) -> CVEKnowledge:
    return CVEKnowledge(
        cve_id=cve_id,
        description=description,
        base_severity=base_severity,
        cvss_score=cvss_score,
        attack_vector=attack_vector,
        privileges_required=privileges_required,
        user_interaction=user_interaction,
        epss_score=epss_score,
        epss_percentile=epss_percentile,
        kev_listed=kev_listed,
        kev_date_added=kev_date_added,
        nvd_url=nvd_url,
        published_at=published_at,
        notes=notes or [],
        intel_source_mode=intel_source_mode,
        intel_last_synced_at=intel_last_synced_at,
        nvd_evidence=nvd_evidence,
    )


# ===================================================================
# clip_text
# ===================================================================

class TestClipText:
    def test_none_returns_empty(self):
        assert clip_text(None, 100) == ""

    def test_empty_string_returns_empty(self):
        assert clip_text("", 100) == ""

    def test_within_limit_unchanged(self):
        assert clip_text("hello", 10) == "hello"

    def test_exact_limit_unchanged(self):
        text = "abcde"
        assert clip_text(text, 5) == "abcde"

    def test_exceeds_limit_clipped(self):
        text = "abcdefghij"  # 10 chars
        result = clip_text(text, 7)
        assert result == "abcd..."
        assert len(result) == 7

    def test_limit_of_3_gives_ellipsis_only(self):
        result = clip_text("abcdef", 3)
        assert result == "..."

    def test_long_text_respects_limit(self):
        text = "x" * 2000
        result = clip_text(text, 300)
        assert len(result) == 300
        assert result.endswith("...")


# ===================================================================
# unique_values
# ===================================================================

class TestUniqueValues:
    def test_empty_iterable(self):
        assert unique_values([]) == []

    def test_deduplication(self):
        assert unique_values(["a", "b", "a", "c", "b"]) == ["a", "b", "c"]

    def test_skips_none(self):
        assert unique_values([None, "a", None, "b"]) == ["a", "b"]

    def test_skips_empty_string(self):
        assert unique_values(["", "a", "", "b"]) == ["a", "b"]

    def test_preserves_insertion_order(self):
        assert unique_values(["z", "a", "m"]) == ["z", "a", "m"]

    def test_generator_input(self):
        gen = (x for x in ["a", "b", "a"])
        assert unique_values(gen) == ["a", "b"]

    def test_non_string_values_coerced(self):
        assert unique_values([1, 2, 1]) == ["1", "2"]

    def test_falsy_zero_skipped(self):
        assert unique_values([0, "a"]) == ["a"]


# ===================================================================
# extract_cpe_product
# ===================================================================

class TestExtractCpeProduct:
    def test_valid_cpe23(self):
        cpe = "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"
        assert extract_cpe_product(cpe) == "openssl"

    def test_none_criteria(self):
        assert extract_cpe_product(None) is None

    def test_empty_criteria(self):
        assert extract_cpe_product("") is None

    def test_malformed_too_few_parts(self):
        assert extract_cpe_product("cpe:2.3:a:vendor") is None

    def test_exactly_five_parts(self):
        assert extract_cpe_product("cpe:2.3:a:vendor:product") == "product"

    def test_complex_product_name(self):
        cpe = "cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*"
        assert extract_cpe_product(cpe) == "http_server"


# ===================================================================
# normalize_package_token
# ===================================================================

class TestNormalizePackageToken:
    def test_none_returns_empty(self):
        assert normalize_package_token(None) == ""

    def test_empty_returns_empty(self):
        assert normalize_package_token("") == ""

    def test_lowercase_alphanumeric_only(self):
        assert normalize_package_token("Open-SSL_1.1") == "openssl11"

    def test_already_clean(self):
        assert normalize_package_token("openssl") == "openssl"

    def test_special_characters_stripped(self):
        assert normalize_package_token("lib-xml2.0+extra") == "libxml20extra"


# ===================================================================
# package_tokens_from_name
# ===================================================================

class TestPackageTokensFromName:
    def test_simple_name(self):
        tokens = package_tokens_from_name("openssl")
        assert tokens == {"openssl"}

    def test_hyphen_split(self):
        tokens = package_tokens_from_name("lib-xml2")
        assert "lib" in tokens
        assert "xml2" in tokens

    def test_multiple_separators(self):
        tokens = package_tokens_from_name("python3.11-dev_extra+test")
        # Splits on '.', '-', '_', '+' — each token is individually normalized
        assert "python3" in tokens
        assert "11" in tokens
        assert "dev" in tokens
        assert "extra" in tokens
        assert "test" in tokens

    def test_leading_trailing_separators(self):
        tokens = package_tokens_from_name("-foo-")
        assert "foo" in tokens
        # Empty strings from leading/trailing splits are discarded
        assert "" not in tokens


# ===================================================================
# nvd_product_match_rank
# ===================================================================

class TestNvdProductMatchRank:
    def test_exact_match_rank_2(self):
        rank = nvd_product_match_rank(
            package_normalized="openssl",
            package_tokens={"openssl"},
            product="openssl",
        )
        assert rank == 2

    def test_token_match_rank_1(self):
        rank = nvd_product_match_rank(
            package_normalized="libxml2",
            package_tokens={"lib", "xml2"},
            product="xml2",
        )
        assert rank == 1

    def test_no_match_rank_0(self):
        rank = nvd_product_match_rank(
            package_normalized="openssl",
            package_tokens={"openssl"},
            product="curl",
        )
        assert rank == 0

    def test_none_product_rank_0(self):
        rank = nvd_product_match_rank(
            package_normalized="openssl",
            package_tokens={"openssl"},
            product=None,
        )
        assert rank == 0

    def test_empty_product_rank_0(self):
        rank = nvd_product_match_rank(
            package_normalized="openssl",
            package_tokens={"openssl"},
            product="",
        )
        assert rank == 0

    def test_case_insensitive_match(self):
        rank = nvd_product_match_rank(
            package_normalized="openssl",
            package_tokens={"openssl"},
            product="OpenSSL",
        )
        assert rank == 2


# ===================================================================
# select_candidate_fixed_versions
# ===================================================================

class TestSelectCandidateFixedVersions:
    def test_no_fixed_versions_returns_none(self):
        matches = [_match(fixed_version=None)]
        version, alternates = select_candidate_fixed_versions(matches, distribution="arch")
        assert version is None
        assert alternates == []

    def test_single_fixed_version(self):
        matches = [_match(fixed_version="3.1.1")]
        version, alternates = select_candidate_fixed_versions(matches, distribution="arch")
        assert version == "3.1.1"
        assert alternates == []

    def test_multiple_versions_highest_selected(self):
        matches = [
            _match(fixed_version="3.1.1"),
            _match(fixed_version="3.2.0"),
            _match(fixed_version="3.1.5"),
        ]
        version, alternates = select_candidate_fixed_versions(matches, distribution="arch")
        assert version == "3.2.0"
        assert "3.1.5" in alternates
        assert "3.1.1" in alternates

    def test_duplicate_versions_deduped(self):
        matches = [
            _match(fixed_version="3.1.1"),
            _match(fixed_version="3.1.1"),
        ]
        version, alternates = select_candidate_fixed_versions(matches, distribution="arch")
        assert version == "3.1.1"
        assert alternates == []

    def test_mixed_none_and_real_versions(self):
        matches = [
            _match(fixed_version=None),
            _match(fixed_version="3.1.1"),
            _match(fixed_version=None),
        ]
        version, alternates = select_candidate_fixed_versions(matches, distribution="arch")
        assert version == "3.1.1"
        assert alternates == []


# ===================================================================
# select_nvd_boundary_versions
# ===================================================================

class TestSelectNvdBoundaryVersions:
    def test_none_nvd_evidence(self):
        result = select_nvd_boundary_versions(
            nvd_evidence=None,
            package_name="openssl",
            installed_version="3.1.0",
            distribution="arch",
        )
        assert result == []

    def test_no_vulnerable_entries(self):
        evidence = NVDEvidence(cpe_matches=[
            NVDCpeMatch(
                vulnerable=False,
                criteria="cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                version_end_excluding="3.2.0",
            ),
        ])
        result = select_nvd_boundary_versions(
            nvd_evidence=evidence,
            package_name="openssl",
            installed_version="3.1.0",
            distribution="arch",
        )
        assert result == []

    def test_no_version_end_excluding(self):
        evidence = NVDEvidence(cpe_matches=[
            NVDCpeMatch(
                vulnerable=True,
                criteria="cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                version_end_excluding=None,
            ),
        ])
        result = select_nvd_boundary_versions(
            nvd_evidence=evidence,
            package_name="openssl",
            installed_version="3.1.0",
            distribution="arch",
        )
        assert result == []

    def test_installed_already_meets_boundary(self):
        evidence = NVDEvidence(cpe_matches=[
            NVDCpeMatch(
                vulnerable=True,
                criteria="cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                version_end_excluding="3.0.0",
            ),
        ])
        result = select_nvd_boundary_versions(
            nvd_evidence=evidence,
            package_name="openssl",
            installed_version="3.1.0",
            distribution="arch",
        )
        assert result == []

    def test_product_no_match_excluded(self):
        evidence = NVDEvidence(cpe_matches=[
            NVDCpeMatch(
                vulnerable=True,
                criteria="cpe:2.3:a:curl:curl:*:*:*:*:*:*:*:*",
                version_end_excluding="8.0.0",
            ),
        ])
        result = select_nvd_boundary_versions(
            nvd_evidence=evidence,
            package_name="openssl",
            installed_version="3.1.0",
            distribution="arch",
        )
        assert result == []

    def test_valid_boundary_returned(self):
        evidence = NVDEvidence(cpe_matches=[
            NVDCpeMatch(
                vulnerable=True,
                criteria="cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                version_end_excluding="3.2.0",
            ),
        ])
        result = select_nvd_boundary_versions(
            nvd_evidence=evidence,
            package_name="openssl",
            installed_version="3.1.0",
            distribution="arch",
        )
        assert result == ["3.2.0"]

    def test_multiple_boundaries_ranked_by_match_quality(self):
        # Package "lib-openssl" has normalized form "libopenssl" and tokens {"lib", "openssl"}.
        # CPE product "openssl" is a token match (rank 1).
        # CPE product "libopenssl" is an exact full-name match (rank 2).
        evidence = NVDEvidence(cpe_matches=[
            NVDCpeMatch(
                vulnerable=True,
                criteria="cpe:2.3:a:someone:openssl:*:*:*:*:*:*:*:*",
                version_end_excluding="3.3.0",
            ),
            NVDCpeMatch(
                vulnerable=True,
                criteria="cpe:2.3:a:someone:libopenssl:*:*:*:*:*:*:*:*",
                version_end_excluding="3.2.0",
            ),
        ])
        result = select_nvd_boundary_versions(
            nvd_evidence=evidence,
            package_name="lib-openssl",
            installed_version="3.1.0",
            distribution="arch",
        )
        # exact match (rank 2) for "libopenssl" beats token match (rank 1) for "openssl"
        assert result[0] == "3.2.0"
        assert "3.3.0" in result

    def test_empty_cpe_matches(self):
        evidence = NVDEvidence(cpe_matches=[])
        result = select_nvd_boundary_versions(
            nvd_evidence=evidence,
            package_name="openssl",
            installed_version="3.1.0",
            distribution="arch",
        )
        assert result == []


# ===================================================================
# derive_nvd_fixed_version_fallback
# ===================================================================

class TestDeriveNvdFixedVersionFallback:
    def test_non_arch_source_returns_none(self):
        matches = [_match(source="osv")]
        intel = _intel()
        version, alternates, source, note = derive_nvd_fixed_version_fallback(matches, intel)
        assert version is None
        assert alternates == []
        assert source == "advisory"
        assert note is None

    def test_arch_source_no_nvd_evidence(self):
        matches = [_match(source="arch-security")]
        intel = _intel(nvd_evidence=None)
        version, alternates, source, note = derive_nvd_fixed_version_fallback(matches, intel)
        assert version is None
        assert source == "advisory"

    def test_arch_source_with_valid_boundary(self):
        nvd = NVDEvidence(cpe_matches=[
            NVDCpeMatch(
                vulnerable=True,
                criteria="cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                version_end_excluding="3.2.0",
            ),
        ])
        matches = [_match(source="arch-security", installed_version="3.1.0")]
        intel = _intel(nvd_evidence=nvd)
        version, alternates, source, note = derive_nvd_fixed_version_fallback(matches, intel)
        assert version == "3.2.0"
        assert source == "nvd-version-end-excluding"
        assert note is not None
        assert "heuristic" in note.lower()

    def test_arch_among_mixed_sources_still_triggers(self):
        matches = [
            _match(source="osv"),
            _match(source="arch-security"),
        ]
        nvd = NVDEvidence(cpe_matches=[
            NVDCpeMatch(
                vulnerable=True,
                criteria="cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                version_end_excluding="3.2.0",
            ),
        ])
        intel = _intel(nvd_evidence=nvd)
        version, _, source, _ = derive_nvd_fixed_version_fallback(matches, intel)
        assert version == "3.2.0"
        assert source == "nvd-version-end-excluding"


# ===================================================================
# build_scoring_candidates — the main integration point
# ===================================================================

class TestBuildScoringCandidates:
    """Tests for the top-level assembly function."""

    def test_empty_matches_returns_empty(self):
        result = build_scoring_candidates([], {}, {})
        assert result == []

    def test_single_match_with_intel(self):
        matches = [_match()]
        knowledge = {"CVE-2023-0001": _intel()}
        descriptions = {1: "Production Arch Linux VM"}

        candidates = build_scoring_candidates(matches, knowledge, descriptions)

        assert len(candidates) == 1
        c = candidates[0]
        assert isinstance(c, ScoringCandidate)
        assert c.system_id == 1
        assert c.system_name == "arch-vm"
        assert c.host == "10.0.0.1"
        assert c.distribution == "arch"
        assert c.package_name == "openssl"
        assert c.installed_version == "3.1.0"
        assert c.cve_id == "CVE-2023-0001"
        assert c.fixed_version == "3.1.1"
        assert c.fixed_version_source == "advisory"
        assert c.nvd_url == "https://nvd.nist.gov/vuln/detail/CVE-2023-0001"
        assert c.base_severity == "HIGH"
        assert c.cvss_score == 8.1
        assert c.attack_vector == "NETWORK"
        assert c.epss_score == 0.42
        assert c.epss_percentile == 0.95
        assert c.kev_listed is False
        assert c.published_at == "2023-06-01T00:00:00Z"
        assert c.host_description == "Production Arch Linux VM"
        assert c.cve_description == "A buffer overflow in openssl."

    def test_match_without_cve_id_uses_advisory_id_as_group_key(self):
        """Advisory-only findings (no CVE) should still produce candidates."""
        matches = [_match(cve_id=None, advisory_id="GHSA-1234-abcd")]
        # No knowledge entry needed for advisory-only
        candidates = build_scoring_candidates(matches, {}, {})
        assert len(candidates) == 1
        c = candidates[0]
        assert c.cve_id is None
        # Advisory-only gets an empty CVEKnowledge stub
        assert c.nvd_url == ""
        assert c.cve_description == ""

    def test_match_without_cve_id_or_advisory_id_skipped(self):
        matches = [_match(cve_id=None, advisory_id=None)]
        candidates = build_scoring_candidates(matches, {}, {})
        assert candidates == []

    def test_match_with_empty_string_ids_skipped(self):
        matches = [_match(cve_id="", advisory_id="")]
        candidates = build_scoring_candidates(matches, {}, {})
        assert candidates == []

    def test_cve_match_without_intel_skipped(self):
        """If a match has a CVE ID but no corresponding knowledge entry, skip it."""
        matches = [_match(cve_id="CVE-2099-9999")]
        candidates = build_scoring_candidates(matches, {}, {})
        assert candidates == []

    def test_grouping_by_system_package_cve(self):
        """Multiple matches for the same (system, package, CVE) produce one candidate."""
        matches = [
            _match(source="osv", advisory_id="GHSA-1111", advisory_severity="High"),
            _match(source="arch-security", advisory_id="ASA-2222", advisory_severity="Critical"),
        ]
        knowledge = {"CVE-2023-0001": _intel()}

        candidates = build_scoring_candidates(matches, knowledge, {})
        assert len(candidates) == 1
        c = candidates[0]
        assert "GHSA-1111" in c.advisory_ids
        assert "ASA-2222" in c.advisory_ids
        assert "osv" in c.evidence_sources
        assert "arch-security" in c.evidence_sources
        assert "High" in c.advisory_severities
        assert "Critical" in c.advisory_severities

    def test_different_cves_same_package_produce_separate_candidates(self):
        matches = [
            _match(cve_id="CVE-2023-0001"),
            _match(cve_id="CVE-2023-0002"),
        ]
        knowledge = {
            "CVE-2023-0001": _intel(cve_id="CVE-2023-0001"),
            "CVE-2023-0002": _intel(cve_id="CVE-2023-0002"),
        }
        candidates = build_scoring_candidates(matches, knowledge, {})
        assert len(candidates) == 2
        cve_ids = {c.cve_id for c in candidates}
        assert cve_ids == {"CVE-2023-0001", "CVE-2023-0002"}

    def test_different_systems_same_cve_produce_separate_candidates(self):
        matches = [
            _match(system_id=1, system_name="host-a"),
            _match(system_id=2, system_name="host-b"),
        ]
        knowledge = {"CVE-2023-0001": _intel()}

        candidates = build_scoring_candidates(matches, knowledge, {})
        assert len(candidates) == 2
        system_ids = {c.system_id for c in candidates}
        assert system_ids == {1, 2}

    def test_host_description_clipped_at_300(self):
        long_desc = "A" * 500
        matches = [_match()]
        knowledge = {"CVE-2023-0001": _intel()}
        descriptions = {1: long_desc}

        candidates = build_scoring_candidates(matches, knowledge, descriptions)
        assert len(candidates[0].host_description) == 300
        assert candidates[0].host_description.endswith("...")

    def test_cve_description_clipped_at_1500(self):
        long_desc = "B" * 2000
        matches = [_match()]
        knowledge = {"CVE-2023-0001": _intel(description=long_desc)}

        candidates = build_scoring_candidates(matches, knowledge, {})
        assert len(candidates[0].cve_description) == 1500
        assert candidates[0].cve_description.endswith("...")

    def test_missing_description_yields_empty_string(self):
        matches = [_match()]
        knowledge = {"CVE-2023-0001": _intel()}

        candidates = build_scoring_candidates(matches, knowledge, {})
        # system_id=1 not in descriptions dict
        assert candidates[0].host_description == ""

    def test_intel_notes_clipped_and_limited_to_five(self):
        notes = [f"Note number {i} with some extra text to make it longer" for i in range(8)]
        matches = [_match()]
        knowledge = {"CVE-2023-0001": _intel(notes=notes)}

        candidates = build_scoring_candidates(matches, knowledge, {})
        assert len(candidates[0].intel_notes) == 5

    def test_intel_notes_individual_clip(self):
        long_note = "X" * 300
        matches = [_match()]
        knowledge = {"CVE-2023-0001": _intel(notes=[long_note])}

        candidates = build_scoring_candidates(matches, knowledge, {})
        assert len(candidates[0].intel_notes[0]) == 200
        assert candidates[0].intel_notes[0].endswith("...")

    def test_kev_fields_propagated(self):
        matches = [_match()]
        knowledge = {"CVE-2023-0001": _intel(kev_listed=True, kev_date_added="2023-07-15")}

        candidates = build_scoring_candidates(matches, knowledge, {})
        c = candidates[0]
        assert c.kev_listed is True
        assert c.kev_date_added == "2023-07-15"

    def test_advisory_metadata_aggregated(self):
        """Vendor status fields from multiple matches are aggregated."""
        matches = [
            _match(
                vendor_status="affected",
                vendor_urgency="high",
                vendor_fix_state="released",
                vendor_support_channel="upstream",
            ),
            _match(
                vendor_status="not-affected",
                vendor_urgency="medium",
                vendor_fix_state="not-released",
                vendor_support_channel="distro",
            ),
        ]
        knowledge = {"CVE-2023-0001": _intel()}
        candidates = build_scoring_candidates(matches, knowledge, {})
        c = candidates[0]
        assert "affected" in c.vendor_statuses
        assert "not-affected" in c.vendor_statuses
        assert "high" in c.vendor_urgencies
        assert "medium" in c.vendor_urgencies
        assert "released" in c.vendor_fix_states
        assert "not-released" in c.vendor_fix_states
        assert "upstream" in c.vendor_support_channels
        assert "distro" in c.vendor_support_channels

    def test_fixed_version_from_advisory_preferred(self):
        """When advisory provides a fixed version, NVD fallback is not used."""
        matches = [_match(fixed_version="3.1.1")]
        knowledge = {"CVE-2023-0001": _intel()}

        candidates = build_scoring_candidates(matches, knowledge, {})
        c = candidates[0]
        assert c.fixed_version == "3.1.1"
        assert c.fixed_version_source == "advisory"
        assert c.fixed_version_note is None

    def test_nvd_fallback_when_no_advisory_fix(self):
        """When advisory has no fixed version, NVD boundary is used for arch-security."""
        nvd = NVDEvidence(cpe_matches=[
            NVDCpeMatch(
                vulnerable=True,
                criteria="cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                version_end_excluding="3.2.0",
            ),
        ])
        matches = [_match(fixed_version=None, source="arch-security")]
        knowledge = {"CVE-2023-0001": _intel(nvd_evidence=nvd)}

        candidates = build_scoring_candidates(matches, knowledge, {})
        c = candidates[0]
        assert c.fixed_version == "3.2.0"
        assert c.fixed_version_source == "nvd-version-end-excluding"
        assert c.fixed_version_note is not None

    def test_no_fixed_version_anywhere(self):
        """When neither advisory nor NVD provides a fix version."""
        matches = [_match(fixed_version=None, source="osv")]
        knowledge = {"CVE-2023-0001": _intel(nvd_evidence=None)}

        candidates = build_scoring_candidates(matches, knowledge, {})
        c = candidates[0]
        assert c.fixed_version is None

    def test_intel_source_mode_propagated(self):
        matches = [_match()]
        knowledge = {"CVE-2023-0001": _intel(intel_source_mode="cache", intel_last_synced_at="2024-02-01")}

        candidates = build_scoring_candidates(matches, knowledge, {})
        c = candidates[0]
        assert c.intel_source_mode == "cache"
        assert c.intel_last_synced_at == "2024-02-01"

    def test_advisory_source_modes_collected(self):
        matches = [
            _match(advisory_source_mode="live"),
            _match(advisory_source_mode="cache"),
        ]
        knowledge = {"CVE-2023-0001": _intel()}

        candidates = build_scoring_candidates(matches, knowledge, {})
        c = candidates[0]
        assert "live" in c.advisory_source_modes
        assert "cache" in c.advisory_source_modes

    def test_advisory_last_synced_at_collected(self):
        matches = [
            _match(advisory_last_synced_at="2024-01-01T00:00:00Z"),
            _match(advisory_last_synced_at="2024-01-15T00:00:00Z"),
        ]
        knowledge = {"CVE-2023-0001": _intel()}

        candidates = build_scoring_candidates(matches, knowledge, {})
        c = candidates[0]
        assert "2024-01-01T00:00:00Z" in c.advisory_last_synced_at
        assert "2024-01-15T00:00:00Z" in c.advisory_last_synced_at

    def test_advisory_current_versions_non_empty_only(self):
        matches = [
            _match(advisory_current_version="3.1.0-1"),
            _match(advisory_current_version=None),
            _match(advisory_current_version=""),
        ]
        knowledge = {"CVE-2023-0001": _intel()}

        candidates = build_scoring_candidates(matches, knowledge, {})
        c = candidates[0]
        assert c.advisory_current_versions == ["3.1.0-1"]

    def test_vendor_status_notes_collected(self):
        matches = [
            _match(vendor_status_note="Upstream fix available"),
            _match(vendor_status_note=None),
        ]
        knowledge = {"CVE-2023-0001": _intel()}

        candidates = build_scoring_candidates(matches, knowledge, {})
        c = candidates[0]
        assert "Upstream fix available" in c.vendor_status_notes

    def test_multiple_cves_across_multiple_systems(self):
        """Full integration: 2 systems, 2 CVEs each, with varying intel."""
        matches = [
            _match(system_id=1, system_name="host-a", cve_id="CVE-2023-0001", package_name="openssl"),
            _match(system_id=1, system_name="host-a", cve_id="CVE-2023-0002", package_name="openssl"),
            _match(system_id=2, system_name="host-b", cve_id="CVE-2023-0001", package_name="openssl"),
            _match(system_id=2, system_name="host-b", cve_id="CVE-2023-0003", package_name="curl"),
        ]
        knowledge = {
            "CVE-2023-0001": _intel(cve_id="CVE-2023-0001"),
            "CVE-2023-0002": _intel(cve_id="CVE-2023-0002"),
            "CVE-2023-0003": _intel(cve_id="CVE-2023-0003"),
        }
        descriptions = {1: "Host A", 2: "Host B"}

        candidates = build_scoring_candidates(matches, knowledge, descriptions)
        assert len(candidates) == 4

        # Verify unique (system_id, package_name, cve_id) keys
        keys = {(c.system_id, c.package_name, c.cve_id) for c in candidates}
        assert (1, "openssl", "CVE-2023-0001") in keys
        assert (1, "openssl", "CVE-2023-0002") in keys
        assert (2, "openssl", "CVE-2023-0001") in keys
        assert (2, "curl", "CVE-2023-0003") in keys

    def test_alternate_fixed_versions_populated(self):
        """When multiple advisories provide different fix versions, alternates are populated."""
        matches = [
            _match(fixed_version="3.1.1", advisory_id="ASA-1"),
            _match(fixed_version="3.2.0", advisory_id="ASA-2"),
            _match(fixed_version="3.1.5", advisory_id="ASA-3"),
        ]
        knowledge = {"CVE-2023-0001": _intel()}

        candidates = build_scoring_candidates(matches, knowledge, {})
        c = candidates[0]
        assert c.fixed_version == "3.2.0"
        assert "3.1.5" in c.alternate_fixed_versions
        assert "3.1.1" in c.alternate_fixed_versions

    def test_advisory_types_collected(self):
        matches = [
            _match(advisory_type="security"),
            _match(advisory_type="bugfix"),
        ]
        knowledge = {"CVE-2023-0001": _intel()}

        candidates = build_scoring_candidates(matches, knowledge, {})
        c = candidates[0]
        assert "security" in c.advisory_types
        assert "bugfix" in c.advisory_types

    def test_evidence_sources_deduped(self):
        matches = [
            _match(source="osv"),
            _match(source="osv"),
            _match(source="arch-security"),
        ]
        knowledge = {"CVE-2023-0001": _intel()}

        candidates = build_scoring_candidates(matches, knowledge, {})
        c = candidates[0]
        assert c.evidence_sources == ["osv", "arch-security"]

    def test_none_intel_fields_pass_through(self):
        """CVEKnowledge with all None optional fields produces a candidate with None fields."""
        matches = [_match()]
        knowledge = {"CVE-2023-0001": _intel(
            base_severity=None,
            cvss_score=None,
            attack_vector=None,
            privileges_required=None,
            user_interaction=None,
            epss_score=None,
            epss_percentile=None,
            kev_listed=False,
            kev_date_added=None,
            published_at=None,
        )}

        candidates = build_scoring_candidates(matches, knowledge, {})
        c = candidates[0]
        assert c.base_severity is None
        assert c.cvss_score is None
        assert c.attack_vector is None
        assert c.privileges_required is None
        assert c.user_interaction is None
        assert c.epss_score is None
        assert c.epss_percentile is None
        assert c.kev_listed is False
        assert c.published_at is None
