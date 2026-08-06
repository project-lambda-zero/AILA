"""Comprehensive unit tests for IntelService covering uncovered paths.

Targets:
- _fetch_from_nvd: CVSS v2/v3.1/v4 metric selection, RateLimitError fallback,
  generic exception fallback, full NVD payload parsing
- _build_fallback_intel: structure verification
- _select_primary_cvss_metric: v4 > v3.1 > v2 priority, Primary preference, empty
- enrich(): full enrichment flow with EPSS/KEV overlay, empty matches, no CVE IDs
- prewarm(): PrewarmResult structure, empty input
- _enrich_cve_ids: cache hit path, NVD live path, fallback counting, EPSS/KEV
  exception resilience, KEV note dedup, cache write gating
"""
from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

from aila.modules.vulnerability.config_schema import VulnerabilityConfigSchema
from aila.modules.vulnerability.contracts import (
    CVEKnowledge,
    IntelEnrichmentResult,
    PrewarmResult,
    VulnerabilityMatch,
)
from aila.modules.vulnerability.services.intel import IntelService, _select_primary_cvss_metric
from aila.platform.exceptions import RateLimitError

# Cache freshness now enforces cve_cache_ttl_hours, so cached payloads must carry
# a recent last_synced_at to be treated as a hit (previously keep-forever).
_FRESH_TS = datetime.now(UTC).isoformat()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_service(
    *,
    nvd_return=None,
    nvd_side_effect=None,
    epss_return=None,
    epss_side_effect=None,
    kev_return=None,
    kev_side_effect=None,
    cache_batch_return=None,
    cache_set_return=None,
) -> IntelService:
    """Build an IntelService with fully mocked, awaitable tools.

    Every ``.forward()`` on the underlying tools is async in production
    (each is awaited inside IntelService), so we wire AsyncMock instances
    onto each tool.forward attribute.
    """
    nvd_tool = MagicMock()
    nvd_tool.forward = AsyncMock()
    if nvd_side_effect is not None:
        nvd_tool.forward.side_effect = nvd_side_effect
    elif nvd_return is not None:
        nvd_tool.forward.return_value = nvd_return

    epss_kev_tool = MagicMock()
    epss_kev_tool.forward = AsyncMock()

    def _epss_kev_dispatch(*, action, cve_ids=None, **kwargs):
        if action == "epss_lookup":
            if epss_side_effect is not None:
                raise epss_side_effect
            return epss_return if epss_return is not None else {}
        if action == "kev_catalog":
            if kev_side_effect is not None:
                raise kev_side_effect
            return kev_return if kev_return is not None else {}
        return {}

    epss_kev_tool.forward.side_effect = _epss_kev_dispatch

    cache_tool = MagicMock()
    cache_tool.forward = AsyncMock()

    def _cache_dispatch(*, action, cve_id=None, cve_ids=None, payload=None, **kwargs):
        if action == "cve_cache_get_batch":
            return cache_batch_return if cache_batch_return is not None else {}
        if action == "cve_cache_set":
            return cache_set_return or {"message": "stored"}
        return {}

    cache_tool.forward.side_effect = _cache_dispatch

    return IntelService(
        nvd_tool=nvd_tool,
        epss_kev_tool=epss_kev_tool,
        cache_tool=cache_tool,
        settings=MagicMock(),
        config=VulnerabilityConfigSchema(),
    )


def _make_nvd_payload(
    cve_id: str = "CVE-2023-1234",
    *,
    description: str = "A test vulnerability",
    metrics: dict | None = None,
    published: str = "2023-06-01T00:00:00.000",
    last_modified: str = "2023-06-15T00:00:00.000",
) -> dict:
    """Build a realistic NVD API v2 response payload."""
    cve_block: dict = {
        "id": cve_id,
        "published": published,
        "lastModified": last_modified,
        "descriptions": [
            {"lang": "en", "value": description},
        ],
    }
    if metrics is not None:
        cve_block["metrics"] = metrics
    return {"vulnerabilities": [{"cve": cve_block}]}


def _make_match(cve_id: str) -> VulnerabilityMatch:
    return VulnerabilityMatch(
        system_id=1,
        system_name="test-system",
        host="test-host",
        distribution="ubuntu",
        package_name="libfoo",
        installed_version="1.0.0",
        cve_id=cve_id,
        source="osv",
    )


# ===========================================================================
# _select_primary_cvss_metric  (module-level, sync)
# ===========================================================================


class TestSelectPrimaryCvssMetric:
    """Test the v4 > v3.1 > v2 priority and Primary type preference."""

    def test_empty_metrics_returns_none(self):
        assert _select_primary_cvss_metric({}) is None

    def test_all_keys_absent_returns_none(self):
        assert _select_primary_cvss_metric({"unrelated": [{"foo": "bar"}]}) is None

    def test_empty_lists_returns_none(self):
        metrics = {
            "cvssMetricV40": [],
            "cvssMetricV31": [],
            "cvssMetricV2": [],
        }
        assert _select_primary_cvss_metric(metrics) is None

    def test_v4_preferred_over_v31_and_v2(self):
        v4_entry = {"type": "Primary", "cvssData": {"version": "4.0", "baseScore": 9.0}}
        v31_entry = {"type": "Primary", "cvssData": {"version": "3.1", "baseScore": 7.5}}
        v2_entry = {"type": "Primary", "cvssData": {"version": "2.0", "baseScore": 5.0}}
        metrics = {
            "cvssMetricV40": [v4_entry],
            "cvssMetricV31": [v31_entry],
            "cvssMetricV2": [v2_entry],
        }
        result = _select_primary_cvss_metric(metrics)
        assert result is v4_entry

    def test_v31_preferred_over_v2_when_no_v4(self):
        v31_entry = {"type": "Primary", "cvssData": {"version": "3.1", "baseScore": 7.5}}
        v2_entry = {"type": "Primary", "cvssData": {"version": "2.0", "baseScore": 5.0}}
        metrics = {
            "cvssMetricV31": [v31_entry],
            "cvssMetricV2": [v2_entry],
        }
        result = _select_primary_cvss_metric(metrics)
        assert result is v31_entry

    def test_v2_used_when_only_version(self):
        v2_entry = {"type": "Primary", "cvssData": {"version": "2.0", "baseScore": 5.0}}
        metrics = {"cvssMetricV2": [v2_entry]}
        result = _select_primary_cvss_metric(metrics)
        assert result is v2_entry

    def test_primary_type_preferred_over_secondary(self):
        secondary = {"type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 6.0}}
        primary = {"type": "Primary", "cvssData": {"version": "3.1", "baseScore": 7.5}}
        metrics = {"cvssMetricV31": [secondary, primary]}
        result = _select_primary_cvss_metric(metrics)
        assert result is primary

    def test_first_entry_used_when_no_primary(self):
        first = {"type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 6.0}}
        second = {"type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 8.0}}
        metrics = {"cvssMetricV31": [first, second]}
        result = _select_primary_cvss_metric(metrics)
        assert result is first

    def test_v4_empty_falls_through_to_v31(self):
        v31_entry = {"type": "Primary", "cvssData": {"version": "3.1", "baseScore": 7.5}}
        metrics = {
            "cvssMetricV40": [],
            "cvssMetricV31": [v31_entry],
        }
        result = _select_primary_cvss_metric(metrics)
        assert result is v31_entry


# ===========================================================================
# _build_fallback_intel  (sync instance method)
# ===========================================================================


class TestBuildFallbackIntel:

    def setup_method(self):
        self.service = _make_service()

    def test_fallback_structure(self):
        result = self.service._build_fallback_intel(
            "CVE-2023-9999",
            "NVD was rate limited.",
            reason="nvd_rate_limited",
        )
        assert isinstance(result, CVEKnowledge)
        assert result.cve_id == "CVE-2023-9999"
        assert result.description == ""
        assert result.intel_source_mode == "fallback"
        assert "NVD was rate limited." in result.notes
        assert result.nvd_url == "https://nvd.nist.gov/vuln/detail/CVE-2023-9999"
        assert result.nvd_evidence is not None
        assert result.nvd_evidence.fallback_reason == "nvd_rate_limited"

    def test_fallback_has_no_scores(self):
        result = self.service._build_fallback_intel("CVE-2023-0001", "error", reason="test")
        assert result.cvss_score is None
        assert result.epss_score is None
        assert result.kev_listed is False

    def test_fallback_custom_reason(self):
        result = self.service._build_fallback_intel(
            "CVE-2024-0001",
            "Connection timeout.",
            reason="nvd_lookup_error",
        )
        assert result.nvd_evidence.fallback_reason == "nvd_lookup_error"


# ===========================================================================
# _fetch_from_nvd  (async instance method)
# ===========================================================================


class TestFetchFromNvd:

    async def test_cvss_v31_fields_mapped(self):
        metrics = {
            "cvssMetricV31": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH",
                        "attackVector": "NETWORK",
                        "privilegesRequired": "NONE",
                        "userInteraction": "NONE",
                    },
                }
            ]
        }
        payload = _make_nvd_payload(metrics=metrics)
        service = _make_service(nvd_return=payload)

        result = await service._fetch_from_nvd("CVE-2023-1234")

        assert result.cve_id == "CVE-2023-1234"
        assert result.cvss_score == 7.5
        assert result.base_severity == "HIGH"
        assert result.attack_vector == "NETWORK"
        assert result.privileges_required == "NONE"
        assert result.user_interaction == "NONE"
        assert result.description == "A test vulnerability"
        assert result.intel_source_mode == "live"
        assert result.published_at == "2023-06-01T00:00:00.000"
        assert result.updated_at == "2023-06-15T00:00:00.000"
        assert "CVE-2023-1234" in result.nvd_url

    async def test_cvss_v2_uses_access_vector_and_authentication(self):
        metrics = {
            "cvssMetricV2": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "version": "2.0",
                        "baseScore": 5.0,
                        "baseSeverity": "MEDIUM",
                        "accessVector": "NETWORK",
                        "authentication": "NONE",
                        "userInteraction": "REQUIRED",
                    },
                }
            ]
        }
        payload = _make_nvd_payload(metrics=metrics)
        service = _make_service(nvd_return=payload)

        result = await service._fetch_from_nvd("CVE-2023-5678")

        assert result.attack_vector == "NETWORK"
        assert result.privileges_required == "NONE"
        assert result.cvss_score == 5.0

    async def test_cvss_v4_fields_mapped(self):
        metrics = {
            "cvssMetricV40": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "version": "4.0",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "attackVector": "NETWORK",
                        "privilegesRequired": "NONE",
                        "userInteraction": "NONE",
                    },
                }
            ]
        }
        payload = _make_nvd_payload(metrics=metrics)
        service = _make_service(nvd_return=payload)

        result = await service._fetch_from_nvd("CVE-2024-0001")

        assert result.cvss_score == 9.8
        assert result.base_severity == "CRITICAL"
        assert result.attack_vector == "NETWORK"

    async def test_no_metrics_yields_none_scores(self):
        payload = _make_nvd_payload(metrics={})
        service = _make_service(nvd_return=payload)

        result = await service._fetch_from_nvd("CVE-2023-0000")

        assert result.cvss_score is None
        assert result.base_severity is None
        assert result.attack_vector is None
        assert result.privileges_required is None

    async def test_empty_vulnerabilities_list(self):
        service = _make_service(nvd_return={"vulnerabilities": []})

        result = await service._fetch_from_nvd("CVE-2023-EMPTY")

        assert result.cve_id == "CVE-2023-EMPTY"
        assert result.description == ""
        assert result.cvss_score is None

    async def test_rate_limit_error_returns_fallback(self):
        service = _make_service(nvd_side_effect=RateLimitError("Too many requests"))

        result = await service._fetch_from_nvd("CVE-2023-RATE")

        assert result.intel_source_mode == "fallback"
        assert result.nvd_evidence is not None
        assert result.nvd_evidence.fallback_reason == "nvd_rate_limited"
        assert any("rate limited" in n.lower() for n in result.notes)

    async def test_generic_exception_returns_fallback(self):
        # NOTE: production catches AILAError (not bare Exception).
        # ConnectionError is not an AILAError, so use an AILA-derived error
        # subclass to exercise the "generic" fallback branch.
        from aila.platform.exceptions import UpstreamError
        service = _make_service(nvd_side_effect=UpstreamError("Connection refused"))

        result = await service._fetch_from_nvd("CVE-2023-CONN")

        assert result.intel_source_mode == "fallback"
        assert result.nvd_evidence.fallback_reason == "nvd_lookup_error"
        assert any("UpstreamError" in n for n in result.notes)

    async def test_english_description_selected(self):
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-MULTI",
                        "descriptions": [
                            {"lang": "es", "value": "Vulnerabilidad de prueba"},
                            {"lang": "en", "value": "English description here"},
                        ],
                    }
                }
            ]
        }
        service = _make_service(nvd_return=payload)
        result = await service._fetch_from_nvd("CVE-2023-MULTI")
        assert result.description == "English description here"

    async def test_no_english_description_yields_empty(self):
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-NOEN",
                        "descriptions": [
                            {"lang": "es", "value": "Solo espanol"},
                        ],
                    }
                }
            ]
        }
        service = _make_service(nvd_return=payload)
        result = await service._fetch_from_nvd("CVE-2023-NOEN")
        assert result.description == ""


# ===========================================================================
# enrich()  (async)
# ===========================================================================


class TestEnrich:

    async def test_no_cve_ids_returns_empty(self):
        service = _make_service()
        matches = [
            VulnerabilityMatch(
                system_id=1,
                system_name="s",
                host="h",
                distribution="d",
                package_name="p",
                installed_version="1",
                cve_id=None,
                source="osv",
            )
        ]
        result = await service.enrich(matches)

        assert isinstance(result, IntelEnrichmentResult)
        assert result.knowledge == {}
        assert "No CVE identifiers" in result.message

    async def test_empty_matches_returns_empty(self):
        service = _make_service()
        result = await service.enrich([])
        assert result.knowledge == {}

    async def test_deduplicates_cve_ids(self):
        """Two matches with the same CVE should only enrich once."""
        nvd_payload = _make_nvd_payload(
            cve_id="CVE-2023-DUP",
            metrics={
                "cvssMetricV31": [
                    {
                        "type": "Primary",
                        "cvssData": {
                            "version": "3.1",
                            "baseScore": 5.0,
                            "baseSeverity": "MEDIUM",
                            "attackVector": "LOCAL",
                            "privilegesRequired": "LOW",
                            "userInteraction": "NONE",
                        },
                    }
                ]
            },
        )
        service = _make_service(nvd_return=nvd_payload)
        matches = [_make_match("CVE-2023-DUP"), _make_match("CVE-2023-DUP")]

        result = await service.enrich(matches)

        assert len(result.knowledge) == 1
        assert "CVE-2023-DUP" in result.knowledge

    async def test_full_enrichment_with_epss_and_kev(self):
        """Verify EPSS scores and KEV data are overlaid onto CVEKnowledge."""
        nvd_payload = _make_nvd_payload(
            cve_id="CVE-2023-FULL",
            metrics={
                "cvssMetricV31": [
                    {
                        "type": "Primary",
                        "cvssData": {
                            "version": "3.1",
                            "baseScore": 8.8,
                            "baseSeverity": "HIGH",
                            "attackVector": "NETWORK",
                            "privilegesRequired": "LOW",
                            "userInteraction": "NONE",
                        },
                    }
                ]
            },
        )
        epss = {"CVE-2023-FULL": {"epss": "0.95", "percentile": "0.99"}}
        kev = {"CVE-2023-FULL": {"dateAdded": "2023-07-01"}}

        service = _make_service(
            nvd_return=nvd_payload,
            epss_return=epss,
            kev_return=kev,
        )
        matches = [_make_match("CVE-2023-FULL")]
        result = await service.enrich(matches)

        intel = result.knowledge["CVE-2023-FULL"]
        assert intel.epss_score == 0.95
        assert intel.epss_percentile == 0.99
        assert intel.kev_listed is True
        assert intel.kev_date_added == "2023-07-01"
        assert "Listed in CISA KEV catalog." in intel.notes

    async def test_epss_failure_does_not_block_enrichment(self):
        """EPSS failure should be swallowed; enrichment continues."""
        # Production catches AILAError inside enrich(), so raise an AILA-derived
        # error to exercise the "swallow and continue" branch.
        from aila.platform.exceptions import UpstreamError
        nvd_payload = _make_nvd_payload(cve_id="CVE-2023-EPSSFAIL", metrics={})
        service = _make_service(
            nvd_return=nvd_payload,
            epss_side_effect=UpstreamError("EPSS unreachable"),
        )
        matches = [_make_match("CVE-2023-EPSSFAIL")]
        result = await service.enrich(matches)

        assert "CVE-2023-EPSSFAIL" in result.knowledge
        assert result.knowledge["CVE-2023-EPSSFAIL"].epss_score is None

    async def test_kev_failure_does_not_block_enrichment(self):
        """KEV failure should be swallowed; enrichment continues."""
        from aila.platform.exceptions import UpstreamError
        nvd_payload = _make_nvd_payload(cve_id="CVE-2023-KEVFAIL", metrics={})
        service = _make_service(
            nvd_return=nvd_payload,
            kev_side_effect=UpstreamError("KEV unreachable"),
        )
        matches = [_make_match("CVE-2023-KEVFAIL")]
        result = await service.enrich(matches)

        assert "CVE-2023-KEVFAIL" in result.knowledge
        assert result.knowledge["CVE-2023-KEVFAIL"].kev_listed is False

    async def test_cache_hit_path_uses_cached_intel(self):
        """Fresh cache entries should be reused without calling NVD."""
        cached_payload = {
            "cve_id": "CVE-2023-CACHED",
            "description": "Cached description",
            "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-CACHED",
            "last_synced_at": _FRESH_TS,
        }
        service = _make_service(cache_batch_return={"CVE-2023-CACHED": cached_payload})
        matches = [_make_match("CVE-2023-CACHED")]

        result = await service.enrich(matches)

        intel = result.knowledge["CVE-2023-CACHED"]
        assert intel.intel_source_mode == "cache"
        assert intel.intel_last_synced_at == _FRESH_TS
        # NVD tool should NOT have been called
        service.nvd_tool.forward.assert_not_called()

    async def test_force_refresh_bypasses_cache(self):
        """force_refresh=True should call NVD even for cached entries."""
        cached_payload = {
            "cve_id": "CVE-2023-REFRESH",
            "description": "Stale",
            "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-REFRESH",
        }
        nvd_payload = _make_nvd_payload(
            cve_id="CVE-2023-REFRESH",
            description="Fresh from NVD",
            metrics={},
        )
        service = _make_service(
            nvd_return=nvd_payload,
            cache_batch_return={"CVE-2023-REFRESH": cached_payload},
        )
        matches = [_make_match("CVE-2023-REFRESH")]

        result = await service.enrich(matches, force_refresh=True)

        intel = result.knowledge["CVE-2023-REFRESH"]
        assert intel.description == "Fresh from NVD"
        assert intel.intel_source_mode == "live"
        assert "Forced refresh" in result.message
        service.nvd_tool.forward.assert_called_once()

    async def test_fallback_entries_not_written_to_cache(self):
        """Fallback intel (rate limited) should NOT be persisted to cache."""
        service = _make_service(nvd_side_effect=RateLimitError("rate limited"))
        matches = [_make_match("CVE-2023-NOWRITE")]

        result = await service.enrich(matches)

        intel = result.knowledge["CVE-2023-NOWRITE"]
        assert intel.intel_source_mode == "fallback"
        # cache_tool.forward should have been called for batch get but NOT for set
        cache_calls = service.cache_tool.forward.call_args_list
        set_calls = [c for c in cache_calls if c.kwargs.get("action") == "cve_cache_set"]
        assert len(set_calls) == 0

    async def test_successful_entries_written_to_cache(self):
        """Non-fallback intel SHOULD be persisted to cache."""
        nvd_payload = _make_nvd_payload(cve_id="CVE-2023-WRITE", metrics={})
        service = _make_service(nvd_return=nvd_payload)
        matches = [_make_match("CVE-2023-WRITE")]

        await service.enrich(matches)

        cache_calls = service.cache_tool.forward.call_args_list
        set_calls = [c for c in cache_calls if c.kwargs.get("action") == "cve_cache_set"]
        assert len(set_calls) == 1
        assert set_calls[0].kwargs["cve_id"] == "CVE-2023-WRITE"
        assert "last_synced_at" in set_calls[0].kwargs["payload"]

    async def test_kev_note_not_duplicated(self):
        """KEV catalog note should not be appended if already present."""
        cached_payload = {
            "cve_id": "CVE-2023-KEVDUP",
            "description": "Already has KEV note",
            "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-KEVDUP",
            "last_synced_at": _FRESH_TS,
            "notes": ["Listed in CISA KEV catalog."],
            "kev_listed": True,
        }
        kev = {"CVE-2023-KEVDUP": {"dateAdded": "2023-08-01"}}
        service = _make_service(
            cache_batch_return={"CVE-2023-KEVDUP": cached_payload},
            kev_return=kev,
        )
        matches = [_make_match("CVE-2023-KEVDUP")]

        result = await service.enrich(matches)
        intel = result.knowledge["CVE-2023-KEVDUP"]
        count = intel.notes.count("Listed in CISA KEV catalog.")
        assert count == 1

    async def test_enrichment_summary_counts(self):
        """Verify enrichment summary counters are populated correctly."""
        nvd_payload = _make_nvd_payload(cve_id="CVE-2023-MISS", metrics={})
        cached = {
            "cve_id": "CVE-2023-HIT",
            "description": "Cached",
            "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-HIT",
            "last_synced_at": _FRESH_TS,
        }
        service = _make_service(
            nvd_return=nvd_payload,
            cache_batch_return={"CVE-2023-HIT": cached},
        )
        matches = [_make_match("CVE-2023-HIT"), _make_match("CVE-2023-MISS")]

        result = await service.enrich(matches)

        summary = result.enrichment_summary
        assert summary.fresh_cache_hits == 1
        assert summary.missing_cache_entries == 1
        assert summary.refresh_targets == 1
        assert summary.live_refreshes == 1
        assert summary.fallback_refreshes == 0

    async def test_fallback_count_in_message(self):
        """When NVD fallbacks happen, the count should appear in the message."""
        service = _make_service(nvd_side_effect=RateLimitError("rate limited"))
        matches = [_make_match("CVE-2023-FB1"), _make_match("CVE-2023-FB2")]

        result = await service.enrich(matches)

        assert "2 CVEs used fallback NVD metadata" in result.message
        assert result.enrichment_summary.fallback_refreshes == 2


# ===========================================================================
# prewarm()  (async)
# ===========================================================================


class TestPrewarm:

    async def test_prewarm_empty_input(self):
        service = _make_service()
        result = await service.prewarm([])

        assert isinstance(result, PrewarmResult)
        assert result.count == 0
        assert "No CVE identifiers" in result.message

    async def test_prewarm_filters_empty_strings(self):
        service = _make_service()
        result = await service.prewarm(["", None])

        assert result.count == 0

    async def test_prewarm_returns_prewarm_result(self):
        nvd_payload = _make_nvd_payload(cve_id="CVE-2023-PW", metrics={})
        service = _make_service(nvd_return=nvd_payload)

        result = await service.prewarm(["CVE-2023-PW"])

        assert isinstance(result, PrewarmResult)
        assert result.count == 1
        assert "Prewarmed intel for 1 CVEs" in result.message
        assert isinstance(result.metadata, dict)

    async def test_prewarm_deduplicates_ids(self):
        nvd_payload = _make_nvd_payload(cve_id="CVE-2023-PWDUP", metrics={})
        service = _make_service(nvd_return=nvd_payload)

        result = await service.prewarm(["CVE-2023-PWDUP", "CVE-2023-PWDUP", "CVE-2023-PWDUP"])

        assert result.count == 1

    async def test_prewarm_metadata_has_summary_fields(self):
        nvd_payload = _make_nvd_payload(cve_id="CVE-2023-META", metrics={})
        service = _make_service(nvd_return=nvd_payload)

        result = await service.prewarm(["CVE-2023-META"])

        meta = result.metadata
        assert "fresh_cache_hits" in meta
        assert "refresh_targets" in meta
        assert "missing_cache_entries" in meta

    async def test_prewarm_with_force_refresh(self):
        cached = {
            "cve_id": "CVE-2023-PWFR",
            "description": "Old",
            "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-PWFR",
        }
        nvd_payload = _make_nvd_payload(cve_id="CVE-2023-PWFR", description="Refreshed", metrics={})
        service = _make_service(
            nvd_return=nvd_payload,
            cache_batch_return={"CVE-2023-PWFR": cached},
        )

        result = await service.prewarm(["CVE-2023-PWFR"], force_refresh=True)

        assert result.count == 1
        service.nvd_tool.forward.assert_called_once()


# ===========================================================================
# _enrich_cve_ids (async, integration-level with mocked tools)
# ===========================================================================


class TestEnrichCveIds:

    async def test_mixed_cache_and_live(self):
        """One cached CVE + one missing CVE: both appear in knowledge."""
        cached = {
            "cve_id": "CVE-2023-C1",
            "description": "From cache",
            "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-C1",
            "last_synced_at": _FRESH_TS,
        }
        nvd_payload = _make_nvd_payload(cve_id="CVE-2023-L1", metrics={})

        service = _make_service(
            nvd_return=nvd_payload,
            cache_batch_return={"CVE-2023-C1": cached},
        )

        result = await service._enrich_cve_ids(["CVE-2023-C1", "CVE-2023-L1"], force_refresh=False)

        assert "CVE-2023-C1" in result.knowledge
        assert "CVE-2023-L1" in result.knowledge
        assert result.knowledge["CVE-2023-C1"].intel_source_mode == "cache"
        assert result.knowledge["CVE-2023-L1"].intel_source_mode == "live"

    async def test_epss_and_kev_overlay_on_cached(self):
        """EPSS/KEV data should overlay onto cache-hit entries too."""
        cached = {
            "cve_id": "CVE-2023-OVERLAY",
            "description": "Cached",
            "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-OVERLAY",
            "last_synced_at": _FRESH_TS,
        }
        epss = {"CVE-2023-OVERLAY": {"epss": "0.42", "percentile": "0.85"}}
        kev = {"CVE-2023-OVERLAY": {"dateAdded": "2023-09-15"}}

        service = _make_service(
            cache_batch_return={"CVE-2023-OVERLAY": cached},
            epss_return=epss,
            kev_return=kev,
        )

        result = await service._enrich_cve_ids(["CVE-2023-OVERLAY"], force_refresh=False)

        intel = result.knowledge["CVE-2023-OVERLAY"]
        assert intel.epss_score == 0.42
        assert intel.epss_percentile == 0.85
        assert intel.kev_listed is True
        assert "Listed in CISA KEV catalog." in intel.notes

    async def test_both_epss_and_kev_fail(self):
        """When both EPSS and KEV fail, enrichment still completes."""
        # Production catches AILAError, so use an AILA-derived error to exercise
        # the fallback branch (a bare RuntimeError would propagate uncaught).
        from aila.platform.exceptions import UpstreamError
        nvd_payload = _make_nvd_payload(cve_id="CVE-2023-BOTHFAIL", metrics={})
        service = _make_service(
            nvd_return=nvd_payload,
            epss_side_effect=UpstreamError("EPSS down"),
            kev_side_effect=UpstreamError("KEV down"),
        )

        result = await service._enrich_cve_ids(["CVE-2023-BOTHFAIL"], force_refresh=False)

        assert "CVE-2023-BOTHFAIL" in result.knowledge
        intel = result.knowledge["CVE-2023-BOTHFAIL"]
        assert intel.epss_score is None
        assert intel.kev_listed is False

    async def test_message_includes_cache_stats(self):
        """Result message should include cache hit and refresh counts."""
        nvd_payload = _make_nvd_payload(cve_id="CVE-2023-STATS", metrics={})
        service = _make_service(nvd_return=nvd_payload)

        result = await service._enrich_cve_ids(["CVE-2023-STATS"], force_refresh=False)

        assert "Cache hits: 0" in result.message
        assert "refresh targets: 1" in result.message
        assert "missing 1" in result.message
