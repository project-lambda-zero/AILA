"""Tests for HTTP capabilities: per-provider TLS toggle and proxy support (HTTP-01, HTTP-02)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from aila.modules.vulnerability.config_schema import VulnerabilityConfigSchema
from aila.modules.vulnerability.providers._http import build_provider_http_client
from aila.platform.config import PlatformConfigSchema


class TestVulnerabilityConfigSchemaVerifyTls:
    def test_nvd_verify_tls_defaults_true(self):
        assert VulnerabilityConfigSchema().nvd_verify_tls is True

    def test_nvd_verify_tls_can_be_false(self):
        assert VulnerabilityConfigSchema(nvd_verify_tls=False).nvd_verify_tls is False

    def test_osv_verify_tls_defaults_true(self):
        assert VulnerabilityConfigSchema().osv_verify_tls is True

    def test_osv_verify_tls_can_be_false(self):
        assert VulnerabilityConfigSchema(osv_verify_tls=False).osv_verify_tls is False

    def test_epss_verify_tls_defaults_true(self):
        assert VulnerabilityConfigSchema().epss_verify_tls is True

    def test_epss_verify_tls_can_be_false(self):
        assert VulnerabilityConfigSchema(epss_verify_tls=False).epss_verify_tls is False

    def test_kev_verify_tls_defaults_true(self):
        assert VulnerabilityConfigSchema().kev_verify_tls is True

    def test_kev_verify_tls_can_be_false(self):
        assert VulnerabilityConfigSchema(kev_verify_tls=False).kev_verify_tls is False

    def test_alpine_verify_tls_defaults_true(self):
        assert VulnerabilityConfigSchema().alpine_verify_tls is True

    def test_alpine_verify_tls_can_be_false(self):
        assert VulnerabilityConfigSchema(alpine_verify_tls=False).alpine_verify_tls is False

    def test_arch_verify_tls_defaults_true(self):
        assert VulnerabilityConfigSchema().arch_verify_tls is True

    def test_arch_verify_tls_can_be_false(self):
        assert VulnerabilityConfigSchema(arch_verify_tls=False).arch_verify_tls is False


class TestPlatformConfigSchemaProxy:
    def test_http_proxy_defaults_empty(self):
        assert PlatformConfigSchema().http_proxy == ""

    def test_https_proxy_defaults_empty(self):
        assert PlatformConfigSchema().https_proxy == ""

    def test_http_proxy_accepts_url(self):
        assert PlatformConfigSchema(http_proxy="http://proxy:3128").http_proxy == "http://proxy:3128"


class TestBuildProviderHttpClientVerifyTls:
    def test_nvd_verify_false_passes_verify_false_to_build_http_client(self):
        config = VulnerabilityConfigSchema(nvd_verify_tls=False)
        settings = MagicMock(request_timeout_seconds=30.0)
        with patch(
            "aila.modules.vulnerability.providers._http._build_http_client"
        ) as mock_build:
            mock_build.return_value = MagicMock()
            build_provider_http_client(settings, config, provider_name="nvd")
        _, kwargs = mock_build.call_args
        assert kwargs["verify"] is False

    def test_nvd_verify_true_by_default(self):
        config = VulnerabilityConfigSchema()
        settings = MagicMock(request_timeout_seconds=30.0)
        with patch(
            "aila.modules.vulnerability.providers._http._build_http_client"
        ) as mock_build:
            mock_build.return_value = MagicMock()
            build_provider_http_client(settings, config, provider_name="nvd")
        _, kwargs = mock_build.call_args
        assert kwargs["verify"] is True


class TestBuildProviderHttpClientProxy:
    def test_http_proxy_env_var_used_when_no_registry(self, monkeypatch):
        monkeypatch.setenv("HTTP_PROXY", "http://proxy.corp:3128")
        monkeypatch.delenv("HTTPS_PROXY", raising=False)
        config = VulnerabilityConfigSchema()
        settings = MagicMock(request_timeout_seconds=30.0)
        with patch(
            "aila.modules.vulnerability.providers._http._build_http_client"
        ) as mock_build:
            mock_build.return_value = MagicMock()
            build_provider_http_client(settings, config)
        _, kwargs = mock_build.call_args
        assert kwargs["proxies"] == "http://proxy.corp:3128"

    def test_no_proxy_when_env_vars_absent_and_no_registry(self, monkeypatch):
        monkeypatch.delenv("HTTP_PROXY", raising=False)
        monkeypatch.delenv("HTTPS_PROXY", raising=False)
        config = VulnerabilityConfigSchema()
        settings = MagicMock(request_timeout_seconds=30.0)
        with patch(
            "aila.modules.vulnerability.providers._http._build_http_client"
        ) as mock_build:
            mock_build.return_value = MagicMock()
            build_provider_http_client(settings, config)
        _, kwargs = mock_build.call_args
        assert kwargs.get("proxies") is None

    def test_registry_proxy_overrides_env_var(self, monkeypatch):
        monkeypatch.setenv("HTTP_PROXY", "http://env-proxy:3128")
        registry = MagicMock()
        registry.get.side_effect = lambda ns, key: (
            "http://registry-proxy:8080" if (ns, key) == ("platform", "https_proxy") else ""
        )
        config = VulnerabilityConfigSchema()
        settings = MagicMock(request_timeout_seconds=30.0)
        with patch(
            "aila.modules.vulnerability.providers._http._build_http_client"
        ) as mock_build:
            mock_build.return_value = MagicMock()
            build_provider_http_client(settings, config, registry=registry)
        _, kwargs = mock_build.call_args
        assert kwargs["proxies"] == "http://registry-proxy:8080"
