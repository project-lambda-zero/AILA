"""Tests for BaseProviderClient lifecycle (GEN-04)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from aila.modules.vulnerability.providers._base_client import BaseProviderClient
from aila.modules.vulnerability.config_schema import VulnerabilityConfigSchema


class TestBaseProviderClientInit:
    def test_sets_settings(self, mock_settings, mock_http_client):
        with patch(
            "aila.modules.vulnerability.providers._base_client.build_provider_http_client",
            return_value=mock_http_client,
        ):
            client = BaseProviderClient(mock_settings)
        assert client.settings is mock_settings

    def test_sets_default_config(self, mock_settings, mock_http_client):
        with patch(
            "aila.modules.vulnerability.providers._base_client.build_provider_http_client",
            return_value=mock_http_client,
        ):
            client = BaseProviderClient(mock_settings)
        assert isinstance(client.config, VulnerabilityConfigSchema)

    def test_uses_provided_config(self, mock_settings, mock_http_client):
        config = VulnerabilityConfigSchema()
        with patch(
            "aila.modules.vulnerability.providers._base_client.build_provider_http_client",
            return_value=mock_http_client,
        ):
            client = BaseProviderClient(mock_settings, config)
        assert client.config is config

    def test_builds_http_client(self, mock_settings, mock_http_client):
        with patch(
            "aila.modules.vulnerability.providers._base_client.build_provider_http_client",
            return_value=mock_http_client,
        ) as mock_build:
            client = BaseProviderClient(mock_settings)
        mock_build.assert_called_once()
        assert client._http_client is mock_http_client


class TestBaseProviderClientClose:
    def test_close_calls_http_client_close(self, mock_settings, mock_http_client):
        with patch(
            "aila.modules.vulnerability.providers._base_client.build_provider_http_client",
            return_value=mock_http_client,
        ):
            client = BaseProviderClient(mock_settings)
        client.close()
        mock_http_client.close.assert_called_once()


class TestBaseProviderClientDel:
    def test_del_calls_http_client_close(self, mock_settings, mock_http_client):
        with patch(
            "aila.modules.vulnerability.providers._base_client.build_provider_http_client",
            return_value=mock_http_client,
        ):
            client = BaseProviderClient(mock_settings)
        client.__del__()
        mock_http_client.close.assert_called_once()

    def test_del_does_not_raise_when_close_raises(self, mock_settings):
        failing_http_client = MagicMock()
        failing_http_client.close.side_effect = RuntimeError("transport already closed")
        with patch(
            "aila.modules.vulnerability.providers._base_client.build_provider_http_client",
            return_value=failing_http_client,
        ):
            client = BaseProviderClient(mock_settings)
        # Must not raise
        client.__del__()


@pytest.fixture
def mock_settings():
    settings = MagicMock()
    settings.request_timeout_seconds = 30.0
    return settings


@pytest.fixture
def mock_http_client():
    return MagicMock()
