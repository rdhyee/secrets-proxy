"""Tests for response scrubbing (reflection attack prevention)."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

import pytest

from secrets_proxy.addon import SecretsProxyAddon
from secrets_proxy.config import ProxyConfig, SecretEntry


def _make_config(secret_value="sk-real-key-12345", secret_name="OPENAI_API_KEY"):
    """Create a minimal ProxyConfig for testing."""
    entry = SecretEntry(
        name=secret_name,
        placeholder="SECRETS_PROXY_PLACEHOLDER_abc123",
        value=secret_value,
        hosts=["api.openai.com"],
    )
    config = ProxyConfig(
        secrets={secret_name: entry},
        allowed_hosts={"api.openai.com"},
    )
    config._placeholder_to_secret[entry.placeholder] = entry
    return config


def _make_flow(
    host="api.openai.com",
    response_body=None,
    response_headers=None,
):
    """Create a mock mitmproxy flow with a response."""
    flow = MagicMock()
    flow.request.pretty_host = host
    flow.request.path = "/v1/test"
    flow.request.method = "GET"
    flow.request.url = f"https://{host}/v1/test"
    flow.request.headers = {}
    flow.request.content = None

    if response_body is not None:
        flow.response.content = response_body.encode("utf-8")
    else:
        flow.response.content = None

    if response_headers is not None:
        flow.response.headers = MagicMock()
        flow.response.headers.keys.return_value = list(response_headers.keys())
        flow.response.headers.__getitem__ = lambda self, k: response_headers[k]
        flow.response.headers.__setitem__ = lambda self, k, v: response_headers.__setitem__(k, v)
        flow.response.headers.__contains__ = lambda self, k: k in response_headers
        flow.response.headers.get = lambda k, d="": response_headers.get(k, d)
    else:
        flow.response.headers = MagicMock()
        flow.response.headers.keys.return_value = []
        flow.response.headers.get = lambda k, d="": d

    return flow


class TestResponseScrubbing:
    """Test that real secret values are redacted from responses."""

    def test_redact_secret_in_response_body(self):
        config = _make_config()
        addon = SecretsProxyAddon(config)

        flow = _make_flow(
            response_body='{"headers": {"Authorization": "Bearer sk-real-key-12345"}}',
        )

        addon.response(flow)

        result = flow.response.content.decode("utf-8")
        assert "sk-real-key-12345" not in result
        assert "[REDACTED:OPENAI_API_KEY]" in result

    def test_no_redaction_when_no_secret_in_body(self):
        config = _make_config()
        addon = SecretsProxyAddon(config)

        original_body = '{"message": "hello world"}'
        flow = _make_flow(response_body=original_body)

        addon.response(flow)

        # Content should not be modified
        assert flow.response.content == original_body.encode("utf-8")

    def test_redact_secret_in_response_header(self):
        config = _make_config()
        addon = SecretsProxyAddon(config)

        headers = {"X-Echo": "Bearer sk-real-key-12345", "Content-Type": "text/plain"}
        flow = _make_flow(response_headers=headers)

        addon.response(flow)

        assert "sk-real-key-12345" not in headers["X-Echo"]
        assert "[REDACTED:OPENAI_API_KEY]" in headers["X-Echo"]

    def test_redact_multiple_occurrences(self):
        config = _make_config()
        addon = SecretsProxyAddon(config)

        flow = _make_flow(
            response_body="key1=sk-real-key-12345 key2=sk-real-key-12345",
        )

        addon.response(flow)

        result = flow.response.content.decode("utf-8")
        assert "sk-real-key-12345" not in result
        assert result.count("[REDACTED:OPENAI_API_KEY]") == 2

    def test_no_crash_on_none_response(self):
        config = _make_config()
        addon = SecretsProxyAddon(config)

        flow = MagicMock()
        flow.response = None

        # Should not raise
        addon.response(flow)

    def test_no_crash_on_binary_response(self):
        config = _make_config()
        addon = SecretsProxyAddon(config)

        flow = _make_flow()
        flow.response.content = b"\x89PNG\r\n\x1a\n\x00\x00"

        # Should not raise (binary content can't be decoded as utf-8)
        addon.response(flow)

    def test_redact_preserves_placeholder(self):
        """Ensure placeholders are NOT redacted — only real values."""
        config = _make_config()
        addon = SecretsProxyAddon(config)

        flow = _make_flow(
            response_body="SECRETS_PROXY_PLACEHOLDER_abc123 is the placeholder",
        )

        addon.response(flow)

        result = flow.response.content.decode("utf-8")
        # Placeholder should still be there (it's harmless)
        assert "SECRETS_PROXY_PLACEHOLDER_abc123" in result
        # No redaction markers since no real secret value present
        assert "[REDACTED:" not in result

    def test_brotli_response_with_scrub_needed_is_blocked(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ):
        """Fail closed when Brotli is unavailable and response needs scrubbing."""
        monkeypatch.setattr("secrets_proxy.addon._HAS_BROTLI", False)
        monkeypatch.setattr("secrets_proxy.addon._brotli", None)

        config = _make_config()
        addon = SecretsProxyAddon(config)
        original = "Bearer sk-real-key-12345"
        headers = {
            "Content-Encoding": "br",
            "Content-Length": str(len(original.encode("utf-8"))),
        }
        flow = _make_flow(response_body=original, response_headers=headers)
        flow._secrets_proxy_request_had_substitutions = True

        with caplog.at_level(logging.WARNING):
            addon.response(flow)

        assert flow.response.status_code == 502
        assert b"blocked Brotli response" in flow.response.content
        assert any(
            "audit action=block_response" in rec.message
            for rec in caplog.records
        )

    def test_brotli_response_without_scrub_needed_passes_through(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ):
        """Pass through when Brotli is unavailable but no scrubbing is needed."""
        monkeypatch.setattr("secrets_proxy.addon._HAS_BROTLI", False)
        monkeypatch.setattr("secrets_proxy.addon._brotli", None)

        config = _make_config()
        addon = SecretsProxyAddon(config)
        original = '{"message": "no secrets here"}'
        headers = {
            "Content-Encoding": "br",
            "Content-Length": str(len(original.encode("utf-8"))),
        }
        flow = _make_flow(response_body=original, response_headers=headers)
        flow._secrets_proxy_request_had_substitutions = False

        with caplog.at_level(logging.WARNING):
            addon.response(flow)

        assert flow.response.content == original.encode("utf-8")
        assert any(
            "audit action=pass_response" in rec.message
            and "reason=brotli_unavailable_no_scrub_needed" in rec.message
            for rec in caplog.records
        )

    def test_brotli_response_with_brotli_available_scrubs_normally(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        """With Brotli available, decode/scrub/re-encode should work."""

        class _FakeBrotli:
            @staticmethod
            def compress(data: bytes) -> bytes:
                return b"BR:" + data

            @staticmethod
            def decompress(data: bytes) -> bytes:
                assert data.startswith(b"BR:")
                return data[3:]

        monkeypatch.setattr("secrets_proxy.addon._HAS_BROTLI", True)
        monkeypatch.setattr("secrets_proxy.addon._brotli", _FakeBrotli)

        config = _make_config()
        addon = SecretsProxyAddon(config)
        original = "Bearer sk-real-key-12345"
        compressed = _FakeBrotli.compress(original.encode("utf-8"))
        headers = {
            "Content-Encoding": "br",
            "Content-Length": str(len(compressed)),
        }
        flow = _make_flow(response_body="", response_headers=headers)
        flow.response.content = compressed

        addon.response(flow)

        assert flow.response.headers["Content-Encoding"] == "br"
        decoded = _FakeBrotli.decompress(flow.response.content).decode("utf-8")
        assert "sk-real-key-12345" not in decoded
        assert "[REDACTED:OPENAI_API_KEY]" in decoded
        assert flow.response.headers["Content-Length"] == str(len(flow.response.content))


class TestRedactSecretsInText:
    """Test the _redact_secrets_in_text helper directly."""

    def test_basic_redaction(self):
        config = _make_config()
        addon = SecretsProxyAddon(config)

        text, count = addon._redact_secrets_in_text(
            "Authorization: Bearer sk-real-key-12345"
        )
        assert count == 1
        assert "sk-real-key-12345" not in text
        assert "[REDACTED:OPENAI_API_KEY]" in text

    def test_no_match(self):
        config = _make_config()
        addon = SecretsProxyAddon(config)

        text, count = addon._redact_secrets_in_text("nothing to see here")
        assert count == 0
        assert text == "nothing to see here"

    def test_multiple_secrets(self):
        entry1 = SecretEntry(
            name="SECRET_A",
            placeholder="PLACEHOLDER_A",
            value="value-aaa",
            hosts=["a.com"],
        )
        entry2 = SecretEntry(
            name="SECRET_B",
            placeholder="PLACEHOLDER_B",
            value="value-bbb",
            hosts=["b.com"],
        )
        config = ProxyConfig(
            secrets={"SECRET_A": entry1, "SECRET_B": entry2},
            allowed_hosts={"a.com", "b.com"},
        )
        config._placeholder_to_secret["PLACEHOLDER_A"] = entry1
        config._placeholder_to_secret["PLACEHOLDER_B"] = entry2

        addon = SecretsProxyAddon(config)
        text, count = addon._redact_secrets_in_text(
            "has value-aaa and value-bbb inside"
        )
        assert count == 2
        assert "value-aaa" not in text
        assert "value-bbb" not in text
        assert "[REDACTED:SECRET_A]" in text
        assert "[REDACTED:SECRET_B]" in text
