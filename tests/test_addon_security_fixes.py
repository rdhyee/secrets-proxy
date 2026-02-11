from __future__ import annotations

import gzip
import json
import logging
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from secrets_proxy import addon as addon_module
from secrets_proxy.addon import SecretsProxyAddon
from secrets_proxy.config import ProxyConfig, SecretEntry


def _make_config(secret_value: str = "sk-openai-real") -> ProxyConfig:
    entry = SecretEntry(
        name="OPENAI_API_KEY",
        placeholder="SECRETS_PROXY_PLACEHOLDER_openai",
        value=secret_value,
        hosts=["api.openai.com"],
    )
    config = ProxyConfig(
        secrets={"OPENAI_API_KEY": entry},
        allowed_hosts={"api.openai.com"},
    )
    config._placeholder_to_secret[entry.placeholder] = entry
    return config


def _make_request_flow(
    *,
    body: str,
    content_type: str,
    host: str = "api.openai.com",
) -> SimpleNamespace:
    return SimpleNamespace(
        request=SimpleNamespace(
            pretty_host=host,
            url="https://api.openai.com/v1/chat/completions",
            path="/v1/chat/completions",
            method="POST",
            headers={"Content-Type": content_type},
            content=body.encode("utf-8"),
        ),
        response=None,
    )


def _make_response_flow(
    *,
    body: str,
    content_type: str = "application/json",
) -> SimpleNamespace:
    body_bytes = body.encode("utf-8")
    return SimpleNamespace(
        request=SimpleNamespace(
            pretty_host="api.openai.com",
            path="/v1/test",
            method="GET",
            headers={},
            url="https://api.openai.com/v1/test",
            content=None,
        ),
        response=SimpleNamespace(
            headers={
                "Content-Type": content_type,
                "Content-Length": str(len(body_bytes)),
            },
            content=body_bytes,
        ),
    )


def test_request_json_body_escapes_double_quotes() -> None:
    secret_value = 'sk-"quoted"'
    config = _make_config(secret_value=secret_value)
    addon = SecretsProxyAddon(config)
    flow = _make_request_flow(
        body='{"token":"SECRETS_PROXY_PLACEHOLDER_openai"}',
        content_type="application/json",
    )

    addon.request(flow)

    body_text = flow.request.content.decode("utf-8")
    assert json.loads(body_text)["token"] == secret_value
    assert '\\"' in body_text


def test_request_json_body_escapes_backslashes() -> None:
    secret_value = r"sk\path\segment"
    config = _make_config(secret_value=secret_value)
    addon = SecretsProxyAddon(config)
    flow = _make_request_flow(
        body='{"token":"SECRETS_PROXY_PLACEHOLDER_openai"}',
        content_type="application/json",
    )

    addon.request(flow)

    body_text = flow.request.content.decode("utf-8")
    assert json.loads(body_text)["token"] == secret_value
    assert "\\\\" in body_text


def test_request_non_json_body_keeps_raw_substitution() -> None:
    secret_value = 'sk-"quoted"\\path'
    config = _make_config(secret_value=secret_value)
    addon = SecretsProxyAddon(config)
    flow = _make_request_flow(
        body="token=SECRETS_PROXY_PLACEHOLDER_openai",
        content_type="text/plain",
    )

    addon.request(flow)

    assert flow.request.content.decode("utf-8") == f"token={secret_value}"


def test_response_json_redaction_handles_json_escaped_secret() -> None:
    secret_value = 'sk-"quoted"\\path'
    config = _make_config(secret_value=secret_value)
    addon = SecretsProxyAddon(config)
    response_body = json.dumps({"token": secret_value})
    flow = _make_response_flow(body=response_body, content_type="application/json")

    addon.response(flow)

    redacted = flow.response.content.decode("utf-8")
    assert json.loads(redacted)["token"] == "[REDACTED:OPENAI_API_KEY]"


def test_try_decompress_normal_gzip_works() -> None:
    config = _make_config()
    addon = SecretsProxyAddon(config)
    original = b'{"token":"hello"}'
    compressed = gzip.compress(original)

    result = addon._try_decompress(compressed, "gzip")

    assert result == original


def test_try_decompress_oversize_returns_none_and_logs_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(addon_module, "MAX_DECOMPRESS_SIZE", 16)
    config = _make_config()
    addon = SecretsProxyAddon(config)
    compressed = gzip.compress(b"a" * 17)

    with caplog.at_level(logging.WARNING):
        result = addon._try_decompress(compressed, "gzip")

    assert result is None
    assert any(
        "reason=decompress_oversize" in rec.message and "encoding=gzip" in rec.message
        for rec in caplog.records
    )


def test_websocket_message_kills_flow_and_logs_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _make_config()
    addon = SecretsProxyAddon(config)
    flow = MagicMock()
    flow.request.pretty_host = "api.openai.com"
    flow.request.path = "/ws"

    with caplog.at_level(logging.WARNING):
        addon.websocket_message(flow)

    flow.kill.assert_called_once()
    assert any(
        "WebSocket blocked (not supported by secrets-proxy)" in rec.message
        for rec in caplog.records
    )
