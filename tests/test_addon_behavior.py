"""Behavior-focused tests for SecretsProxyAddon request handling."""

from __future__ import annotations

import gzip
from types import SimpleNamespace
from urllib.parse import urlsplit

from secrets_proxy.addon import SecretsProxyAddon
from secrets_proxy.config import ProxyConfig, SecretEntry


def _make_config() -> ProxyConfig:
    openai = SecretEntry(
        name="OPENAI_API_KEY",
        placeholder="SECRETS_PROXY_PLACEHOLDER_openai",
        value="sk-openai-real",
        hosts=["api.openai.com"],
    )
    github = SecretEntry(
        name="GITHUB_TOKEN",
        placeholder="SECRETS_PROXY_PLACEHOLDER_github",
        value="ghp-github-real",
        hosts=["api.github.com"],
    )
    config = ProxyConfig(
        secrets={"OPENAI_API_KEY": openai, "GITHUB_TOKEN": github},
        allowed_hosts={"api.openai.com", "api.github.com"},
    )
    config._placeholder_to_secret[openai.placeholder] = openai
    config._placeholder_to_secret[github.placeholder] = github
    return config


def _make_flow(
    *,
    host: str,
    url: str,
    method: str = "POST",
    path: str = "/v1/chat/completions",
    headers: dict[str, str] | None = None,
    content: bytes | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        request=SimpleNamespace(
            pretty_host=host,
            url=url,
            path=path,
            method=method,
            headers=headers or {},
            content=content,
        ),
        response=None,
    )


def test_gzip_request_body_substitution_recompresses() -> None:
    config = _make_config()
    addon = SecretsProxyAddon(config)

    body = b'{"token":"SECRETS_PROXY_PLACEHOLDER_openai"}'
    compressed = gzip.compress(body)
    flow = _make_flow(
        host="api.openai.com",
        url="https://api.openai.com/v1/chat/completions",
        headers={
            "Content-Encoding": "gzip",
            "Content-Type": "application/json",
            "Content-Length": str(len(compressed)),
        },
        content=compressed,
    )

    addon.request(flow)

    assert flow.response is None
    assert flow.request.headers["Content-Encoding"] == "gzip"
    assert flow.request.headers["Content-Length"] == str(len(flow.request.content))

    decompressed = gzip.decompress(flow.request.content).decode("utf-8")
    assert "sk-openai-real" in decompressed
    assert "SECRETS_PROXY_PLACEHOLDER_openai" not in decompressed


def test_query_substitution_url_encodes_secret_value() -> None:
    config = _make_config()
    special = config.secrets["OPENAI_API_KEY"]
    special.value = "sk+/=?&value"
    addon = SecretsProxyAddon(config)

    flow = _make_flow(
        host="api.openai.com",
        method="GET",
        path="/v1/search",
        url=(
            "https://api.openai.com/v1/search"
            "?token=SECRETS_PROXY_PLACEHOLDER_openai&x=1"
        ),
        headers={},
        content=None,
    )

    addon.request(flow)

    query = urlsplit(flow.request.url).query
    assert "token=sk%2B%2F%3D%3F%26value" in query
    assert "SECRETS_PROXY_PLACEHOLDER_openai" not in query


def test_url_substitution_encodes_query_but_not_path() -> None:
    config = _make_config()
    special = config.secrets["OPENAI_API_KEY"]
    special.value = "raw/value+plus"
    addon = SecretsProxyAddon(config)

    flow = _make_flow(
        host="api.openai.com",
        method="GET",
        path="/v1/SECRETS_PROXY_PLACEHOLDER_openai/details",
        url=(
            "https://api.openai.com/v1/SECRETS_PROXY_PLACEHOLDER_openai/details"
            "?token=SECRETS_PROXY_PLACEHOLDER_openai"
        ),
        headers={},
        content=None,
    )

    addon.request(flow)

    split = urlsplit(flow.request.url)
    assert split.path == "/v1/raw/value+plus/details"
    assert "token=raw%2Fvalue%2Bplus" in split.query


def test_binary_body_skips_without_crashing() -> None:
    config = _make_config()
    addon = SecretsProxyAddon(config)

    binary = b"\xff\xfe\xfa\xfb\x00\x80"
    flow = _make_flow(
        host="api.openai.com",
        url="https://api.openai.com/upload",
        headers={"Content-Type": "application/octet-stream"},
        content=binary,
    )

    addon.request(flow)

    assert flow.response is None
    assert flow.request.content == binary


def test_blocked_host_gets_403() -> None:
    config = _make_config()
    addon = SecretsProxyAddon(config)

    flow = _make_flow(
        host="evil.example.com",
        method="GET",
        path="/",
        url="https://evil.example.com/",
        headers={},
        content=None,
    )

    addon.request(flow)

    assert flow.response is not None
    assert flow.response.status_code == 403


def test_allowed_host_without_placeholders_passes_through() -> None:
    config = _make_config()
    addon = SecretsProxyAddon(config)

    flow = _make_flow(
        host="api.openai.com",
        method="GET",
        path="/v1/models",
        url="https://api.openai.com/v1/models",
        headers={"Authorization": "Bearer static-value"},
        content=None,
    )

    addon.request(flow)

    assert flow.response is None
    assert flow.request.headers["Authorization"] == "Bearer static-value"


def test_multiple_secrets_only_host_matched_secret_substitutes() -> None:
    config = _make_config()
    addon = SecretsProxyAddon(config)

    flow = _make_flow(
        host="api.openai.com",
        url="https://api.openai.com/v1/chat/completions",
        headers={
            "Authorization": (
                "Bearer SECRETS_PROXY_PLACEHOLDER_openai "
                "and SECRETS_PROXY_PLACEHOLDER_github"
            )
        },
        content=None,
    )

    addon.request(flow)

    auth = flow.request.headers["Authorization"]
    assert "sk-openai-real" in auth
    assert "SECRETS_PROXY_PLACEHOLDER_github" in auth
    assert "ghp-github-real" not in auth
