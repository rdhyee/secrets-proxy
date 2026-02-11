"""Thin mitmproxy entry point for secrets-proxy.

Loaded by: mitmdump -s addon_entry.py

Reads SECRETS_PROXY_CONFIG_JSON from the environment, builds a ProxyConfig,
and instantiates the production SecretsProxyAddon.
This ensures all deployment paths (launcher, Docker, Sprites) use the same
addon code with full security features (compression, JSON escaping, URL
encoding, WebSocket blocking, Brotli fail-closed, decompression limits).
"""

from __future__ import annotations

import logging
import os

from secrets_proxy.addon import SecretsProxyAddon
from secrets_proxy.config import ProxyConfig

logger = logging.getLogger("secrets-proxy")


def _load_config_from_env() -> ProxyConfig:
    """Load ProxyConfig from the SECRETS_PROXY_CONFIG_JSON env var.

    Expected JSON format (produced by ProxyConfig.to_env_json()):
    {
        "secrets": {
            "PLACEHOLDER_HEX": {
                "name": "SECRET_NAME",
                "value": "real-value",
                "hosts": ["api.example.com"]
            }
        },
        "allowed_hosts": ["api.example.com", ...]
    }

    The env var is popped immediately so child processes don't inherit it.
    """
    raw_json = os.environ.pop("SECRETS_PROXY_CONFIG_JSON")
    return ProxyConfig.from_env_json(raw_json)


config = _load_config_from_env()
addons = [SecretsProxyAddon(config)]
