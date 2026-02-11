"""mitmproxy addon that performs placeholder → secret substitution on outbound requests."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from mitmproxy import http

if TYPE_CHECKING:
    from .config import ProxyConfig, SecretEntry

logger = logging.getLogger("secrets-proxy")


class SecretsProxyAddon:
    """mitmproxy addon that intercepts HTTPS requests and:

    1. Blocks requests to non-allowlisted hosts
    2. Substitutes placeholder strings with real secrets for approved hosts
    """

    def __init__(self, config: ProxyConfig):
        self.config = config
        self._stats = {"blocked": 0, "substituted": 0, "passed": 0}

    def _host_allowed(self, host: str) -> bool:
        """Check if a host is in the allowlist (including wildcard patterns)."""
        for pattern in self.config.allowed_hosts:
            if pattern.startswith("*."):
                suffix = pattern[1:]
                if host.endswith(suffix) or host == pattern[2:]:
                    return True
            elif host == pattern:
                return True
        return False

    def _substitute_in_text(self, text: str, host: str) -> tuple[str, int]:
        """Replace all placeholder occurrences with real secrets for the given host.

        Returns the modified text and the number of substitutions made.
        """
        count = 0
        matches = self.config.find_secret_for_placeholder(text)
        for placeholder, entry in matches:
            if entry.matches_host(host):
                text = text.replace(placeholder, entry.value)
                count += 1
                logger.debug(
                    "Substituted secret '%s' for host '%s'", entry.name, host
                )
            else:
                logger.warning(
                    "Placeholder for '%s' found in request to '%s' but host not approved "
                    "(approved: %s). Placeholder left intact.",
                    entry.name,
                    host,
                    entry.hosts,
                )
        return text, count

    def request(self, flow: http.HTTPFlow) -> None:
        """Process each outbound request."""
        host = flow.request.pretty_host

        # 1. Block non-allowlisted hosts
        if not self._host_allowed(host):
            flow.response = http.Response.make(
                403,
                f"secrets-proxy: host '{host}' not in allowlist".encode(),
                {"Content-Type": "text/plain"},
            )
            self._stats["blocked"] += 1
            logger.info("Blocked request to non-allowed host: %s", host)
            return

        # 2. Substitute placeholders in request headers
        total_subs = 0
        for header_name in list(flow.request.headers.keys()):
            header_value = flow.request.headers[header_name]
            new_value, subs = self._substitute_in_text(header_value, host)
            if subs > 0:
                flow.request.headers[header_name] = new_value
                total_subs += subs

        # 3. Substitute placeholders in URL (query params)
        if flow.request.url:
            new_url, subs = self._substitute_in_text(flow.request.url, host)
            if subs > 0:
                flow.request.url = new_url
                total_subs += subs

        # 4. Substitute placeholders in request body
        if flow.request.content:
            try:
                body_text = flow.request.content.decode("utf-8")
                new_body, subs = self._substitute_in_text(body_text, host)
                if subs > 0:
                    flow.request.content = new_body.encode("utf-8")
                    total_subs += subs
            except UnicodeDecodeError:
                pass  # Binary body, skip substitution

        if total_subs > 0:
            self._stats["substituted"] += 1
            logger.info(
                "Substituted %d secret(s) in request to %s%s",
                total_subs,
                host,
                flow.request.path,
            )
        else:
            self._stats["passed"] += 1

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)
