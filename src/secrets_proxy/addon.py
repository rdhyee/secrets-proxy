"""mitmproxy addon that performs placeholder → secret substitution on outbound requests."""

from __future__ import annotations

import gzip
import io
import json
import logging
import zlib
from typing import TYPE_CHECKING
from urllib.parse import quote as url_quote

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
        """Check if a host is in the allowlist (delegating to ProxyConfig)."""
        return self.config.is_host_allowed(host)

    def _substitute_in_text(
        self, text: str, host: str, url_encode: bool = False
    ) -> tuple[str, int]:
        """Replace all placeholder occurrences with real secrets for the given host.

        Args:
            text: The text to search for placeholders.
            host: The target host (used to check if the secret is approved).
            url_encode: If True, URL-encode the secret value before substitution
                        (used for URL/query-parameter contexts).

        Returns the modified text and the number of substitutions made.
        """
        count = 0
        matches = self.config.find_secret_for_placeholder(text)
        for placeholder, entry in matches:
            if entry.matches_host(host):
                value = entry.value
                if url_encode:
                    value = url_quote(value, safe="")
                text = text.replace(placeholder, value)
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

    def _try_decompress(self, data: bytes, encoding: str) -> bytes | None:
        """Try to decompress data according to Content-Encoding.

        Returns decompressed bytes, or None if decompression fails.
        """
        try:
            if encoding == "gzip":
                return gzip.decompress(data)
            elif encoding == "deflate":
                return zlib.decompress(data)
            elif encoding == "br":
                try:
                    import brotli
                    return brotli.decompress(data)
                except ImportError:
                    logger.warning(
                        "Brotli Content-Encoding detected but 'brotli' package not installed. "
                        "Skipping body substitution."
                    )
                    return None
        except Exception as exc:
            logger.warning("Failed to decompress %s body: %s", encoding, exc)
            return None
        return None

    def _try_compress(self, data: bytes, encoding: str) -> bytes | None:
        """Re-compress data with the given encoding. Returns None on failure."""
        try:
            if encoding == "gzip":
                buf = io.BytesIO()
                with gzip.GzipFile(fileobj=buf, mode="wb") as f:
                    f.write(data)
                return buf.getvalue()
            elif encoding == "deflate":
                return zlib.compress(data)
            elif encoding == "br":
                try:
                    import brotli
                    return brotli.compress(data)
                except ImportError:
                    return None
        except Exception as exc:
            logger.warning("Failed to re-compress %s body: %s", encoding, exc)
            return None
        return None

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

        # 3. Substitute placeholders in URL (query params) — URL-encode secrets
        if flow.request.url:
            new_url, subs = self._substitute_in_text(
                flow.request.url, host, url_encode=True
            )
            if subs > 0:
                flow.request.url = new_url
                total_subs += subs

        # 4. Substitute placeholders in request body
        if flow.request.content:
            content_encoding = flow.request.headers.get("Content-Encoding", "").lower().strip()
            body_bytes = flow.request.content
            was_compressed = False

            # Attempt decompression if Content-Encoding is set
            if content_encoding in ("gzip", "deflate", "br"):
                decompressed = self._try_decompress(body_bytes, content_encoding)
                if decompressed is not None:
                    body_bytes = decompressed
                    was_compressed = True
                else:
                    logger.warning(
                        "Could not decompress %s body for host %s; "
                        "skipping body substitution.",
                        content_encoding,
                        host,
                    )
                    body_bytes = None  # Signal to skip

            if body_bytes is not None:
                try:
                    body_text = body_bytes.decode("utf-8")
                    new_body, subs = self._substitute_in_text(body_text, host)
                    if subs > 0:
                        new_body_bytes = new_body.encode("utf-8")
                        if was_compressed:
                            recompressed = self._try_compress(new_body_bytes, content_encoding)
                            if recompressed is not None:
                                flow.request.content = recompressed
                            else:
                                # Could not re-compress; send uncompressed and remove header
                                flow.request.content = new_body_bytes
                                del flow.request.headers["Content-Encoding"]
                                logger.warning(
                                    "Removed Content-Encoding header after failed re-compression"
                                )
                        else:
                            flow.request.content = new_body_bytes
                        total_subs += subs
                except UnicodeDecodeError:
                    logger.warning(
                        "Request body to %s%s is not valid UTF-8; skipping body substitution.",
                        host,
                        flow.request.path,
                    )

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
