"""mitmproxy addon that performs placeholder -> secret substitution on outbound requests."""

from __future__ import annotations

import gzip
import io
import logging
import zlib
from typing import TYPE_CHECKING
from urllib.parse import quote as url_quote

from mitmproxy import http

if TYPE_CHECKING:
    from .config import ProxyConfig, SecretEntry

logger = logging.getLogger("secrets-proxy")

# Check brotli availability at import time
try:
    import brotli as _brotli
    _HAS_BROTLI = True
except ImportError:
    _brotli = None
    _HAS_BROTLI = False


class SecretsProxyAddon:
    """mitmproxy addon that intercepts HTTPS requests and:

    1. Blocks requests to non-allowlisted hosts
    2. Substitutes placeholder strings with real secrets for approved hosts
    3. Handles compressed bodies and URL-encoding context
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
                if _HAS_BROTLI:
                    return _brotli.decompress(data)
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
                if _HAS_BROTLI:
                    return _brotli.compress(data)
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
            logger.info(
                "audit action=block host=%s path=%s method=%s",
                host, flow.request.path, flow.request.method,
            )
            return

        # Strip brotli from Accept-Encoding if we can't handle it
        # (prevents fail-open where compressed body passes through unscanned)
        if not _HAS_BROTLI and "Accept-Encoding" in flow.request.headers:
            ae = flow.request.headers["Accept-Encoding"]
            tokens = [t.strip() for t in ae.split(",")]
            filtered = [t for t in tokens if t and not t.startswith("br")]
            cleaned = ", ".join(filtered)
            if cleaned != ae:
                if cleaned:
                    flow.request.headers["Accept-Encoding"] = cleaned
                else:
                    del flow.request.headers["Accept-Encoding"]

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
            content_encoding = flow.request.headers.get(
                "Content-Encoding", ""
            ).lower().strip()
            body_bytes = flow.request.content
            was_compressed = False

            # Parse Content-Encoding as a token list (handles compound like "gzip, br")
            _SUPPORTED_ENCODINGS = {"gzip", "deflate", "br", "identity", ""}
            encoding_tokens = [t.strip() for t in content_encoding.split(",")]

            if content_encoding and not all(t in _SUPPORTED_ENCODINGS for t in encoding_tokens):
                # Unknown or unsupported encoding — fail closed (cannot scan body)
                logger.warning(
                    "audit action=block host=%s path=%s reason=unsupported_content_encoding encoding=%s",
                    host, flow.request.path, content_encoding,
                )
                flow.response = http.Response.make(
                    415,
                    f"secrets-proxy: unsupported Content-Encoding '{content_encoding}'".encode(),
                    {"Content-Type": "text/plain"},
                )
                return

            # Apply decompression in reverse order (outermost encoding listed last)
            active_encodings = [t for t in encoding_tokens if t and t != "identity"]
            for enc in reversed(active_encodings):
                decompressed = self._try_decompress(body_bytes, enc)
                if decompressed is not None:
                    body_bytes = decompressed
                    was_compressed = True
                else:
                    logger.warning(
                        "audit action=skip_body host=%s path=%s reason=decompress_failed encoding=%s",
                        host, flow.request.path, enc,
                    )
                    body_bytes = None
                    break

            if body_bytes is not None:
                try:
                    body_text = body_bytes.decode("utf-8")
                    new_body, subs = self._substitute_in_text(body_text, host)
                    if subs > 0:
                        new_body_bytes = new_body.encode("utf-8")
                        if was_compressed:
                            # Re-compress in forward order (reverse of decompression)
                            recompressed = new_body_bytes
                            compress_ok = True
                            for enc in active_encodings:
                                result = self._try_compress(recompressed, enc)
                                if result is not None:
                                    recompressed = result
                                else:
                                    compress_ok = False
                                    break
                            if compress_ok:
                                flow.request.content = recompressed
                            else:
                                flow.request.content = new_body_bytes
                                del flow.request.headers["Content-Encoding"]
                        else:
                            flow.request.content = new_body_bytes
                        # Update Content-Length after any body mutation
                        if "Content-Length" in flow.request.headers:
                            flow.request.headers["Content-Length"] = str(
                                len(flow.request.content)
                            )
                        total_subs += subs
                except UnicodeDecodeError:
                    logger.warning(
                        "audit action=skip_body host=%s path=%s reason=binary_content",
                        host, flow.request.path,
                    )

        if total_subs > 0:
            self._stats["substituted"] += 1
            logger.info(
                "audit action=substitute host=%s path=%s secrets_injected=%d method=%s",
                host, flow.request.path, total_subs, flow.request.method,
            )
        else:
            self._stats["passed"] += 1
            logger.debug(
                "audit action=pass host=%s path=%s method=%s",
                host, flow.request.path, flow.request.method,
            )

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)
