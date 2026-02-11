"""mitmproxy addon that performs placeholder -> secret substitution on outbound requests."""

from __future__ import annotations

import gzip
import io
import json
import logging
import zlib
from typing import TYPE_CHECKING
from urllib.parse import quote as url_quote, urlsplit, urlunsplit

from mitmproxy import http

if TYPE_CHECKING:
    from .config import ProxyConfig, SecretEntry

logger = logging.getLogger("secrets-proxy")
MAX_DECOMPRESS_SIZE = 100 * 1024 * 1024

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
        self,
        text: str,
        host: str,
        url_encode: bool = False,
        json_escape: bool = False,
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
                if json_escape:
                    # json.dumps returns a quoted JSON string; strip quotes to get
                    # the JSON-escaped content for safe injection into existing JSON.
                    value = json.dumps(value)[1:-1]
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

    def _substitute_in_url(self, url: str, host: str) -> tuple[str, int]:
        """Substitute placeholders in a URL with query-only URL encoding.

        - Query component: URL-encode injected secret values.
        - Non-query components (scheme/netloc/path/fragment): plain substitution.
        """
        split = urlsplit(url)
        total_subs = 0

        scheme, subs = self._substitute_in_text(split.scheme, host, url_encode=False)
        total_subs += subs
        netloc, subs = self._substitute_in_text(split.netloc, host, url_encode=False)
        total_subs += subs
        path, subs = self._substitute_in_text(split.path, host, url_encode=False)
        total_subs += subs
        query, subs = self._substitute_in_text(split.query, host, url_encode=True)
        total_subs += subs
        fragment, subs = self._substitute_in_text(
            split.fragment, host, url_encode=False
        )
        total_subs += subs

        return urlunsplit((scheme, netloc, path, query, fragment)), total_subs

    @staticmethod
    def _is_json_content_type(content_type: str | None) -> bool:
        if not content_type:
            return False
        mime = content_type.split(";", 1)[0].strip().lower()
        return mime == "application/json"

    def _try_decompress(self, data: bytes, encoding: str) -> bytes | None:
        """Try to decompress data according to Content-Encoding.

        Returns decompressed bytes, or None if decompression fails.
        """
        try:
            result = None
            if encoding == "gzip":
                result = gzip.decompress(data)
            elif encoding == "deflate":
                result = zlib.decompress(data)
            elif encoding == "br":
                if _HAS_BROTLI:
                    result = _brotli.decompress(data)
                else:
                    logger.warning(
                        "Brotli Content-Encoding detected but 'brotli' package not installed. "
                        "Skipping body substitution."
                    )
                    return None
            if result is not None and len(result) > MAX_DECOMPRESS_SIZE:
                logger.warning(
                    "audit action=skip_body reason=decompress_oversize encoding=%s "
                    "decompressed_size=%d max_size=%d",
                    encoding,
                    len(result),
                    MAX_DECOMPRESS_SIZE,
                )
                return None
            return result
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

        # 3. Substitute placeholders in URL.
        # URL-encode substitutions in query only; keep path/host unencoded.
        if flow.request.url:
            new_url, subs = self._substitute_in_url(flow.request.url, host)
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
                    is_json_body = self._is_json_content_type(
                        flow.request.headers.get("Content-Type", "")
                    )
                    new_body, subs = self._substitute_in_text(
                        body_text,
                        host,
                        json_escape=is_json_body,
                    )
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

    def _redact_secrets_in_text(
        self, text: str, json_escape: bool = False
    ) -> tuple[str, int]:
        """Replace real secret values with redaction markers in response text.

        This prevents reflection attacks where an approved host echoes
        back injected secrets in its response (e.g., debug/echo endpoints).

        Returns the redacted text and the number of redactions made.
        """
        count = 0
        for _name, entry in self.config.secrets.items():
            search_values = [entry.value]
            if json_escape:
                escaped_value = json.dumps(entry.value)[1:-1]
                if escaped_value != entry.value:
                    search_values.insert(0, escaped_value)

            for search_value in search_values:
                if search_value in text:
                    text = text.replace(search_value, f"[REDACTED:{entry.name}]")
                    count += 1
                    logger.warning(
                        "audit action=redact_response secret=%s reason=reflection_prevention",
                        entry.name,
                    )
        return text, count

    def response(self, flow: http.HTTPFlow) -> None:
        """Scrub real secret values from responses to prevent reflection attacks.

        If an approved host echoes back request headers or body (e.g., a debug
        endpoint like httpbin.org/headers), the real secret injected by the
        request hook would be visible to the sandbox. This hook redacts them.
        """
        if flow.response is None:
            return

        total_redactions = 0

        # Scrub response headers
        for header_name in list(flow.response.headers.keys()):
            header_value = flow.response.headers[header_name]
            new_value, redactions = self._redact_secrets_in_text(header_value)
            if redactions > 0:
                flow.response.headers[header_name] = new_value
                total_redactions += redactions

        # Scrub response body
        if flow.response.content:
            content_encoding = flow.response.headers.get(
                "Content-Encoding", ""
            ).lower().strip()
            body_bytes = flow.response.content
            was_compressed = False

            # Decompress if needed
            encoding_tokens = [t.strip() for t in content_encoding.split(",")]
            active_encodings = [t for t in encoding_tokens if t and t != "identity"]

            for enc in reversed(active_encodings):
                decompressed = self._try_decompress(body_bytes, enc)
                if decompressed is not None:
                    body_bytes = decompressed
                    was_compressed = True
                else:
                    logger.warning(
                        "audit action=skip_response_scrub host=%s path=%s "
                        "reason=decompress_failed encoding=%s",
                        flow.request.pretty_host,
                        flow.request.path,
                        enc,
                    )
                    body_bytes = None
                    break

            if body_bytes is not None:
                try:
                    body_text = body_bytes.decode("utf-8")
                    is_json_body = self._is_json_content_type(
                        flow.response.headers.get("Content-Type", "")
                    )
                    new_body, redactions = self._redact_secrets_in_text(
                        body_text, json_escape=is_json_body
                    )
                    if redactions > 0:
                        new_body_bytes = new_body.encode("utf-8")
                        if was_compressed:
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
                                flow.response.content = recompressed
                            else:
                                flow.response.content = new_body_bytes
                                if "Content-Encoding" in flow.response.headers:
                                    del flow.response.headers["Content-Encoding"]
                        else:
                            flow.response.content = new_body_bytes

                        if "Content-Length" in flow.response.headers:
                            flow.response.headers["Content-Length"] = str(
                                len(flow.response.content)
                            )
                        total_redactions += redactions
                except UnicodeDecodeError:
                    pass

        if total_redactions > 0:
            logger.warning(
                "audit action=redact_response host=%s path=%s redactions=%d",
                flow.request.pretty_host, flow.request.path, total_redactions,
            )

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        flow.kill()
        logger.warning(
            "WebSocket blocked (not supported by secrets-proxy)",
            extra={
                "audit_action": "block_websocket",
                "host": getattr(flow.request, "pretty_host", ""),
                "path": getattr(flow.request, "path", ""),
            },
        )

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)
