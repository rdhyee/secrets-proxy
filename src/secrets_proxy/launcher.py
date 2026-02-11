"""Process launcher: starts mitmproxy, sets up environment, runs sandboxed command.

Network enforcement (Linux/nftables):
    All TCP egress from the sandbox UID is redirected to the proxy port via a
    dedicated nftables chain ("secrets_proxy"). The proxy's own outbound packets
    are exempted using packet marks (SO_MARK / mitmproxy ``--set mark=0x1``), so
    they reach upstream hosts directly without looping back.

    UDP egress is blocked for the sandbox UID, except DNS (UDP port 53) which is
    allowed so name resolution works. HTTP/3 (QUIC over UDP) is **not supported**
    -- clients that attempt QUIC will fall back to HTTP/2 or HTTP/1.1 over TCP.

macOS / fallback:
    On macOS (or when nftables is unavailable), the launcher sets HTTP_PROXY /
    HTTPS_PROXY environment variables. This is a weaker enforcement suitable for
    local development only.
"""

from __future__ import annotations

import json as _json
import logging
import os
import platform
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

from .ca_trust import setup_ca_trust, MITMPROXY_CA_CERT, MITMPROXY_CA_DIR
from .config import ProxyConfig

# Reusable path to the addon entry point module (loaded by mitmdump -s).
_ADDON_ENTRY_PATH = str(Path(__file__).parent / "addon_entry.py")

logger = logging.getLogger("secrets-proxy")

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8080

# Packet mark used by mitmproxy to tag its own outbound connections.
# nftables rules skip packets carrying this mark so the proxy can reach
# upstream hosts without being redirected back to itself.
_PROXY_MARK = 0x1

# Shared nftables table for secrets-proxy chains.
_NFT_TABLE = "secrets_proxy"
_NFT_NAT_CHAIN_PREFIX = "secrets_proxy"
_NFT_FILTER_CHAIN_PREFIX = "secrets_proxy_filter"

# Names of chains created by this process instance.
_NFT_NAT_CHAIN_NAME: str | None = None
_NFT_FILTER_CHAIN_NAME: str | None = None


def _nft_chain_names_for_pid(pid: int) -> tuple[str, str]:
    """Return per-process nftables chain names."""
    return (
        f"{_NFT_NAT_CHAIN_PREFIX}_{pid}",
        f"{_NFT_FILTER_CHAIN_PREFIX}_{pid}",
    )


def _check_mitmdump() -> None:
    """Verify that mitmdump is available on PATH.

    Raises RuntimeError with a clear message if not found.
    """
    if shutil.which("mitmdump") is None:
        raise RuntimeError(
            "mitmdump not found on PATH. Install mitmproxy: "
            "pip install mitmproxy  or  brew install mitmproxy"
        )


def _check_config_permissions(config_path: str | Path) -> None:
    """Warn if the secrets config file has overly permissive permissions."""
    try:
        st = os.stat(config_path)
        mode = st.st_mode
        if mode & (stat.S_IRGRP | stat.S_IROTH):
            logger.warning(
                "Config file %s is readable by group/others (mode %o). "
                "Consider: chmod 600 %s",
                config_path, stat.S_IMODE(mode), config_path,
            )
    except OSError:
        pass


def _generate_mitmproxy_ca_if_needed() -> None:
    """Run mitmproxy briefly to generate CA certs if they don't exist."""
    if MITMPROXY_CA_CERT.exists():
        return

    _check_mitmdump()

    logger.info("Generating mitmproxy CA certificate (first run)...")
    MITMPROXY_CA_DIR.mkdir(parents=True, exist_ok=True)

    proc = subprocess.Popen(
        ["mitmdump", "--listen-port", "0", "-q"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(2)
    proc.terminate()
    proc.wait(timeout=5)

    if MITMPROXY_CA_CERT.exists():
        logger.info("CA certificate generated at %s", MITMPROXY_CA_CERT)
    else:
        raise RuntimeError("Failed to generate mitmproxy CA certificate")


def _setup_nftables(sandbox_uid: int, proxy_port: int) -> bool:
    """Set up nftables to redirect **all** sandbox TCP through the proxy.

    Creates dedicated chains in the ``inet`` family (covers both IPv4 and
    IPv6) so that teardown only removes our rules (not anyone else's).

    The rules implement a default-deny egress policy for the sandbox UID:

    1. Skip packets that carry ``_PROXY_MARK`` (these are mitmproxy's own
       upstream connections -- without this exemption the proxy's traffic would
       loop back to itself).
    2. Allow traffic to the proxy listener only (127.0.0.1:proxy_port).
    3. Redirect **all** remaining IPv4 TCP from ``sandbox_uid`` to ``proxy_port``.
    4. Drop **all** IPv6 TCP from ``sandbox_uid`` (proxy listens on IPv4 only).
    5. Drop **all** UDP from ``sandbox_uid`` except DNS (port 53).

    Returns True if nftables was set up, False if not available.
    Only works on Linux with root/CAP_NET_ADMIN.

    Note: HTTP/3 (QUIC over UDP) is intentionally blocked.  Well-behaved HTTP
    clients will fall back to TCP-based HTTP/2 or HTTP/1.1 automatically.
    """
    if platform.system() != "Linux":
        logger.info("Not on Linux, skipping nftables (using proxy env vars instead)")
        return False

    try:
        global _NFT_NAT_CHAIN_NAME, _NFT_FILTER_CHAIN_NAME
        pid = os.getpid()
        nat_chain, filter_chain = _nft_chain_names_for_pid(pid)
        _NFT_NAT_CHAIN_NAME = nat_chain
        _NFT_FILTER_CHAIN_NAME = filter_chain

        # Create shared table once; multiple secrets-proxy instances can add
        # distinct chains in the same table safely.
        table_exists = subprocess.run(
            ["nft", "list", "table", "inet", _NFT_TABLE],
            capture_output=True,
        )
        if table_exists.returncode != 0:
            subprocess.run(
                ["nft", "add", "table", "inet", _NFT_TABLE],
                check=True,
                capture_output=True,
            )

        cmds = [
            # --- NAT chain (IPv4 redirect) ---
            # Note: redirect target in inet NAT chains applies to IPv4 traffic.
            # IPv6 TCP is handled by the filter chain (dropped).
            ["nft", "add", "chain", "inet", _NFT_TABLE, nat_chain,
             "{ type nat hook output priority -1 ; }"],

            # 1. Skip marked packets (proxy's own upstream traffic)
            ["nft", "add", "rule", "inet", _NFT_TABLE, nat_chain,
             "meta", "mark", hex(_PROXY_MARK), "accept"],

            # 2. Allow sandbox -> proxy listener ONLY (not all of localhost)
            ["nft", "add", "rule", "inet", _NFT_TABLE, nat_chain,
             "meta", "skuid", str(sandbox_uid),
             "ip", "daddr", "127.0.0.1", "tcp", "dport", str(proxy_port), "accept"],

            # 3. Redirect all remaining IPv4 TCP from sandbox UID to proxy port
            ["nft", "add", "rule", "inet", _NFT_TABLE, nat_chain,
             "meta", "skuid", str(sandbox_uid),
             "meta", "nfproto", "ipv4",
             "meta", "l4proto", "tcp",
             "redirect", "to", f":{proxy_port}"],

            # --- Filter chain (blocks IPv6 TCP + all UDP except DNS) ---
            ["nft", "add", "chain", "inet", _NFT_TABLE, filter_chain,
             "{ type filter hook output priority 0 ; }"],

            # 4. Drop ALL IPv6 TCP from sandbox (proxy only listens on IPv4)
            ["nft", "add", "rule", "inet", _NFT_TABLE, filter_chain,
             "meta", "skuid", str(sandbox_uid),
             "meta", "nfproto", "ipv6",
             "meta", "l4proto", "tcp",
             "drop"],

            # 5a. Allow DNS (UDP port 53) so name resolution works
            ["nft", "add", "rule", "inet", _NFT_TABLE, filter_chain,
             "meta", "skuid", str(sandbox_uid),
             "udp", "dport", "53", "accept"],

            # 5b. Drop all other UDP from sandbox UID (QUIC bypass prevention)
            ["nft", "add", "rule", "inet", _NFT_TABLE, filter_chain,
             "meta", "skuid", str(sandbox_uid),
             "meta", "l4proto", "udp",
             "drop"],
        ]
        for cmd in cmds:
            subprocess.run(cmd, check=True, capture_output=True)
        logger.info(
            "nftables rules set for UID %d -> port %d (mark 0x%x exempt, "
            "IPv6 TCP blocked, UDP blocked except DNS)",
            sandbox_uid, proxy_port, _PROXY_MARK,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logger.warning("nftables setup failed: %s. Falling back to proxy env vars.", e)
        return False


def _can_set_so_mark() -> bool:
    """Check whether SO_MARK can be set (requires CAP_NET_ADMIN on Linux)."""
    if platform.system() != "Linux":
        return False
    if not hasattr(socket, "SO_MARK"):
        logger.error("SO_MARK is unavailable. Cannot use nftables enforcement.")
        return False

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, _PROXY_MARK)
        return True
    except PermissionError:
        logger.error("CAP_NET_ADMIN required for SO_MARK. Cannot use nftables enforcement.")
        return False
    except OSError as exc:
        logger.error("SO_MARK check failed: %s. Cannot use nftables enforcement.", exc)
        return False
    finally:
        s.close()


def _select_network_enforcement(sandbox_uid: int, proxy_port: int) -> bool:
    """Enable nftables only when SO_MARK capability checks pass."""
    if platform.system() != "Linux":
        logger.info("Network enforcement mode: env-var-only (non-Linux platform)")
        return False

    if not _can_set_so_mark():
        logger.info("Network enforcement mode: env-var-only (SO_MARK unavailable)")
        return False

    used_nftables = _setup_nftables(sandbox_uid, proxy_port)
    if used_nftables:
        logger.info("Network enforcement mode: nftables active")
    else:
        logger.info("Network enforcement mode: env-var-only (nftables setup failed)")
    return used_nftables


def _teardown_nftables(sandbox_uid: int, proxy_port: int) -> None:
    """Remove only the nftables table created by secrets-proxy. Best-effort.

    Flushes and deletes the per-process chains without touching chains created
    by other processes.
    """
    if platform.system() != "Linux":
        return
    del sandbox_uid, proxy_port  # kept for backward-compatible call shape

    nat_chain = _NFT_NAT_CHAIN_NAME
    filter_chain = _NFT_FILTER_CHAIN_NAME
    if nat_chain is None or filter_chain is None:
        nat_chain, filter_chain = _nft_chain_names_for_pid(os.getpid())

    for chain in (nat_chain, filter_chain):
        try:
            subprocess.run(
                ["nft", "flush", "chain", "inet", _NFT_TABLE, chain],
                capture_output=True,
            )
            subprocess.run(
                ["nft", "delete", "chain", "inet", _NFT_TABLE, chain],
                capture_output=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
    logger.info("nftables rules cleaned up (chains: %s, %s)", nat_chain, filter_chain)


def cleanup_nftables_chains() -> list[str]:
    """Remove stale secrets-proxy nftables chains across tables/families."""
    if platform.system() != "Linux":
        return []

    try:
        result = subprocess.run(
            ["nft", "-j", "list", "ruleset"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []

    try:
        ruleset = _json.loads(result.stdout or "{}")
    except _json.JSONDecodeError:
        return []

    matches: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for entry in ruleset.get("nftables", []):
        chain = entry.get("chain")
        if not isinstance(chain, dict):
            continue

        name = chain.get("name")
        family = chain.get("family")
        table = chain.get("table")
        if not isinstance(name, str) or not isinstance(family, str) or not isinstance(table, str):
            continue
        if not name.startswith("secrets_proxy_"):
            continue

        key = (family, table, name)
        if key not in seen:
            seen.add(key)
            matches.append(key)

    cleaned: list[str] = []
    for family, table, name in matches:
        subprocess.run(
            ["nft", "flush", "chain", family, table, name],
            capture_output=True,
        )
        subprocess.run(
            ["nft", "delete", "chain", family, table, name],
            capture_output=True,
        )
        cleaned.append(f"{family} {table} {name}")

    return cleaned


def start_proxy(
    config: ProxyConfig,
    addon_path: str,
    *,
    use_transparent: bool = False,
    addon_env: dict[str, str] | None = None,
) -> subprocess.Popen:
    """Start mitmproxy with the secrets addon.

    Args:
        config: Proxy configuration.
        addon_path: Path to the auto-generated mitmproxy addon script.
        use_transparent: If True, use ``--mode transparent`` (required when
            nftables redirects raw TCP to the proxy port). If False, use
            ``--mode regular`` (for macOS / env-var proxy mode).

    Uses subprocess.DEVNULL for stdout/stderr to avoid pipe deadlock.
    """
    _check_mitmdump()

    mode = "transparent" if use_transparent else "regular"
    port = config.proxy_port or PROXY_PORT

    cmd = [
        "mitmdump",
        "--mode", mode,
        "--listen-host", PROXY_HOST,
        "--listen-port", str(port),
        "--set", "connection_strategy=lazy",
        "-s", addon_path,
        "-q",
    ]

    # When using transparent mode on Linux, tell mitmproxy to mark its own
    # outbound packets so nftables can exempt them from redirection.
    if use_transparent:
        cmd.extend(["--set", f"mark={_PROXY_MARK}"])

    logger.info("Starting mitmproxy (%s mode): %s", mode, " ".join(cmd))
    proxy_env = os.environ.copy()
    if addon_env:
        proxy_env.update(addon_env)

    proc = subprocess.Popen(
        cmd,
        env=proxy_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    time.sleep(1)
    if proc.poll() is not None:
        raise RuntimeError(
            f"mitmproxy exited immediately (code {proc.returncode}). "
            "Check that the port is available and the addon script is valid."
        )

    logger.info("mitmproxy started (PID %d) on %s:%d", proc.pid, PROXY_HOST, port)
    return proc


def run(
    config: ProxyConfig,
    command: list[str],
    *,
    ca_bundle_path: Path | None = None,
) -> int:
    """Run a command with secrets-proxy wrapping.

    1. Check dependencies (mitmdump on PATH)
    2. Generate mitmproxy CA if needed
    3. Create combined CA bundle (temp file, no root needed)
    4. Write mitmproxy addon script (secrets via env var, not on disk)
    5. Set up nftables (Linux) or prepare proxy env vars (macOS)
    6. Start mitmproxy (transparent if nftables, regular otherwise)
    7. Run the sandboxed command with placeholder env vars
    8. Clean up (nftables, proxy, temp files)

    Returns the sandboxed command's exit code.
    """
    print("If this process is killed with SIGKILL, run: secrets-proxy cleanup")

    port = config.proxy_port or PROXY_PORT

    # Step 1: Check dependencies
    _check_mitmdump()

    # Step 2: Ensure CA exists
    _generate_mitmproxy_ca_if_needed()

    # Step 3: Create combined CA bundle (temp file — no root needed)
    bundle_path, ca_env = setup_ca_trust(ca_bundle_path)
    logger.info("CA bundle created at %s", bundle_path)

    # Step 4: Addon entry point (secrets passed via env var, not in file)
    addon_script = _ADDON_ENTRY_PATH
    addon_env = {"SECRETS_PROXY_CONFIG_JSON": config.to_env_json()}

    # Step 5: Try nftables (Linux strong mode) BEFORE starting proxy
    # so we know which mitmproxy mode to use.
    uid = os.getuid()
    used_nftables = _select_network_enforcement(uid, port)

    # Step 6: Start mitmproxy — transparent mode when nftables is active
    proxy_proc = start_proxy(
        config, addon_script, use_transparent=used_nftables, addon_env=addon_env,
    )

    # Sandbox process reference for health monitor
    sandbox_proc: subprocess.Popen | None = None
    sandbox_ready = threading.Event()
    shutting_down = threading.Event()

    def _proxy_health_monitor() -> None:
        """Background thread: kill sandbox if proxy dies unexpectedly."""
        sandbox_ready.wait()
        while not shutting_down.is_set():
            if shutting_down.wait(timeout=1):
                return
            if proxy_proc.poll() is not None:
                if shutting_down.is_set():
                    return
                logger.error(
                    "mitmproxy died (exit %d) — killing sandbox for fail-closed safety",
                    proxy_proc.returncode,
                )
                if sandbox_proc and sandbox_proc.poll() is None:
                    sandbox_proc.kill()
                return

    def _cleanup() -> None:
        """Best-effort cleanup of all resources."""
        # Prevent monitor from killing sandbox during intentional shutdown.
        shutting_down.set()
        sandbox_ready.set()
        proxy_proc.terminate()
        try:
            proxy_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy_proc.kill()
            proxy_proc.wait()
        logger.info("mitmproxy stopped")

        if used_nftables:
            _teardown_nftables(uid, port)

        try:
            os.unlink(str(bundle_path))
        except OSError:
            pass

    def _signal_handler(signum: int, frame: object) -> None:
        logger.info("Received signal %d, cleaning up...", signum)
        _cleanup()
        sys.exit(128 + signum)

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    try:
        # Step 7: Build environment for sandboxed process
        sandbox_env = os.environ.copy()

        # Placeholder env vars (secrets)
        sandbox_env.update(config.get_env_vars())

        # CA trust env vars
        sandbox_env.update(ca_env)

        # Proxy env vars (harmless when nftables is active,
        # primary enforcement mechanism on macOS)
        proxy_url = f"http://{PROXY_HOST}:{port}"
        sandbox_env["HTTP_PROXY"] = proxy_url
        sandbox_env["HTTPS_PROXY"] = proxy_url
        sandbox_env["http_proxy"] = proxy_url
        sandbox_env["https_proxy"] = proxy_url

        # Start health monitor
        monitor = threading.Thread(target=_proxy_health_monitor, daemon=True)
        monitor.start()

        # Step 8: Run the sandboxed command
        logger.info("Running: %s", " ".join(command))
        try:
            sandbox_proc = subprocess.Popen(command, env=sandbox_env)
            sandbox_ready.set()
            sandbox_proc.wait()
            return sandbox_proc.returncode
        finally:
            if sandbox_proc and sandbox_proc.poll() is None:
                sandbox_proc.terminate()
                try:
                    sandbox_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    sandbox_proc.kill()

    finally:
        _cleanup()


def _get_addon_entry_path() -> str:
    """Return the path to the production addon_entry.py module."""
    return _ADDON_ENTRY_PATH
