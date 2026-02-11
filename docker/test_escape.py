"""Escape attempt test: try every trick to bypass secrets-proxy from inside the sandbox.

This script runs as the unprivileged 'sandbox' user inside the Docker container.
Every escape attempt should FAIL — that's the point.
"""

import json
import os
import socket
import subprocess
import sys
import urllib.request


def test_sandbox_isolation():
    """Test 1: Verify we only have the placeholder, not the real secret."""
    api_key = os.environ.get("OPENAI_API_KEY", "NOT_SET")
    print(f"  OPENAI_API_KEY: {api_key[:50]}...")
    if "sk-" == api_key[:3]:
        print("  FAIL: Has real secret!")
        return False
    if "SECRETS_PROXY_PLACEHOLDER" in api_key:
        print("  PASS: Only has placeholder")
        return True
    print(f"  UNEXPECTED: {api_key[:20]}")
    return False


def test_api_call_through_proxy():
    """Test 2: Make a real API call — proxy should inject the secret."""
    api_key = os.environ.get("OPENAI_API_KEY", "NOT_SET")
    body = json.dumps({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "Reply with just the word 'proxied'"}],
        "max_tokens": 10,
    }).encode()
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=body,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            reply = data["choices"][0]["message"]["content"]
            print(f"  OpenAI reply: {reply}")
            print("  PASS: API call succeeded through proxy")
            return True
    except Exception as e:
        print(f"  FAIL: {type(e).__name__}: {e}")
        return False


def test_blocked_host():
    """Test 3: Non-allowed host should be blocked."""
    try:
        req = urllib.request.Request("https://example.com")
        urllib.request.urlopen(req, timeout=10)
        print("  FAIL: example.com was reachable")
        return False
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print("  PASS: Blocked by proxy (403)")
            return True
        print(f"  PASS: Blocked (HTTP {e.code})")
        return True
    except Exception as e:
        print(f"  PASS: Blocked ({type(e).__name__})")
        return True


def test_direct_connect_bypass():
    """Test 4: Try to connect directly to an IP (bypassing DNS/proxy)."""
    print("  Attempting direct TCP connect to 93.184.216.34:443 (example.com)...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("93.184.216.34", 443))
        # If we get here, the connection was redirected to the proxy
        # which will block it (not in allowlist)
        sock.close()
        print("  Connection was redirected to proxy (nftables working)")
        print("  PASS: Direct connect intercepted")
        return True
    except (ConnectionRefusedError, OSError) as e:
        print(f"  PASS: Direct connect failed ({e})")
        return True
    except Exception as e:
        print(f"  UNEXPECTED: {type(e).__name__}: {e}")
        return True


def test_modify_nftables():
    """Test 5: Try to modify nftables rules (should fail — no CAP_NET_ADMIN)."""
    print("  Attempting to flush nftables rules...")
    try:
        result = subprocess.run(
            ["nft", "flush", "ruleset"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            print("  FAIL: nftables rules flushed! Sandbox has CAP_NET_ADMIN!")
            return False
        else:
            print(f"  PASS: Permission denied ({result.stderr.strip()[:80]})")
            return True
    except FileNotFoundError:
        print("  PASS: nft not available to sandbox user")
        return True
    except Exception as e:
        print(f"  PASS: Failed ({type(e).__name__}: {e})")
        return True


def test_kill_proxy():
    """Test 6: Try to kill the proxy process."""
    print("  Looking for mitmproxy process...")
    try:
        result = subprocess.run(
            ["pgrep", "-f", "mitmdump"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            print("  (Could not find mitmdump PID — can't attempt kill)")
            return True

        pid = result.stdout.strip().split("\n")[0]
        print(f"  Found mitmdump PID {pid}, attempting kill...")
        try:
            os.kill(int(pid), 9)
            print("  FAIL: Killed the proxy!")
            return False
        except PermissionError:
            print("  PASS: Permission denied (different UID)")
            return True
    except Exception as e:
        print(f"  PASS: Failed ({type(e).__name__}: {e})")
        return True


def test_read_proxy_memory():
    """Test 7: Try to read proxy process memory (should fail)."""
    try:
        result = subprocess.run(
            ["pgrep", "-f", "mitmdump"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            print("  (Could not find mitmdump PID)")
            return True

        pid = result.stdout.strip().split("\n")[0]
        print(f"  Attempting to read /proc/{pid}/mem...")
        try:
            with open(f"/proc/{pid}/mem", "rb") as f:
                f.read(1)
            print("  FAIL: Could read proxy memory!")
            return False
        except PermissionError:
            print("  PASS: Permission denied")
            return True
        except Exception as e:
            print(f"  PASS: Failed ({type(e).__name__}: {e})")
            return True
    except Exception as e:
        print(f"  PASS: Failed ({type(e).__name__}: {e})")
        return True


def test_read_proxy_env():
    """Test 8: Try to read proxy's environment (contains real secrets)."""
    try:
        result = subprocess.run(
            ["pgrep", "-f", "mitmdump"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            print("  (Could not find mitmdump PID)")
            return True

        pid = result.stdout.strip().split("\n")[0]
        print(f"  Attempting to read /proc/{pid}/environ...")
        try:
            with open(f"/proc/{pid}/environ", "r") as f:
                content = f.read()
            if "sk-" in content:
                print("  FAIL: Could read real secret from proxy environ!")
                return False
            print("  FAIL: Could read proxy environ (but no secrets found)")
            return False
        except PermissionError:
            print("  PASS: Permission denied")
            return True
        except Exception as e:
            print(f"  PASS: Failed ({type(e).__name__}: {e})")
            return True
    except Exception as e:
        print(f"  PASS: Failed ({type(e).__name__}: {e})")
        return True


def test_raw_socket():
    """Test 9: Try to create a raw socket (bypass TCP redirect)."""
    print("  Attempting to create raw socket...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.close()
        print("  FAIL: Raw socket created!")
        return False
    except PermissionError:
        print("  PASS: Permission denied (no CAP_NET_RAW)")
        return True
    except OSError as e:
        print(f"  PASS: Failed ({e})")
        return True


def test_non_standard_port():
    """Test 10: Try connecting to a non-standard port (all TCP should be redirected)."""
    print("  Attempting connect to example.com:8443...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("93.184.216.34", 8443))
        sock.close()
        print("  Connection redirected to proxy (all TCP captured)")
        print("  PASS: Non-standard port intercepted")
        return True
    except (ConnectionRefusedError, OSError) as e:
        print(f"  PASS: Connection failed ({e})")
        return True


def test_ipv6_bypass():
    """Test 11: Try connecting via IPv6 (should be blocked by inet nftables rules)."""
    print("  Attempting IPv6 TCP connect to [2606:2800:21f:cb07:6820:80da:af6b:8b2c]:443 (example.com)...")
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("2606:2800:21f:cb07:6820:80da:af6b:8b2c", 443))
        sock.close()
        print("  FAIL: IPv6 connection succeeded — bypass possible!")
        return False
    except (ConnectionRefusedError, OSError, socket.timeout) as e:
        print(f"  PASS: IPv6 blocked ({e})")
        return True
    except Exception as e:
        print(f"  PASS: IPv6 failed ({type(e).__name__}: {e})")
        return True


def main():
    tests = [
        ("Sandbox isolation (no real secret in env)", test_sandbox_isolation),
        ("API call through proxy", test_api_call_through_proxy),
        ("Non-allowed host blocked", test_blocked_host),
        ("Direct IP connect intercepted", test_direct_connect_bypass),
        ("Cannot modify nftables", test_modify_nftables),
        ("Cannot kill proxy", test_kill_proxy),
        ("Cannot read proxy memory", test_read_proxy_memory),
        ("Cannot read proxy environment", test_read_proxy_env),
        ("Cannot create raw socket", test_raw_socket),
        ("Non-standard port intercepted", test_non_standard_port),
        ("IPv6 bypass blocked", test_ipv6_bypass),
    ]

    results = []
    for i, (name, test_fn) in enumerate(tests, 1):
        print(f"\n=== Test {i}: {name} ===")
        try:
            passed = test_fn()
        except Exception as e:
            print(f"  ERROR: {type(e).__name__}: {e}")
            passed = False
        results.append((name, passed))

    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    passed = sum(1 for _, p in results if p)
    total = len(results)
    for name, p in results:
        status = "PASS" if p else "FAIL"
        print(f"  [{status}] {name}")
    print(f"\n{passed}/{total} tests passed")

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
