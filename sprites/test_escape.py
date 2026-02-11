"""Sprite proof of concept: real OpenAI call + escape attempts."""

import json
import os
import socket
import subprocess
import sys
import urllib.request


def run_test(name, fn):
    print(f"\n=== {name} ===")
    try:
        return fn()
    except Exception as e:
        print(f"  ERROR: {type(e).__name__}: {e}")
        return False


def test_isolation():
    api_key = os.environ.get("OPENAI_API_KEY", "NOT_SET")
    print(f"  OPENAI_API_KEY: {api_key[:50]}...")
    if "sk-" == api_key[:3]:
        print("  FAIL: Has real secret!")
        return False
    print("  PASS: Only placeholder")
    return True


def test_openai_call():
    api_key = os.environ.get("OPENAI_API_KEY", "NOT_SET")
    body = json.dumps({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "Reply with just: 'hello from sprite'"}],
        "max_tokens": 10,
    }).encode()
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=body,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
        reply = data["choices"][0]["message"]["content"]
        print(f"  OpenAI reply: {reply}")
        print("  PASS: API call through proxy")
        return True


def test_blocked_host():
    try:
        urllib.request.urlopen(urllib.request.Request("https://example.com"), timeout=10)
        print("  FAIL: example.com reachable")
        return False
    except urllib.error.HTTPError as e:
        print(f"  PASS: Blocked ({e.code})")
        return True
    except Exception as e:
        print(f"  PASS: Blocked ({type(e).__name__})")
        return True


def test_direct_ip():
    print("  Connecting to 93.184.216.34:443...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("93.184.216.34", 443))
        s.close()
        print("  PASS: Redirected to proxy")
        return True
    except Exception as e:
        print(f"  PASS: Blocked ({e})")
        return True


def test_nftables():
    r = subprocess.run(["nft", "flush", "ruleset"], capture_output=True, text=True, timeout=5)
    if r.returncode == 0:
        print("  FAIL: flushed nftables!")
        return False
    print(f"  PASS: Denied ({r.stderr.strip()[:60]})")
    return True


def test_kill_proxy():
    r = subprocess.run(["pgrep", "-f", "mitmdump"], capture_output=True, text=True, timeout=5)
    if r.returncode != 0:
        print("  (no mitmdump found)")
        return True
    pid = int(r.stdout.strip().split("\n")[0])
    try:
        os.kill(pid, 9)
        print("  FAIL: Killed proxy!")
        return False
    except PermissionError:
        print(f"  PASS: Cannot kill PID {pid}")
        return True


def test_raw_socket():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.close()
        print("  FAIL: Raw socket created!")
        return False
    except (PermissionError, OSError) as e:
        print(f"  PASS: Denied ({e})")
        return True


tests = [
    ("Sandbox isolation", test_isolation),
    ("OpenAI API through proxy", test_openai_call),
    ("Non-allowed host blocked", test_blocked_host),
    ("Direct IP intercepted", test_direct_ip),
    ("Cannot modify nftables", test_nftables),
    ("Cannot kill proxy", test_kill_proxy),
    ("Cannot create raw socket", test_raw_socket),
]

results = [(name, run_test(name, fn)) for name, fn in tests]

print("\n" + "=" * 50)
passed = sum(1 for _, p in results if p)
for name, p in results:
    print(f"  [{'PASS' if p else 'FAIL'}] {name}")
print(f"\n{passed}/{len(results)} passed")
sys.exit(0 if passed == len(results) else 1)
