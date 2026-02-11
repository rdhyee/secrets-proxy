"""End-to-end test script: run inside secrets-proxy to verify secret injection.

This script is "oblivious" — it uses standard Python HTTP libraries and doesn't
know it's being proxied. It reads MY_API_KEY from the environment (which will be
a placeholder) and sends it in an Authorization header to httpbin.org.

If secrets-proxy is working correctly:
- The env var will contain a placeholder (SECRETS_PROXY_PLACEHOLDER_...)
- httpbin.org will receive the real secret (sk-test-secret-12345)
- Requests to non-allowed hosts will fail
"""

import json
import os
import sys
import urllib.request


def main():
    api_key = os.environ.get("MY_API_KEY", "NOT_SET")
    print(f"MY_API_KEY from env: {api_key[:50]}...")
    print(f"Is placeholder? {'SECRETS_PROXY_PLACEHOLDER' in api_key}")
    print()

    # Test 1: Send secret to approved host
    print("=== Test 1: Request to approved host (httpbin.org) ===")
    req = urllib.request.Request(
        "https://httpbin.org/headers",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            auth = data.get("headers", {}).get("Authorization", "missing")
            print(f"httpbin received Authorization: {auth}")

            if "sk-test-secret-12345" in auth:
                print("PASS: Real secret was injected by proxy")
            elif "SECRETS_PROXY_PLACEHOLDER" in auth:
                print("FAIL: Placeholder was sent (proxy didn't substitute)")
            else:
                print(f"UNEXPECTED: {auth}")
    except Exception as e:
        print(f"FAIL: Request failed: {e}")

    print()

    # Test 2: Try to reach a non-allowed host
    print("=== Test 2: Request to non-allowed host (example.com) ===")
    try:
        req2 = urllib.request.Request("https://example.com")
        urllib.request.urlopen(req2, timeout=10)
        print("FAIL: example.com was reachable (should be blocked)")
    except Exception as e:
        error_str = str(e)
        if "403" in error_str or "blocked" in error_str.lower() or "Forbidden" in error_str:
            print(f"PASS: Blocked by proxy ({type(e).__name__})")
        elif "tunnel" in error_str.lower() or "connect" in error_str.lower():
            print(f"PASS: Blocked at proxy level ({type(e).__name__}: {e})")
        else:
            print(f"BLOCKED (different error): {type(e).__name__}: {e}")

    print()

    # Test 3: Verify placeholder isn't the real secret
    print("=== Test 3: Verify sandbox isolation ===")
    if api_key == "sk-test-secret-12345":
        print("FAIL: Sandbox has the real secret!")
        return 1
    elif "SECRETS_PROXY_PLACEHOLDER" in api_key:
        print("PASS: Sandbox only has placeholder")
    else:
        print(f"UNEXPECTED env value: {api_key}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
