#!/bin/bash
# secrets-proxy on Sprites — proof of concept
#
# Usage: sudo bash sprite_secrets_proxy.sh <config_json> -- <command>
#
# Runs as root for init time (nftables, proxy), drops to 'sprite' for sandbox.

set -euo pipefail

PROXY_PORT=8080
PROXY_MARK=1
SANDBOX_USER="sandbox"
SANDBOX_UID=$(id -u "$SANDBOX_USER")
NFT_CHAIN="secrets_proxy"
MITMDUMP="/.sprite/languages/python/pyenv/versions/3.13.7/bin/mitmdump"
PYTHON3="/.sprite/languages/python/pyenv/versions/3.13.7/bin/python3"

CONFIG_JSON="$1"
shift
if [[ "$1" == "--" ]]; then shift; fi

echo "[secrets-proxy] Starting on Sprite (proxy_port=$PROXY_PORT, sandbox_uid=$SANDBOX_UID)"

# ── Generate mitmproxy CA if needed ───────────────────────────

MITM_CA="/root/.mitmproxy/mitmproxy-ca-cert.pem"
if [[ ! -f "$MITM_CA" ]]; then
    echo "[secrets-proxy] Generating mitmproxy CA..."
    $MITMDUMP --listen-port 0 -q &
    GENPID=$!
    sleep 2
    kill $GENPID 2>/dev/null || true
    wait $GENPID 2>/dev/null || true
fi

# ── Generate config + addon via secrets_proxy init ────────────

SECRETS_PROXY_CONFIG_JSON=$(echo "$CONFIG_JSON" | \
    $PYTHON3 -m secrets_proxy init --sandbox-env /tmp/sandbox_env.sh)
export SECRETS_PROXY_CONFIG_JSON

ADDON_SCRIPT=$($PYTHON3 -c "from pathlib import Path; import secrets_proxy; print(Path(secrets_proxy.__file__).resolve().parent / 'addon_entry.py')")

echo "[secrets-proxy] Addon configured (using production SecretsProxyAddon)"

# ── CA trust setup ─────────────────────────────────────────────

CA_BUNDLE=$(mktemp /tmp/secrets_proxy_ca_XXXXXX.pem)
for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
    if [[ -f "$f" ]]; then
        cat "$f" > "$CA_BUNDLE"
        echo "" >> "$CA_BUNDLE"
        # Also append to system store
        cat "$MITM_CA" >> "$f"
        break
    fi
done
cat "$MITM_CA" >> "$CA_BUNDLE"
chmod 644 "$CA_BUNDLE"

# Append to certifi if available
CERTIFI_BUNDLE=$($PYTHON3 -c "import certifi; print(certifi.where())" 2>/dev/null || true)
if [[ -n "$CERTIFI_BUNDLE" && -f "$CERTIFI_BUNDLE" ]]; then
    cat "$MITM_CA" >> "$CERTIFI_BUNDLE"
fi

echo "[secrets-proxy] CA trust configured"

# ── Start mitmproxy (transparent mode, as root for SO_MARK) ───

# Use regular mode (not transparent) because Sprite kernel lacks
# SO_ORIGINAL_DST support needed for transparent mode.
# nftables still enforces that all TCP goes through the proxy.
$MITMDUMP \
    --mode regular \
    --listen-host 127.0.0.1 \
    --listen-port "$PROXY_PORT" \
    --set connection_strategy=lazy \
    --set mark="$PROXY_MARK" \
    -s "$ADDON_SCRIPT" \
    -q &
PROXY_PID=$!

# Wait for mitmproxy to fully load (addon + listener)
echo "[secrets-proxy] Waiting for mitmproxy to be ready..."
for i in $(seq 1 15); do
    if $PYTHON3 -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect(('127.0.0.1', $PROXY_PORT))
    s.close()
    sys.exit(0)
except:
    sys.exit(1)
" 2>/dev/null; then
        echo "[secrets-proxy] Proxy ready after ${i}s"
        break
    fi
    sleep 1
done

if ! kill -0 $PROXY_PID 2>/dev/null; then
    echo "[secrets-proxy] ERROR: mitmproxy failed to start" >&2
    exit 1
fi
echo "[secrets-proxy] mitmproxy started (PID $PROXY_PID)"

# ── nftables setup (the "concrete walls") ──────────────────────
# Uses inet family to cover both IPv4 and IPv6.

nft add table inet "$NFT_CHAIN"

# NAT chain — redirect sandbox IPv4 TCP traffic
nft add chain inet "$NFT_CHAIN" nat_output '{ type nat hook output priority -1 ; }'
nft add rule inet "$NFT_CHAIN" nat_output meta mark 0x$PROXY_MARK accept
nft add rule inet "$NFT_CHAIN" nat_output meta skuid "$SANDBOX_UID" ip daddr 127.0.0.1 tcp dport "$PROXY_PORT" accept
nft add rule inet "$NFT_CHAIN" nat_output meta skuid "$SANDBOX_UID" meta nfproto ipv4 meta l4proto tcp redirect to :"$PROXY_PORT"

# Filter chain — block IPv6 TCP + all UDP except DNS
nft add chain inet "$NFT_CHAIN" filter_output '{ type filter hook output priority 0 ; }'
nft add rule inet "$NFT_CHAIN" filter_output meta skuid "$SANDBOX_UID" meta nfproto ipv6 meta l4proto tcp drop
nft add rule inet "$NFT_CHAIN" filter_output meta skuid "$SANDBOX_UID" udp dport 53 accept
nft add rule inet "$NFT_CHAIN" filter_output meta skuid "$SANDBOX_UID" meta l4proto udp drop

echo "[secrets-proxy] nftables installed:"
nft list table inet "$NFT_CHAIN"

# ── Cleanup handler ────────────────────────────────────────────

cleanup() {
    echo "[secrets-proxy] Cleaning up..."
    kill $PROXY_PID 2>/dev/null || true
    wait $PROXY_PID 2>/dev/null || true
    nft delete table inet "$NFT_CHAIN" 2>/dev/null || true
    rm -f "$CA_BUNDLE" /tmp/sandbox_env.sh
    echo "[secrets-proxy] Done"
}
trap cleanup EXIT

# ── Drop to sandbox user and run ───────────────────────────────

echo "[secrets-proxy] Running as '$SANDBOX_USER': $*"
echo "────────────────────────────────────────"

PROXY_URL="http://127.0.0.1:$PROXY_PORT"
su "$SANDBOX_USER" -c "
    source /tmp/sandbox_env.sh
    export SSL_CERT_FILE=$CA_BUNDLE
    export REQUESTS_CA_BUNDLE=$CA_BUNDLE
    export NODE_EXTRA_CA_CERTS=$CA_BUNDLE
    export CURL_CA_BUNDLE=$CA_BUNDLE
    export HTTP_PROXY=$PROXY_URL
    export HTTPS_PROXY=$PROXY_URL
    export http_proxy=$PROXY_URL
    export https_proxy=$PROXY_URL
    $*
"
EXIT_CODE=$?

echo "────────────────────────────────────────"
echo "[secrets-proxy] Exit code: $EXIT_CODE"
exit $EXIT_CODE
