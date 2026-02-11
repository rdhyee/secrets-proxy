FROM python:3.13-slim

# Install system deps for nftables
RUN apt-get update && apt-get install -y --no-install-recommends \
    nftables \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install mitmproxy + our package
RUN pip install --no-cache-dir mitmproxy

# Copy secrets-proxy source
COPY . /opt/secrets-proxy
RUN pip install --no-cache-dir /opt/secrets-proxy

# Create unprivileged sandbox user
RUN useradd -m -s /bin/bash sandbox

# Generate mitmproxy CA cert (one-time)
RUN mitmdump --listen-port 0 -q &  GENPID=$!; sleep 2; kill $GENPID 2>/dev/null; wait $GENPID 2>/dev/null || true

# Copy entrypoint
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
