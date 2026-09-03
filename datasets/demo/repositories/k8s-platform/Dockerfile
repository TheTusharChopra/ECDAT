FROM envoyproxy/envoy:v1.29.1
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY config/envoy-tls.yaml /etc/envoy/
