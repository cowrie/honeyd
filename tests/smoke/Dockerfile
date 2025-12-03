# ABOUTME: Dockerfile for honeyd smoke test environment
# ABOUTME: Builds honeyd and runs basic integration test using network namespaces

FROM debian:bookworm-slim

# Install build and runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    libevent-dev \
    libdumbnet-dev \
    libpcap-dev \
    libreadline-dev \
    zlib1g-dev \
    flex \
    bison \
    iproute2 \
    iputils-ping \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Copy source
WORKDIR /src/honeyd
COPY . .

# Build and install honeyd
RUN mkdir -p build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo && \
    cmake --build . -j$(nproc) && \
    cmake --install .

# Make test script executable
RUN chmod +x tests/smoke/smoke_test.sh

# Run the smoke test
# Requires: --cap-add=NET_ADMIN --cap-add=NET_RAW
CMD ["/src/honeyd/tests/smoke/smoke_test.sh"]
