# ABOUTME: Dockerfile for honeyd passthrough proxy test
# ABOUTME: Tests that honeyd correctly proxies traffic to real local services

FROM debian:bookworm-slim

# Install build and runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    libevent-dev \
    libdumbnet-dev \
    libpcap-dev \
    libpcre3-dev \
    libreadline-dev \
    zlib1g-dev \
    flex \
    bison \
    python3-dev \
    python3 \
    iproute2 \
    iputils-ping \
    procps \
    netcat-openbsd \
    nmap \
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
RUN chmod +x tests/passthrough/test_passthrough.sh

# Run the passthrough test
# Requires: --privileged (or --cap-add=NET_ADMIN --cap-add=NET_RAW)
CMD ["/src/honeyd/tests/passthrough/test_passthrough.sh"]
