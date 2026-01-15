# Soqucoin Node Docker Image
# Multi-architecture build: linux/amd64, linux/arm64
#
# Usage:
#   docker run -d -p 44556:44556 -v soqucoin-data:/root/.soqucoin soqucoin/soqucoin
#
# Build locally:
#   docker build -t soqucoin/soqucoin .

FROM ubuntu:22.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential libtool autotools-dev automake \
    pkg-config bsdmainutils python3 libssl-dev \
    libevent-dev libboost-all-dev libminiupnpc-dev \
    libzmq3-dev libsqlite3-dev libdb++-dev git \
    && rm -rf /var/lib/apt/lists/*

# Clone and build
WORKDIR /build
COPY . .
RUN ./autogen.sh \
    && ./configure --without-gui --disable-tests --disable-bench \
    && make -j$(nproc)

# Runtime image (slim)
FROM ubuntu:22.04

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    libssl3 libevent-2.1-7 libboost-system1.74.0 \
    libboost-filesystem1.74.0 libboost-thread1.74.0 \
    libminiupnpc17 libzmq5 libsqlite3-0 libdb5.3++ \
    && rm -rf /var/lib/apt/lists/*

# Copy binaries from builder
COPY --from=builder /build/src/soqucoind /usr/local/bin/
COPY --from=builder /build/src/soqucoin-cli /usr/local/bin/

# Create data directory
RUN mkdir -p /root/.soqucoin

# Expose P2P and RPC ports
EXPOSE 44556 44555

# Data volume
VOLUME ["/root/.soqucoin"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s \
    CMD soqucoin-cli getblockchaininfo || exit 1

# Default command
ENTRYPOINT ["soqucoind"]
CMD ["-printtoconsole", "-server=1"]
