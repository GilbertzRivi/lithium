# syntax=docker/dockerfile:1

FROM rust:1.96.0-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    libtss2-dev \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY lithium_core ./lithium_core
COPY lithiums ./lithiums

WORKDIR /src/lithiums
RUN cargo build --release --bin lithiums

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    libtss2-esys-3.0.2-0 \
    libtss2-tctildr0 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --create-home --home-dir /home/lithium --shell /usr/sbin/nologin lithium \
 && mkdir -p /var/lib/lithiums \
 && chown -R lithium:lithium /var/lib/lithiums

COPY --from=builder /src/lithiums/target/release/lithiums /usr/local/bin/lithiums

USER lithium
WORKDIR /home/lithium

EXPOSE 4108
ENTRYPOINT ["/usr/local/bin/lithiums"]