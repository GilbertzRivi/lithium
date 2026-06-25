# syntax=docker/dockerfile:1
#
# Reproducible build of the Lithium client daemon (lithiumd) — the client TCB.
# Build context is the repository root:
#
#   docker build -f build/Dockerfile -t lithium-repro .
#   docker run --rm lithium-repro            # prints sha256 of the binary
#
# Pin the base image by digest in production (replace the tag with
# rust:1.96.0-bookworm@sha256:<digest>) so a re-pushed tag cannot swap the toolchain.
FROM rust:1.96.0-bookworm

# System libraries required to link lithiumd: GTK3 + Ayatana app indicator for the tray.
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libgtk-3-dev \
    libayatana-appindicator3-dev \
    libssl-dev \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Determinism: fixed timestamp and path remapping, so absolute build paths do not leak
# into the binary (debug info, panic strings). The compiler version is pinned by the
# committed rust-toolchain.toml, which the FROM tag above matches.
ENV SOURCE_DATE_EPOCH=1 \
    CARGO_HOME=/usr/local/cargo \
    RUSTFLAGS="--remap-path-prefix=/build=. --remap-path-prefix=/usr/local/cargo=cargo"

WORKDIR /build
COPY . .

# --locked pins the exact dependency set from the committed Cargo.lock.
RUN cargo build --release --locked --bin lithiumd

CMD ["sha256sum", "target/release/lithiumd"]
