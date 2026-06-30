# Reproducible build

Lithium's architecture closes coercion on the **server** side (the 
operator has no plaintext). It doesn't close it by itself on the 
**client distribution** side: a coerced, signed, backdoored build 
of the client binary. A reproducible build is the answer, it lets 
anyone verify that the published `lithiumd` binary came from the 
public source. A coerced backdoor won't reproduce bit for bit, so 
it becomes detectable.

This is a prerequisite for further distribution hardening (Phase 5: 
the C2 binary transparency log, the C3 threshold release 
signature).

## What is pinned

- **Dependencies**: `Cargo.lock` in the repo; the build uses 
  `--locked`, so the exact set of crates is reproducible.
- **Compiler**: `rust-toolchain.toml` pins `1.96.0`; the container 
  base image (`rust:1.96.0-bookworm`) is the same version.
- **Build environment**: the `build/Dockerfile` container with 
  pinned system libraries (GTK3 + Ayatana app indicator for 
  linking `lithiumd`).
- **Nondeterminism**: `RUSTFLAGS=--remap-path-prefix` removes 
  absolute build paths from the binary (debug info, panic 
  strings); `SOURCE_DATE_EPOCH` fixes the timestamps.

## How to reproduce

From the repo root:

```bash
docker build -f build/Dockerfile -t lithium-repro .
docker run --rm lithium-repro            # prints the binary's sha256
```

## How to verify a published binary

1. Clone the repo at the release tag the binary belongs to.
2. Build as above and compute `sha256sum target/release/lithiumd` 
   in the container.
3. Compare with the sum published with the release. An identical 
   sum means the binary matches the source.

CI (`.github/workflows/reproducible-build.yml`) does this 
automatically: it builds `lithiumd` **twice** (the second time 
without cache) and checks that both binaries have identical 
sha256. A mismatch breaks the build.

## Known sources of nondeterminism and how they're closed

| Source | Closed by |
|--------|-----------|
| Compiler version | `rust-toolchain.toml` + base image pin |
| Dependency set | `Cargo.lock` + `--locked` |
| Absolute build paths | `--remap-path-prefix` |
| Timestamps | `SOURCE_DATE_EPOCH` |
| System libraries | pinned in `build/Dockerfile` |

## Future hardening

- **Pin the base image by digest.** Replace the 
  `rust:1.96.0-bookworm` tag with 
  `rust:1.96.0-bookworm@sha256:<digest>`, so a re-pushed tag can't 
  swap the toolchain.
- **Binary transparency log (C2)**: an append-only public log of 
  artifacts (Sigstore / CT-style), so a targeted substituted build 
  leaves a public trace.
- **Threshold / multi-person release signature (C3)**: so no one 
  alone (the maintainer included) can ship an update.
