# Development, building, and fuzzing

A practical guide to building and testing the repository.

## Workspace crates

| Crate | Role |
|-------|------|
| `lithium_core` | shared cryptography, key management, secret types, DB abstractions |
| `lithiumd` | local client daemon; holds the keys, exposes IPC |
| `lithiumg` | GUI client (egui); talks to `lithiumd` over IPC |
| `lithiums` | relay server; REST on Poem + PostgreSQL |
| `lithium_itest` | integration tests; shared helpers in `src/`, test binaries in `tests/` |

## Building

```bash
cargo build                        # the whole workspace
cargo build -p lithium_core        # a single crate
cargo clippy -- -D warnings
cargo fmt
```

### Version pinning and reproducibility

The dependency set is pinned in `Cargo.lock` (tracked in the 
repo), and the toolchain version in `rust-toolchain.toml` 
(`channel = "1.96.0"`). Together they are the single source of 
truth for what goes into a build: an auditor reproduces exactly 
the same set of crates and the same compiler version, without 
guessing. Updating a dependency is a deliberate change to 
`Cargo.lock` in a commit, not a side effect of a fresh `cargo 
build`. This is also a precondition for a reproducible build 
(verifying that a published binary matches the public source).

### System dependencies (Linux)

Building `lithiumd` links GTK 3 and libappindicator for the system 
tray. Without them the build stops at the `*-sys` pkg-config step. 
Install `libgtk-3-dev` and `libappindicator3-dev` (or the 
libayatana-appindicator equivalent).

## Feature flags

| Crate | Feature | Default | Effect |
|-------|---------|---------|--------|
| `lithiums` | `tpm` | **on** (`default = ["tpm"]`) | `TpmMkProvider`, master key sealed in the TPM; needs `tss-esapi` |
| `lithiums` | `fuzzing` | off | exposes `fuzz_api` to the harnesses |
| `lithium_core` | `fuzzing` | off | exposes `parse_keyfile_fuzz`, `opaque_parse_fuzz` |
| `lithiumd` | `fuzzing` | off | exposes `fuzz_api`; derives `Arbitrary` for `FuzzOp` |

Without TPM the server builds with `--no-default-features` (see 
[deploy-instructions.md](deploy-instructions.md)); at runtime you 
can also force the file provider with `LITHIUM_MK_PROVIDER=plain`. 
The `fuzzing` feature does **not** swap the RNG or the 
cryptographic primitives, it only adds public parsing entry points 
for the fuzzer.

## Tests

```bash
cargo test                                        # all
cargo test -p lithium_core                        # crate tests
cargo test -p lithium_core name                   # a single test
cargo test -p lithium_itest --test daemon_basic   # one itest binary
```

The crypto core has public-API tests in `lithium_core/tests/` 
(`crypto_tests`, `secret_tests`, `password_tests`, `store_tests`) 
and known-answer vectors (KAT) in `golden_tests.rs`, checked 
against data in `tests/testdata/` (golden vectors for KyberBox and 
ML-DSA-87 verification), they guard against wire-format regression 
and drift from the primitives.

The integration tests (`lithium_itest`) split into three suites in 
`tests/`: `server/` (the server in isolation), `daemon/` (the 
daemon against an in-process `TestServer`), and 
`daemon_server_tests/` (two daemons through a real server). The 
individual test binaries and their scope are described by the 
files in `lithium_itest/tests/`.

## Fuzzing

The fuzz targets (`cargo-fuzz`) live in `fuzz/fuzz_targets/`, the 
corpora in `fuzz/corpus/`. Each target calls a parsing entry point 
exposed by the `fuzzing` feature of the relevant crate (for 
example `parse_keyfile_fuzz`, `opaque_parse_fuzz`, the `fuzz_api` 
modules).

```bash
cargo +nightly fuzz run <target>
```

Available targets: `aead_decrypt`, `e2e_session_seq`, 
`identity_decode`, `invite_decode`, `keyfile_parse`, 
`kyberbox_decrypt`, `opaque_parse`, `pow_verify`, `secret_json`, 
`sign_verify`, `transport_decode`, `transport_micro`, 
`unpack_wire`.

The targets aim at the surfaces that parse untrusted input: wire 
format decoding (`unpack_wire`, `transport_decode`, 
`identity_decode`, `invite_decode`), decryption (`aead_decrypt`, 
`kyberbox_decrypt`), key file parsing (`keyfile_parse`), OPAQUE 
(`opaque_parse`), signature and PoW verification (`sign_verify`, 
`pow_verify`), and E2E session state sequences (`e2e_session_seq`).
