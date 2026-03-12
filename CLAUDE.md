# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build all crates
cargo build

# Build specific crate
cargo build -p lithium_core
cargo build -p lithiumd
cargo build -p lithiumg
cargo build -p lithiums

# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p lithium_core

# Run a single test
cargo test -p lithium_core test_name

# Lint
cargo clippy -- -D warnings

# Format
cargo fmt
```

## Architecture

Lithium is a post-quantum end-to-end encrypted messenger. The server is explicitly untrusted — it only relays ciphertexts and never sees plaintext.

### Workspace Crates

- **`lithium_core`** — shared crypto, key management, database abstractions, secret types
- **`lithiumd`** — local daemon on the client machine; manages keys, exposes IPC endpoint
- **`lithiumg`** — egui GUI client; communicates with `lithiumd` via IPC
- **`lithiums`** — relay server; PostgreSQL-backed REST API (Poem framework)

### Data Flow

```
lithiumg (GUI)
  ↕ JSON over Unix socket / Windows named pipe
lithiumd (daemon)
  - Stores keys and messages locally (SQLite via SeaORM)
  - Performs all cryptographic operations
  ↕ HTTPS REST
lithiums (server)
  - PostgreSQL for user records and ephemeral message relay
  - Never decrypts anything
```

### Cryptography

All hybrid: classical + post-quantum for algorithm agility.

- **Encryption**: X25519 + ML-KEM-1024 (Kyberbox), AEAD = AES-256-GCM-SIV
- **Signatures**: Ed25519 + ML-DSA-87 (dual-signed)
- **KDF**: HKDF-SHA256; password hashing: Argon2
- **Secret types**: `Byte32`, `SecretBytes`, `SecretString`, `MasterKey32` — all `zeroize` on drop

Key lifecycle is managed by `KeyManager<MkProvider>` in `lithium_core/src/keys/manager.rs`. The `MkProvider` trait is pluggable (currently `PlainFileMkProvider` for file-based storage). Keys rotate every hour via a background `MkRotator` task (spawned in both `lithiumd` and `lithiums`).

### IPC (lithiumd)

The daemon listens on a Unix socket (Linux) or named pipe (Windows). Authentication uses a session token issued on `UnlockKeystore`, optionally bound to UID/PID on Linux.

Command flow: `handle_conn()` → `authorize_request()` → `dispatch()` → handler in `lithiumd/src/commands/`.

IPC command enum is in `lithiumd/src/ipc/types.rs`. Commands that require auth are gated in `ipc/mod.rs`.

### Server Transport (lithiums)

Two crypto modes defined in `lithiums/src/transport/mod.rs`:

- **Shake**: single-pass handshake; client sends ephemeral keys in headers; server responds with session keys
- **Session**: authenticated; JWT validated, dual-signed, Kyberbox-encrypted body

Middleware chain: `CryptoMiddleware` (decryption, JWT) → `GuardMiddleware` (rate limiting). Rate limits: login 5 failures → exponential backoff; register 3 failures/hour.

### Database

- `lithiumd` → SQLite via SeaORM
- `lithiums` → PostgreSQL via SeaORM (connection from env vars)

### Trust Model

The server is treated as a potentially hostile relay. All keys are derived and stored on the client. Loss of key material is preferred over recovery vectors. One-time message fetch (fetch deletes from server). No automatic sync — manual pull model.