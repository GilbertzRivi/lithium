# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Commands

```bash
cargo build                        # all crates
cargo build -p lithium_core        # specific crate
cargo test                         # all tests
cargo test -p lithium_core         # crate tests
cargo test -p lithium_core name    # single test
cargo test -p lithium_itest --test daemon_basic   # single itest binary
cargo clippy -- -D warnings
cargo fmt
```

## Architecture

Lithium is a post-quantum end-to-end encrypted messenger. The server is explicitly untrusted — it only relays ciphertexts and never sees plaintext.

### Workspace Crates

- **`lithium_core`** — shared crypto, key management, database abstractions, secret types
- **`lithiumd`** — local daemon; manages keys, exposes IPC endpoint over Unix socket
- **`lithiumg`** — egui GUI client; communicates with `lithiumd` via IPC
- **`lithiums`** — relay server; PostgreSQL-backed REST API (Poem framework)
- **`lithium_itest`** — integration tests; not a binary, only `[[test]]` entries in Cargo.toml

### Data Flow

```
lithiumg (GUI)
  IPC: JSON lines over Unix socket (Linux) / named pipe (Windows)
lithiumd (daemon)
  SQLite via SeaORM — local keys and messages
  All crypto runs here
  HTTPS REST
lithiums (server)
  PostgreSQL — user records and ephemeral relay
  Never sees plaintext
```

### Cryptography

All schemes are hybrid classical + post-quantum.

- **Encryption**: X25519 + ML-KEM-1024 (Kyberbox), AEAD = AES-256-GCM-SIV
- **Signatures**: Ed25519 + ML-DSA-87 (dual-signed)
- **KDF**: HKDF-SHA256; passwords: Argon2
- **Secret types**: `Byte32`, `SecretBytes`, `SecretString`, `MasterKey32` — all `zeroize` on drop

Key lifecycle: `KeyManager<MkProvider>` in `lithium_core/src/keys/manager.rs`. `MkProvider` is pluggable (`PlainFileMkProvider` for file-based storage). Keys rotate hourly via `MkRotator` (spawned in `lithiumd` and `lithiums`).

### IPC (lithiumd)

Command flow: `handle_conn()` → `authorize_request()` → `dispatch()` → handler in `lithiumd/src/commands/`.

IPC command enum: `lithiumd/src/ipc/types.rs`. Auth-gating: `ipc/mod.rs`.

Auth state machine:
- No active session (keystore locked): any protected command returns `ipc_auth_required`
- Session active, wrong token: returns `ipc_auth_failed`
- Token issued on `unlock_keystore`; invalidated on `lock_keystore` or `wipe_local`
- On Linux: token optionally bound to UID+PID of the issuing connection

`LITHIUMD_IPC_MAX_CONNECTIONS` controls the semaphore. When exhausted the daemon closes the stream; client sees EOF.

Account credentials (`handler` + `password`) are **in-memory only** — never written to disk. After each restart + `unlock_keystore`, the client must call `set_credentials` again before `unlock_storage`. Tests that restart and need storage must account for this.

### Server Transport (lithiums)

`lithiums` binds plain HTTP. TLS is terminated by a reverse proxy (nginx, Caddy, etc.) in front of it. Do not add TLS to `lithiums` itself.

Two crypto modes in `lithiums/src/transport/mod.rs`:

- **Shake**: single-pass handshake; ephemeral keys in headers
- **Session**: authenticated; JWT validated, dual-signed, Kyberbox-encrypted body

Middleware: `CryptoMiddleware` → `GuardMiddleware` (rate limiting). Rate limits: login 5 failures → exponential backoff; register 3 failures/hour.

### Database

- `lithiumd` → SQLite via SeaORM
- `lithiums` → PostgreSQL via SeaORM (connection from env vars)

### Trust Model

Server is a hostile relay. All keys on client. Loss of key material preferred over recovery vectors. One-time fetch (fetch deletes from server). Manual pull model, no auto-sync.

## Integration Tests (lithium_itest)

Two test suites: `tests/server/` and `tests/daemon/`.

### Daemon tests

Shared infrastructure lives in `tests/daemon/common.rs`. Each test binary includes it with:
```rust
#[path = "common.rs"]
mod common;
use common::*;
```

Test binaries:

| Binary | Path | What it covers |
|---|---|---|
| `daemon_basic` | `tests/daemon/basic.rs` | ping, unlock, lock, wipe, shutdown |
| `daemon_server` | `tests/daemon/server.rs` | register, invite exchange, messaging |
| `daemon_adversarial` | `tests/daemon/adversarial.rs` | bad JSON, wrong tokens, weak passwords, connection limits |
| `daemon_state_order` | `tests/daemon/state_order.rs` | operations called in wrong order |
| `daemon_payload` | `tests/daemon/payload.rs` | malformed IPC payload fields |
| `daemon_concurrency` | `tests/daemon/concurrency.rs` | parallel connections, shutdown races |
| `daemon_persistence` | `tests/daemon/persistence.rs` | state survives daemon restart |
| `daemon_contacts` | `tests/daemon/contacts.rs` | negative contact/invite flows |

Key details in `common.rs`:
- `wait_for_socket` checks file existence only — connecting would consume a semaphore slot
- `DaemonProcess::start_in` removes the stale socket before spawning so `wait_for_socket` sees only the new file
- `DaemonProcess::start()` uses `max_conn=4` so normal tests don't starve each other
- `daemon_bin()` is lazily built once per test process via `OnceLock`

## Code Style

### Comments

Comments exist only to explain **why**, never what. Acceptable:

- Non-obvious trade-off or constraint
- An edge case that looks wrong but isn't
- "Don't refactor X to Y — it breaks Z"
- An architectural decision not derivable from the code

Not acceptable:

- Describing what the code does (the code already says that)
- Section dividers (`// --- foo ---`, `// ===`, etc.)
- Any decorative or structural comment
- Characters not on a standard keyboard (`→`, `─`, `•`, `═`, etc.)
- Anything that reads like an AI wrote it

Before writing a comment ask: would a reader ask *why* here? If yes, write it. If they'd ask *what*, don't.

### General

- No helpers that exist only to wrap a single call
- No error handling for scenarios that can't happen
- No feature flags, backwards-compat shims, or re-exports for removed code
- No docstrings on internal functions unless they are public API surface
- Don't add type annotations, docstrings, or comments to code you didn't change
- Minimum complexity for the current task — three similar lines beat a premature abstraction