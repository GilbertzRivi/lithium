# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Build all workspace members
cargo build

# Build specific crate
cargo build -p lithiumd
cargo build -p lithiums
cargo build -p lithiumg

# Run in release mode
cargo run -p lithiumd --release
cargo run -p lithiums --release

# Run tests for all crates
cargo test

# Run tests for a specific crate
cargo test -p lithium_core

# Run a single test by name
cargo test -p lithium_core test_name

# Check without building
cargo check
```

## Architecture Overview

Lithium is a post-quantum secure private messenger composed of four Rust workspace crates:

### `lithium_core` — Shared Cryptographic Library
The foundation. No binaries, only library code. Provides:
- **`crypto/`**: Hybrid PQ crypto primitives — `kyberbox` (X25519 + ML-KEM-1024 hybrid encryption), `aead` (AES-GCM-SIV), `kdf` (HKDF), `sign` (Ed25519 + ML-DSA-87 dual signing)
- **`keys/manager.rs`**: `KeyManager<P: MkProvider>` — manages ed25519/x25519/kyber/dilithium keypairs on disk, encrypted under a master key. Supports periodic master-key rotation (`maybe_rotate_mk`). Two flavors: `PlainFileMkProvider` (server) and `PasswordFileMkProvider` (daemon/client)
- **`db/manager.rs`**: `DataManager` — wraps SeaORM, handles encrypted storage using the key manager
- **`secrets/`**: Zeroizing secret types (`SecretString`, `SecretBytes`, `Byte32`, `Byte64`, `SecretJson`) used everywhere sensitive data flows
- **`passwords/`**: Argon2-based password hashing/verification with policy enforcement
- **`utils/store.rs`**: `EphemeralStoreManager` — in-memory TTL store for session/crypto state

### `lithiumd` — Client Daemon (background process)
Runs as a local daemon on the user's machine. Communicates with both the server (`lithiums`) and the GUI (`lithiumg`). Key components:
- **`ipc/`**: Listens on a Unix socket (Linux/macOS) or named pipe (Windows). IPC protocol is newline-delimited JSON with `cmd` tag dispatch
- **`ipc/types.rs`**: All IPC commands (`IpcRequest` / `IpcResponse`) and their response constructors
- **`commands/mod.rs`**: Routes `IpcRequest` variants to handler functions in individual files
- **`protocol_manager.rs`**: `ProtocolManager` — handles the encrypted handshake/session protocol with the server. All HTTP requests are encrypted with hybrid PQ (`kyberbox`), signed with Ed25519 + ML-DSA-87, and padded to random block sizes to resist traffic analysis
- **`commands/e2e.rs`**: End-to-end message encryption logic — custom forward-secrecy ratchet using X25519 + ML-KEM-1024, with prekey support and a sliding-window ACK for key GC
- **`state.rs`**: `DaemonState` — shared mutable state protected by `Arc<Mutex<...>>`. Key lifecycle states: keystore locked → credentials set → registered → storage unlocked → ready
- **`db/`**: Local SQLite database (via SeaORM) storing contacts, messages, prekeys

### `lithiums` — Server
HTTP API server built with `poem`. All endpoints use the encrypted transport layer:
- **`transport/mod.rs`**: `CryptoMiddleware` / `CryptoCfg` — decrypts and authenticates every request before the handler runs; encrypts every response. Three auth modes: `KeysInHeaders` (identity keys in app-headers), `LoginByHandler` (server looks up registered user keys), `JwtUser` (single-use JWT)
- **`api/handshake.rs`**: `/shake` — establishes an ephemeral session (client sends ephemeral keys, server stores session private keys in `EphemeralStoreManager`)
- **`api/user.rs`**: `/user/register`, `/user/login`
- **`api/messages.rs`**: `/msg/send`, `/msg/fetch` — mailbox-style message relay; messages are stored as opaque blobs already E2E-encrypted by the client
- **`db/`**: PostgreSQL backend (via SeaORM)
- **`state.rs`**: `AppState` wraps `KeyManager`, `EphemeralStoreManager`, and `DataManager`

### `lithiumg` — GUI
Desktop GUI built with `egui`/`eframe`. Communicates with the daemon via IPC:
- **`ipc.rs`**: All IPC call functions (typed wrappers around the JSON protocol)
- **`app.rs`**: `LithiumApp` — egui app with a command/event channel pattern. Sends `Command` to a worker thread via `mpsc`, receives `WorkerEvent` back. Follows a state machine (`Screen` enum) driven by ping responses from the daemon

## Cryptographic Transport Protocol

All client↔server traffic goes through the `kyberbox` hybrid encryption scheme:
1. Client generates ephemeral X25519 + ML-KEM-1024 keypairs
2. Body and app-headers are each separately encrypted and random-padded
3. Requests include dual signatures (Ed25519 + ML-DSA-87)
4. For session endpoints, both sides store ephemeral session keys in `EphemeralStoreManager` with TTL; keys are consumed (single-use) on each request

## Environment Variables

**`lithiumd/.env`** (client daemon):
- `SERVER_X25519`, `SERVER_KYBER` — server's public bootstrap keys (hex)
- `SERVER_ED25519`, `SERVER_DILITHIUM` — server's identity signature keys for response verification (optional)
- `LITHIUM_SERVER_URL` — server base URL (default: `http://127.0.0.1:4108`)
- `LITHIUMD_DATA_DIR` — local data directory
- `LITHIUMD_SOCKET_PATH` — Unix socket path
- `RUST_LOG` — log level

**`lithiums/.env`** (server):
- `DATABASE_URL` — PostgreSQL connection URL
- `LITHIUM_KEYS_DIR` — directory for server keypair storage
- `LITHIUM_BIND` — bind address (default: `0.0.0.0:4108`)
- `LITHIUM_SERVER_NAME` — keystore namespace (default: `default`)
- `LITHIUM_MK_ROTATE_SECS` — master key rotation interval in seconds (default: 3600)

## Data Storage

- **Server**: PostgreSQL (via SeaORM). Tables: `users`, `messages` (mailboxes), prekeys
- **Daemon**: SQLite (via SeaORM). Tables: `contacts` (with encrypted peer/self state blobs), `messages`, `prekeys`
- **Keyfiles**: Stored in `{base_dir}/{server|user}/{name}/pub/` and `.../priv/`. Private keys are AES-GCM-SIV encrypted under the master key. Public keys are plain files