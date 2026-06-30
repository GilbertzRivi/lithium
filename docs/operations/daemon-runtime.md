# lithiumd daemon runtime: process model, system tray, lifecycle

This document describes how the `lithiumd` process is built and how 
it starts, restarts, and shuts down. The IPC commands are in 
[ipc-reference.md](../protocol/ipc-reference.md); this file is 
about the process runtime itself (`lithiumd/src/lib.rs`, `main.rs`, 
`tray.rs`, `util.rs`).

## Why `main()` is not `#[tokio::main]`

The system tray must own the process's main thread, so startup is 
split across two threads (`lithiumd/src/lib.rs`):

- The **main thread** runs `tray::run`, the tray menu loop.
- A **separate `std::thread`** creates the Tokio runtime and runs 
  the whole async daemon (`daemon_async`).

`main()` (`lithiumd/src/main.rs`) only calls `lithiumd::run()` and 
maps an error to `eprintln!("fatal: {e}")` + `exit(1)`. On Windows 
`#![cfg_attr(windows, windows_subsystem = "windows")]` suppresses 
the console window.

## The primitives bridging the two threads

| Primitive | Direction | Role |
|-----------|-----------|------|
| `watch::channel<bool>` (`stop_tx`/`stop_rx`) | tray -> daemon | the tray signals the daemon to stop |
| `Arc<AtomicBool>` (`daemon_done`) | daemon -> tray | the daemon tells the tray it has finished |
| `oneshot::channel<()>` (`shutdown_tx`/`shutdown_rx`) | IPC -> daemon | the IPC `shutdown` command breaks the daemon loop |

## The daemon loop (`daemon_async`)

The daemon waits in one `tokio::select!` on four events 
(`lithiumd/src/lib.rs`):

```
tokio::select! {
    _ = ipc_task        => {}   // the IPC listener task finished
    _ = shutdown_rx     => {}   // the IPC `shutdown` command
    _ = stop_rx.changed() => {} // a signal from the tray (Close/Restart)
    _ = signal          => {}   // SIGTERM or Ctrl+C (Unix), Ctrl+C (Windows)
}
```

Each of these paths unwinds the same `select!` and ends the 
daemon. After it ends, the daemon thread sets `daemon_done = true`.

## System tray (`tray.rs`)

The tray menu has: an inactive `Lithium` header, a separator, 
**Restart**, **Close**. The icon is a programmatically generated 
blue 32x32 circle. The tray loop:

1. On Linux it first calls `gtk::init()`; the loop calls 
   `gtk::main_iteration_do(false)` and checks menu events every 16 
   ms.
2. Clicking **Restart** or **Close** sends `stop.send(true)` 
   (stops the daemon) and returns the matching `Action`.
3. If `daemon_done` becomes `true` on its own (for example a 
   `shutdown` through IPC), the tray exits with `Action::Close`.

**Headless degradation:** if `gtk::init()` fails or 
`TrayIconBuilder::build()` doesn't succeed (no graphical 
environment), the tray degrades to `wait_daemon_done`, it blocks 
without an icon until the daemon finishes. The daemon then runs 
normally, just without a tray icon.

## Shutdown and restart

- **Close**, **SIGTERM**/Ctrl+C, and the IPC `shutdown` all lead 
  to the same `select!` unwind and end the daemon.
- After the `tray::run` loop ends, the daemon thread is joined 
  (`daemon_thread.join()`).
- **Restart** additionally: after joining the daemon thread, 
  `run()` re-spawns the current executable 
  (`std::env::current_exe()`), then ends the old process.
- `WipeLocal` (an IPC command) first securely wipes `{data_dir}` 
  (overwrite with random data, `fsync`, delete, 
  `util::wipe_dir_all`), then shuts the daemon down.

## The IPC endpoint and its lifecycle

The endpoint is chosen at startup (`util::default_ipc_endpoint`):

- **Unix**: `LITHIUMD_SOCKET_PATH`, otherwise 
  `{XDG_RUNTIME_DIR}/lithiumd.sock`. Without `XDG_RUNTIME_DIR` and 
  without an override, startup fails (no safe location). The 
  socket listens with owner permissions; at startup 
  `prepare_socket` removes a stale socket from a previous run.
- **Windows**: the named pipe `LITHIUMD_PIPE_NAME` (default 
  `\\.\pipe\lithiumd`), `reject_remote_clients(true)`.

The IPC connection policy (`util::load_ipc_policy`), 
`LITHIUMD_IPC_MAX_CONNECTIONS`, `LITHIUMD_IPC_IDLE_TIMEOUT_SECS`, 
`LITHIUMD_IPC_ALLOWED_UID`, is collected in the [Environment 
variables](#environment-variables) section.

## Process startup, step by step

`run()` (`lithiumd/src/lib.rs`) does, in order:

1. `util::default_data_dir()`, resolve the data directory (see 
   below).
2. `prepare_private_dir`, create the data directory with `0o700` 
   permissions (Unix).
3. `prepare_ipc_endpoint`, remove a stale socket.
4. Load `server_url` (a file), the `server.identity` path 
   (`LITHIUMD_SERVER_IDENTITY` or `{data_dir}/server.identity`), 
   and the `needs_register` flag (whether `registered.flag` 
   exists).
5. Build `DaemonState`, start the daemon thread and `tray::run` on 
   the main thread.

The keystore, `MkRotator`, the local database, and 
`ProtocolManager` are not created at startup, they come up only 
after `unlock_keystore` / `unlock_storage` (see 
[ipc-reference.md](../protocol/ipc-reference.md)).

## Data directory layout

`default_data_dir()` returns `LITHIUMD_DATA_DIR`, or failing that 
the platform directory (Linux: `{XDG_DATA_HOME}/lithiumd` or 
`~/.local/share/lithiumd`; Windows: `%LOCALAPPDATA%\Lithiumd`). 
The contents:

```
{data_dir}/                       (0o700)
  keystore/
    user/
      mk.enc                Master Key wrapped by the data password (Argon2id + AES-256-GCM-SIV)
      root.salt             random per-install Argon2 salt for DEK derivation
    pub/                    public keys (cache: ed25519.pub, x25519.pub, ...)
    priv/                   private keys (*.keyf, wrapped under the MK)
    secrets/                derived secrets (*.keyf, wrapped under the MK)
    .rotate/                temporary MK rotation directory
  storage/
    lithiumd.sqlite         local database (contacts, messages, prekeys)
  server.identity           server public keys (or LITHIUMD_SERVER_IDENTITY)
  server_url                relay address (text)
  registered.flag           registration marker (0o600)
```

The IPC socket does **not** live in the data directory, by default 
it's in `{XDG_RUNTIME_DIR}`. The `mk.enc`, `*.keyf`, and 
`server.identity` formats are in 
[crypto-protocol.md](../protocol/crypto-protocol.md); the 
`storage/lithiumd.sqlite` table schema is in 
[lithiumd.md](../crates/lithiumd.md). At-rest data encryption and 
the "two-factor" model (password + `server_dek`) are in 
[security-model.md](../security-model.md).

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LITHIUMD_DATA_DIR` | the platform data directory (e.g. `~/.local/share/lithiumd`) | The daemon's data directory |
| `LITHIUMD_SOCKET_PATH` | `{XDG_RUNTIME_DIR}/lithiumd.sock` | Unix socket path |
| `LITHIUMD_PIPE_NAME` | `\\.\pipe\lithiumd` | Named pipe name (Windows) |
| `LITHIUMD_SERVER_IDENTITY` | `{data_dir}/server.identity` | Server identity file path |
| `LITHIUMD_IPC_MAX_CONNECTIONS` | `1` | Max parallel IPC connections |
| `LITHIUMD_IPC_IDLE_TIMEOUT_SECS` | `300` | Connection idle timeout (min 5) |
| `LITHIUMD_IPC_ALLOWED_UID` | - | Allowed UID (Linux; none = no restriction); a denial drops the connection with no JSON reply |
| `LITHIUMD_TRAFFIC_SEND_INTERVAL_SECS` | `20` | Cadence of the cover-traffic send dispatcher (min 1) |
| `LITHIUMD_TRAFFIC_FETCH_INTERVAL_SECS` | `20` | Cadence of the cover-traffic fetch dispatcher / auto-fetch (min 1) |

The relay address is not an environment variable, it's set with 
the IPC `set_server_url` command and saved to 
`{data_dir}/server_url`.
