use std::sync::Arc;

use reqwest::Url;
use tokio::sync::{oneshot, Mutex};

use lithium_core::error::Result;

mod password_provider;
mod protocol_manager;

mod util;
mod state;
mod identity;
mod ipc;
mod commands;
mod db;

use state::DaemonState;
use util::IpcEndpoint;

#[tokio::main]
async fn main() -> Result<()> {
    let base_dir = util::default_data_dir();
    let ipc_endpoint = util::default_ipc_endpoint();
    let ipc_policy = util::load_ipc_policy()?;

    util::prepare_private_dir(&base_dir)?;
    util::prepare_ipc_endpoint(&ipc_endpoint)?;

    let server_url_path = util::server_url_path(&base_dir);
    let base_url = std::fs::read_to_string(&server_url_path)
        .ok()
        .and_then(|s| Url::parse(s.trim()).ok());

    // Server identity is read lazily on first connection — only the path is resolved here.
    let identity_path = match std::env::var_os("LITHIUMD_SERVER_IDENTITY") {
        Some(v) => std::path::PathBuf::from(v),
        None => base_dir.join("server.identity"),
    };

    let needs_register = util::load_needs_register(&base_dir);

    let state = Arc::new(DaemonState::new(
        base_dir,
        base_url,
        identity_path,
        needs_register,
    ));

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let shutdown_tx = Arc::new(Mutex::new(Some(shutdown_tx)));

    #[cfg(unix)]
    let ipc_task = {
        let IpcEndpoint::Unix(socket_path) = &ipc_endpoint;
        ipc::unix::run(
            socket_path,
            Arc::clone(&shutdown_tx),
            Arc::clone(&state),
            ipc_policy.clone(),
        )
    };

    #[cfg(windows)]
    let ipc_task = {
        let IpcEndpoint::NamedPipe(pipe_name) = &ipc_endpoint;
        ipc::windows::run(
            pipe_name,
            Arc::clone(&shutdown_tx),
            Arc::clone(&state),
            ipc_policy.clone(),
        )
    };

    tokio::select! {
        _ = ipc_task => {},
        _ = shutdown_rx => {},
    }

    Ok(())
}