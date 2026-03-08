use std::{fs, sync::Arc};

use tokio::sync::{oneshot, Mutex};
use reqwest::Url;

use lithium_core::error::{LithiumError, Result};

mod password_provider;
mod protocol_manager;

mod util;
mod state;
mod ipc;
mod commands;
mod db;

use state::DaemonState;
use util::IpcEndpoint;

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    util::init_logging();

    let base_dir = util::default_data_dir();
    let ipc_endpoint = util::default_ipc_endpoint();

    fs::create_dir_all(&base_dir).map_err(LithiumError::io)?;
    util::prepare_ipc_endpoint(&ipc_endpoint)?;

    let base_url = match std::env::var("LITHIUM_SERVER_URL") {
        Ok(s) => Url::parse(&s).map_err(|_| LithiumError::env_invalid("LITHIUM_SERVER_URL"))?,
        Err(_) => Url::parse("http://127.0.0.1:4108")
            .map_err(|_| LithiumError::env_invalid("LITHIUM_SERVER_URL"))?,
    };

    let bootstrap = protocol_manager::load_server_bootstrap_from_env()?;
    let needs_register = util::load_needs_register(&base_dir);

    let state = Arc::new(DaemonState::new(
        base_dir,
        base_url,
        bootstrap,
        needs_register,
    ));

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let shutdown_tx = Arc::new(Mutex::new(Some(shutdown_tx)));

    #[cfg(unix)]
    let ipc_task = {
        let IpcEndpoint::Unix(socket_path) = &ipc_endpoint;
        ipc::unix::run(socket_path, Arc::clone(&shutdown_tx), Arc::clone(&state))
    };

    #[cfg(windows)]
    let ipc_task = {
        let IpcEndpoint::NamedPipe(pipe_name) = &ipc_endpoint;
        ipc::windows::run(pipe_name, Arc::clone(&shutdown_tx), Arc::clone(&state))
    };

    tokio::select! {
        _ = ipc_task => {},
        _ = shutdown_rx => {},
    }

    Ok(())
}
