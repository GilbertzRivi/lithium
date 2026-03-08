use std::sync::Arc;

use tokio::{
    net::windows::named_pipe::ServerOptions,
    sync::{oneshot, Mutex},
};

use lithium_core::error::{LithiumError, Result};

use crate::state::DaemonState;

fn server_builder(first_instance: bool) -> ServerOptions {
    let mut opts = ServerOptions::new();
    opts.reject_remote_clients(true);
    if first_instance {
        opts.first_pipe_instance(true);
    }
    opts
}

pub async fn run(
    pipe_name: &str,
    shutdown_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    state: Arc<DaemonState>,
) -> Result<()> {
    let first = server_builder(true)
        .create(pipe_name)
        .map_err(LithiumError::io)?;

    first.connect().await.map_err(LithiumError::io)?;
    {
        let shutdown_tx = Arc::clone(&shutdown_tx);
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = super::handle_conn(first, shutdown_tx, state).await {
                eprintln!("ipc conn error: {e:?}");
            }
        });
    }

    loop {
        let server = server_builder(false)
            .create(pipe_name)
            .map_err(LithiumError::io)?;

        server.connect().await.map_err(LithiumError::io)?;

        let shutdown_tx = Arc::clone(&shutdown_tx);
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = super::handle_conn(server, shutdown_tx, state).await {
                eprintln!("ipc conn error: {e:?}");
            }
        });
    }
}
