use std::sync::Arc;

use tokio::{
    net::windows::named_pipe::ServerOptions,
    sync::{Mutex, Semaphore, oneshot},
};

use lithium_core::error::{LithiumError, Result};

use crate::{ipc::IpcPeerMeta, state::DaemonState, util::IpcPolicy};

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
    policy: IpcPolicy,
) -> Result<()> {
    let limiter = Arc::new(Semaphore::new(policy.max_connections));

    let first = server_builder(true)
        .create(pipe_name)
        .map_err(LithiumError::io)?;

    first.connect().await.map_err(LithiumError::io)?;
    {
        let permit = limiter
            .clone()
            .try_acquire_owned()
            .map_err(|_| LithiumError::io(std::io::Error::other("too many ipc connections")))?;
        let shutdown_tx = Arc::clone(&shutdown_tx);
        let state = Arc::clone(&state);
        let idle_timeout = policy.idle_timeout;

        tokio::spawn(async move {
            let _permit = permit;
            let _ = super::handle_conn(
                first,
                shutdown_tx,
                state,
                idle_timeout,
                IpcPeerMeta::default(),
            )
            .await;
        });
    }

    loop {
        let server = server_builder(false)
            .create(pipe_name)
            .map_err(LithiumError::io)?;

        server.connect().await.map_err(LithiumError::io)?;

        let permit = match limiter.clone().try_acquire_owned() {
            Ok(v) => v,
            Err(_) => continue,
        };

        let shutdown_tx = Arc::clone(&shutdown_tx);
        let state = Arc::clone(&state);
        let idle_timeout = policy.idle_timeout;

        tokio::spawn(async move {
            let _permit = permit;
            let _ = super::handle_conn(
                server,
                shutdown_tx,
                state,
                idle_timeout,
                IpcPeerMeta::default(),
            )
            .await;
        });
    }
}
