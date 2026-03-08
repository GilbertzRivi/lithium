use std::{fs, path::Path, sync::Arc};

use tokio::{net::UnixListener, sync::{oneshot, Mutex}};

use lithium_core::error::{LithiumError, Result};

use crate::state::DaemonState;

pub async fn run(
    socket_path: &Path,
    shutdown_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    state: Arc<DaemonState>,
) -> Result<()> {
    let listener = UnixListener::bind(socket_path).map_err(LithiumError::io)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))
            .map_err(LithiumError::io)?;
    }

    loop {
        let (stream, _addr) = listener.accept().await.map_err(LithiumError::io)?;
        let shutdown_tx = Arc::clone(&shutdown_tx);
        let state = Arc::clone(&state);

        tokio::spawn(async move {
            if let Err(e) = super::handle_conn(stream, shutdown_tx, state).await {
                eprintln!("ipc conn error: {e:?}");
            }
        });
    }
}
