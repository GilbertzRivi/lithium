use std::sync::Arc;

use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    sync::{oneshot, Mutex},
};

use lithium_core::error::{LithiumError, Result};
use lithium_core::passwords::passwords::PasswordPolicy;

use crate::commands;
use crate::ipc::types::{bad_json_resp, IpcRequest, IpcResponse};
use crate::state::DaemonState;

pub mod types;

#[cfg(unix)]
pub mod unix;

#[cfg(windows)]
pub mod windows;

async fn write_resp<W: AsyncWrite + Unpin>(w: &mut W, resp: &IpcResponse) -> Result<()> {
    let out = serde_json::to_string(resp).map_err(LithiumError::json_parse)?;
    w.write_all(out.as_bytes()).await.map_err(LithiumError::io)?;
    w.write_all(b"\n").await.map_err(LithiumError::io)?;
    Ok(())
}

pub async fn handle_conn<S>(
    stream: S,
    shutdown_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    state: Arc<DaemonState>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (r, mut w) = tokio::io::split(stream);
    let mut lines = BufReader::new(r).lines();

    let pol = PasswordPolicy::default();

    while let Some(line) = lines.next_line().await.map_err(LithiumError::io)? {
        if line.trim().is_empty() {
            continue;
        }

        let req: IpcRequest = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => {
                let resp = bad_json_resp(0);
                write_resp(&mut w, &resp).await?;
                continue;
            }
        };

        let resp = commands::dispatch(req, Arc::clone(&state), Arc::clone(&shutdown_tx), &pol).await;
        write_resp(&mut w, &resp).await?;
    }

    Ok(())
}
