use std::{fmt::Write as _, io, sync::Arc, time::Duration};

use serde_json::json;
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    sync::{oneshot, Mutex},
};
use lithium_core::crypto::keys;
use lithium_core::error::{LithiumError, Result};
use lithium_core::passwords::passwords::PasswordPolicy;

use crate::commands;
use crate::ipc::types::{bad_json_resp, err_resp, IpcCommand, IpcRequest, IpcResponse};
use crate::state::DaemonState;

pub mod types;

#[cfg(unix)]
pub mod unix;

#[cfg(windows)]
pub mod windows;

#[derive(Clone, Copy, Debug, Default)]
pub struct IpcPeerMeta {
    #[cfg(target_os = "linux")]
    pub uid: Option<u32>,

    #[cfg(target_os = "linux")]
    pub pid: Option<i32>,
}

async fn write_resp<W: AsyncWrite + Unpin>(w: &mut W, resp: &IpcResponse) -> Result<()> {
    let out = serde_json::to_string(resp).map_err(LithiumError::json_parse)?;
    w.write_all(out.as_bytes()).await.map_err(LithiumError::io)?;
    w.write_all(b"\n").await.map_err(LithiumError::io)?;
    Ok(())
}

fn timeout_err(what: &'static str) -> LithiumError {
    LithiumError::io(io::Error::new(io::ErrorKind::TimedOut, what))
}

fn cmd_requires_auth(cmd: &IpcCommand) -> bool {
    !matches!(cmd, IpcCommand::Ping | IpcCommand::UnlockKeystore { .. })
}

fn cmd_is_unlock(cmd: &IpcCommand) -> bool {
    matches!(cmd, IpcCommand::UnlockKeystore { .. })
}

async fn authorize_request(
    state: &Arc<DaemonState>,
    peer: IpcPeerMeta,
    req: &IpcRequest,
) -> Option<IpcResponse> {
    if !cmd_requires_auth(&req.cmd) {
        return None;
    }

    let provided = match req.auth_token.as_deref() {
        Some(v) if !v.is_empty() => v,
        _ => return Some(err_resp(req.id, "ipc_auth_required")),
    };

    let auth = state.ipc_auth.lock().await;

    let expected = match auth.session_token.as_deref() {
        Some(v) if !v.is_empty() => v,
        _ => return Some(err_resp(req.id, "ipc_auth_required")),
    };

    if provided.as_bytes() != expected.as_bytes() {
        return Some(err_resp(req.id, "ipc_auth_failed"));
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(bound_uid) = auth.bound_uid {
            if peer.uid != Some(bound_uid) {
                return Some(err_resp(req.id, "ipc_auth_failed"));
            }
        }

        if let Some(bound_pid) = auth.bound_pid {
            if peer.pid != Some(bound_pid) {
                return Some(err_resp(req.id, "ipc_auth_failed"));
            }
        }
    }

    None
}


async fn issue_ipc_session(state: &Arc<DaemonState>, peer: IpcPeerMeta) -> Result<String> {
    let token = keys::random_32()?.to_hex().expose().to_string();
    let mut auth = state.ipc_auth.lock().await;
    auth.session_token = Some(token.clone());

    #[cfg(target_os = "linux")]
    {
        auth.bound_uid = peer.uid;
        auth.bound_pid = peer.pid;
    }

    Ok(token)
}

fn attach_ipc_auth_result(resp: &mut IpcResponse, token: String) {
    let mut result = resp.result.take().unwrap_or_else(|| json!({}));

    if !result.is_object() {
        result = json!({});
    }

    if let Some(obj) = result.as_object_mut() {
        obj.insert("ipc_auth_token".into(), serde_json::Value::String(token));
    }

    resp.result = Some(result);
}

pub async fn handle_conn<S>(
    stream: S,
    shutdown_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    state: Arc<DaemonState>,
    idle_timeout: Duration,
    peer: IpcPeerMeta,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (r, mut w) = tokio::io::split(stream);
    let mut lines = BufReader::new(r).lines();

    let pol = PasswordPolicy::default();

    loop {
        let next = tokio::time::timeout(idle_timeout, lines.next_line())
            .await
            .map_err(|_| timeout_err("ipc idle timeout"))?;

        let Some(line) = next.map_err(LithiumError::io)? else {
            break;
        };

        if line.trim().is_empty() {
            continue;
        }

        let req: IpcRequest = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => {
                let resp = bad_json_resp(0);
                tokio::time::timeout(idle_timeout, write_resp(&mut w, &resp))
                    .await
                    .map_err(|_| timeout_err("ipc write timeout"))??;
                continue;
            }
        };

        if let Some(resp) = authorize_request(&state, peer, &req).await {
            tokio::time::timeout(idle_timeout, write_resp(&mut w, &resp))
                .await
                .map_err(|_| timeout_err("ipc write timeout"))??;
            continue;
        }

        let is_unlock = cmd_is_unlock(&req.cmd);
        let mut resp =
            commands::dispatch(req, Arc::clone(&state), Arc::clone(&shutdown_tx), &pol).await;

        if is_unlock && resp.ok {
            match issue_ipc_session(&state, peer).await {
                Ok(token) => attach_ipc_auth_result(&mut resp, token),
                Err(_) => {
                    resp.ok = false;
                    resp.result = None;
                    resp.error = Some("ipc_auth_issue_failed".into());
                }
            }
        }

        tokio::time::timeout(idle_timeout, write_resp(&mut w, &resp))
            .await
            .map_err(|_| timeout_err("ipc write timeout"))??;
    }

    Ok(())
}