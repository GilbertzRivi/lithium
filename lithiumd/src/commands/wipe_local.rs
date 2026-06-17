use std::sync::Arc;

use serde_json::json;

use crate::{
    ipc::types::{IpcResponse, err_resp},
    state::DaemonState,
    util,
};

pub async fn wipe(state: &Arc<DaemonState>) -> Result<(), ()> {
    let dir = state.base_dir.clone();
    state.lock_keystore().await;
    tokio::task::spawn_blocking(move || util::wipe_dir_all(&dir))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
    state.mark_needs_register().await;
    Ok(())
}

pub async fn handle(id: u64, state: Arc<DaemonState>) -> IpcResponse {
    match wipe(&state).await {
        Ok(()) => IpcResponse {
            id,
            ok: true,
            result: Some(json!({"wiped": true, "best_effort": true})),
            error: None,
        },
        Err(()) => err_resp(id, "wipe_failed"),
    }
}
