use std::sync::Arc;

use serde_json::json;

use crate::{
    ipc::types::{err_resp, IpcResponse},
    state::DaemonState,
    util,
};

/// Wipes all local data and locks the keystore.
/// Caller must hold a valid auth session — auth is cleared as the last step.
pub async fn wipe(state: &Arc<DaemonState>) -> Result<(), ()> {
    let dir = state.base_dir.clone();
    util::wipe_dir_all(&dir).map_err(|_| ())?;
    state.mark_needs_register().await;
    state.lock_keystore().await;
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