use std::sync::Arc;

use serde_json::json;

use crate::{
    ipc::types::{err_resp, IpcResponse},
    state::DaemonState,
    util,
};

pub async fn handle(id: u64, state: Arc<DaemonState>) -> IpcResponse {
    state.lock_keystore().await;

    let dir = state.base_dir.clone();
    match util::wipe_dir_all(&dir) {
        Ok(()) => {
            state.mark_needs_register().await;

            IpcResponse {
                id,
                ok: true,
                result: Some(json!({
                    "wiped": true,
                    "best_effort": true
                })),
                error: None,
            }
        }
        Err(_) => err_resp(id, "wipe_failed"),
    }
}