use std::sync::Arc;

use serde_json::json;

use crate::{ipc::types::IpcResponse, state::DaemonState};

pub async fn handle(id: u64, state: Arc<DaemonState>) -> IpcResponse {
    state.lock_keystore().await;

    IpcResponse {
        id,
        ok: true,
        result: Some(json!({ "locked": true })),
        error: None,
    }
}
