// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use serde_json::json;

use crate::{
    ipc::types::{IpcResponse, err_resp, internal_err},
    state::DaemonState,
};

pub async fn handle(id: u64, data: String, state: Arc<DaemonState>) -> IpcResponse {
    let bytes = match hex::decode(&data) {
        Ok(b) => b,
        Err(_) => return err_resp(id, "server_identity_bad_hex"),
    };

    if let Err(e) = crate::identity::parse(&bytes) {
        return err_resp(id, format!("server_identity_invalid:{e}"));
    }

    if let Some(parent) = state.identity_path.parent()
        && std::fs::create_dir_all(parent).is_err()
    {
        return internal_err(id);
    }

    if std::fs::write(&state.identity_path, &bytes).is_err() {
        return internal_err(id);
    }

    if let Some(proto) = state.proto.lock().await.as_ref() {
        proto.invalidate_bootstrap_cache().await;
    }

    IpcResponse {
        id,
        ok: true,
        result: Some(json!({"saved": true})),
        error: None,
    }
}
