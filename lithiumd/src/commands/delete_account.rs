// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use serde_json::json;

use crate::{
    commands::wipe_local,
    ipc::types::{IpcResponse, err_resp, protocol_err},
    state::DaemonState,
};

pub async fn handle(id: u64, state: Arc<DaemonState>) -> IpcResponse {
    let proto_opt = state.proto.lock().await.clone();
    let Some(proto) = proto_opt else {
        return err_resp(id, "keystore_locked");
    };

    if proto.delete().await.is_err() {
        return protocol_err(id);
    }

    if wipe_local::wipe(&state).await.is_err() {
        return err_resp(id, "account_deleted_but_local_wipe_failed");
    }

    IpcResponse {
        id,
        ok: true,
        result: Some(json!({"deleted": true})),
        error: None,
    }
}
