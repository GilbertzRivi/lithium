// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use serde_json::json;
use tokio::sync::{Mutex, oneshot};

use crate::{ipc::types::IpcResponse, state::DaemonState};

pub async fn handle(
    id: u64,
    state: Arc<DaemonState>,
    shutdown_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
) -> IpcResponse {
    let tx_opt = shutdown_tx.lock().await.take();
    if let Some(tx) = tx_opt {
        state.lock_keystore().await;
        let _ = tx.send(());
    }

    IpcResponse {
        id,
        ok: true,
        result: Some(json!({"shutting_down": true})),
        error: None,
    }
}
