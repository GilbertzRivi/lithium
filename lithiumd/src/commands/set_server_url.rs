// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use reqwest::Url;
use serde_json::json;

use crate::{
    ipc::types::{IpcResponse, err_resp},
    state::DaemonState,
    util,
};

pub async fn handle(id: u64, url: String, state: Arc<DaemonState>) -> IpcResponse {
    let url = url.trim().to_string();

    let parsed = match Url::parse(&url) {
        Ok(v) => v,
        Err(_) => return err_resp(id, "invalid_url"),
    };

    let path = util::server_url_path(&state.base_dir);
    if std::fs::write(&path, parsed.as_str()).is_err() {
        return err_resp(id, "write_failed");
    }

    state.set_server_url(parsed).await;

    IpcResponse {
        id,
        ok: true,
        result: Some(json!({"saved": true})),
        error: None,
    }
}
