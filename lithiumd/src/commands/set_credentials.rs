// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use serde_json::json;

use lithium_core::passwords::passwords::{
    PasswordPolicy, validate_password, validate_passwords_distinct,
};
use lithium_core::secrets::SecretString;

use crate::ipc::types::{IpcResponse, err_resp};
use crate::state::DaemonState;

pub async fn handle(
    id: u64,
    handler: SecretString,
    password: SecretString,
    state: Arc<DaemonState>,
    pol: &PasswordPolicy,
) -> IpcResponse {
    let handler_ss = handler;
    let account_pass = password;

    if validate_password(&account_pass, *pol).is_err() {
        return err_resp(id, "bad_account_password");
    }

    let dp_opt = state.data_pass.lock().await.clone();
    let distinct_ok = match dp_opt {
        None => Ok(()),
        Some(dp) => validate_passwords_distinct(&account_pass, &dp),
    };

    if distinct_ok.is_err() {
        return err_resp(id, "passwords_must_be_distinct");
    }

    *state.account_creds.lock().await = Some((handler_ss.clone(), account_pass.clone()));

    let proto_opt = state.proto.lock().await.clone();
    if let Some(proto) = proto_opt {
        proto.set_credentials(handler_ss, account_pass).await;
    }

    IpcResponse {
        id,
        ok: true,
        result: Some(json!({ "stored": true })),
        error: None,
    }
}
