use std::sync::Arc;

use serde_json::json;

use crate::ipc::types::IpcResponse;
use crate::state::DaemonState;
use crate::util;

pub async fn handle(id: u64, state: Arc<DaemonState>) -> IpcResponse {
    let has_proto = state.proto.lock().await.is_some();
    let needs_register = *state.needs_register.lock().await;
    let has_dek = state.dek_plain.lock().await.is_some();
    let has_local_db = state.local_db.lock().await.is_some();
    let has_keys = state.keys.lock().await.is_some();
    let has_creds = state.account_creds.lock().await.is_some();
    let has_data_pass = state.data_pass.lock().await.is_some();

    let has_server_url = state.server_url().await.is_some();
    let has_server_identity = state.identity_path.exists();
    let keystore_path = state.base_dir.join("keystore");
    let registered_marker = util::registered_marker_path(&state.base_dir);
    let local_db_path = state.base_dir.join("storage").join("lithiumd.sqlite");

    let has_keystore_on_disk = keystore_path.exists();
    let is_registered_on_disk = registered_marker.exists();
    let has_local_db_on_disk = local_db_path.exists();

    let first_run = !has_keystore_on_disk && !is_registered_on_disk;

    let ui_state = if !has_proto || !has_keys || !has_data_pass {
        "keystore_locked"
    } else if !has_creds {
        "needs_credentials"
    } else if needs_register {
        "needs_register"
    } else if !has_dek || !has_local_db {
        "storage_locked"
    } else {
        "ready"
    };

    let mut actions: Vec<&'static str> = Vec::new();

    if !has_proto || !has_keys || !has_data_pass {
        actions.push("unlock_keystore");
    }
    if has_proto && has_keys && has_data_pass && !has_creds {
        actions.push("set_credentials");
    }
    if has_proto && has_keys && has_data_pass && has_creds && needs_register {
        actions.push("register");
    }
    if has_proto
        && has_keys
        && has_data_pass
        && has_creds
        && !needs_register
        && (!has_dek || !has_local_db)
    {
        actions.push("unlock_storage");
    }

    IpcResponse {
        id,
        ok: true,
        result: Some(json!({
            "pong": true,
            "status": {
                "has_proto": has_proto,
                "has_keys": has_keys,
                "has_credentials": has_creds,
                "has_data_password": has_data_pass,
                "needs_register": needs_register,
                "has_dek": has_dek,
                "has_local_db": has_local_db,
                "has_server_url": has_server_url,
                "has_server_identity": has_server_identity,
                "has_keystore_on_disk": has_keystore_on_disk,
                "is_registered_on_disk": is_registered_on_disk,
                "has_local_db_on_disk": has_local_db_on_disk,
                "first_run": first_run,
            },
            "ui_state": ui_state,
            "actions_needed": actions
        })),
        error: None,
    }
}