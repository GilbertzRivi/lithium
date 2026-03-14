use std::{fs, io, sync::Arc};

use serde_json::json;

use crate::{
    ipc::types::{err_resp, protocol_err, IpcResponse},
    state::DaemonState,
    util,
};

fn remove_registered_flag(base_dir: &std::path::Path) -> std::io::Result<()> {
    let p = util::registered_marker_path(base_dir);

    match fs::remove_file(&p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

pub async fn handle(id: u64, state: Arc<DaemonState>) -> IpcResponse {
    let proto_opt = state.proto.lock().await.clone();
    let Some(proto) = proto_opt else {
        return err_resp(id, "keystore_locked");
    };

    if proto.delete().await.is_err() {
        return protocol_err(id);
    }

    state.lock_keystore().await;
    state.mark_needs_register().await;

    if remove_registered_flag(&state.base_dir).is_err() {
        return err_resp(id, "account_deleted_but_registered_flag_remove_failed");
    }

    let storage_dir = state.base_dir.join("storage");
    if util::wipe_dir_all(&storage_dir).is_err() {
        return err_resp(id, "account_deleted_but_local_storage_wipe_failed");
    }

    IpcResponse {
        id,
        ok: true,
        result: Some(json!({
            "deleted": true,
            "local_cleanup": true
        })),
        error: None,
    }
}