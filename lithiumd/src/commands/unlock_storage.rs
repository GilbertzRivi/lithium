use std::sync::Arc;

use serde_json::json;

use lithium_core::opaque::dek::unwrap_dek_under_export_key;
use lithium_core::secrets::Byte32;

use crate::{
    db,
    ipc::types::{IpcResponse, crypto_err, err_resp, internal_err, protocol_err},
    state::DaemonState,
};

pub async fn handle(id: u64, state: Arc<DaemonState>) -> IpcResponse {
    let proto_opt = state.proto.lock().await.clone();

    if proto_opt.is_none() {
        return err_resp(id, "keystore_locked");
    }
    if *state.needs_register.lock().await {
        return err_resp(id, "register_required");
    }

    *state.dek_plain.lock().await = None;

    let dp_opt = state.data_pass.lock().await.clone();
    match (dp_opt, proto_opt) {
        (Some(_dp), Some(proto)) => match proto.get_dek().await {
            Ok(dek_blob_hex) => {
                let export_key = match proto.get_export_key().await {
                    Ok(v) => v,
                    Err(_) => return protocol_err(id),
                };
                match unwrap_dek_under_export_key(&dek_blob_hex, &export_key) {
                    Ok(dek_b32) => {
                        let arr = match Byte32::from_slice(dek_b32.as_slice()) {
                            Ok(v) => v,
                            Err(_) => return internal_err(id),
                        };

                        *state.dek_plain.lock().await = Some(arr.clone());

                        let keys_opt = state.keys.lock().await.clone();
                        let Some(keys) = keys_opt else {
                            return err_resp(id, "keystore_locked");
                        };

                        {
                            let mut km = keys.lock().await;
                            km.mk_provider_mut().set_server_dek(arr.clone());
                        }

                        let need_init = state.local_db.lock().await.is_none();
                        if need_init {
                            match db::init_local_data_manager(&state.base_dir, keys).await {
                                Ok(dm) => {
                                    *state.local_db.lock().await = Some(dm);
                                }
                                Err(_) => return err_resp(id, "storage_init_failed"),
                            }
                        }

                        IpcResponse {
                            id,
                            ok: true,
                            result: Some(json!({"unlocked": true})),
                            error: None,
                        }
                    }
                    Err(_) => crypto_err(id),
                }
            }
            Err(_) => protocol_err(id),
        },
        (None, _) => err_resp(id, "missing_data_password"),
        _ => err_resp(id, "internal_state_error"),
    }
}
