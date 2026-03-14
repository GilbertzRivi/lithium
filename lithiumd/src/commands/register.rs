use std::sync::Arc;

use serde_json::json;

use lithium_core::passwords::passwords::{
    generate_dek, validate_passwords_distinct, wrap_dek_for_server_hex, PasswordPolicy,
};
use lithium_core::secrets::Byte32;

use crate::{
    ipc::types::{crypto_err, err_resp, internal_err, protocol_err, IpcResponse},
    state::DaemonState,
    util,
};

pub async fn handle(id: u64, state: Arc<DaemonState>, _pol: &PasswordPolicy) -> IpcResponse {
    let needs_register = *state.needs_register.lock().await;
    let proto_opt = state.proto.lock().await.clone();

    if proto_opt.is_none() {
        return err_resp(id, "keystore_locked");
    }
    if !needs_register {
        return IpcResponse {
            id,
            ok: true,
            result: Some(json!({"registered": true})),
            error: None,
        };
    }

    let dp_opt = state.data_pass.lock().await.clone();
    let creds_opt = state.account_creds.lock().await.clone();

    match (dp_opt, creds_opt, proto_opt) {
        (None, _, _) => err_resp(id, "missing_data_password"),
        (_, None, _) => err_resp(id, "missing_account_credentials"),
        (Some(dp), Some((h, ap)), Some(proto)) => {
            if validate_passwords_distinct(&dp, &ap).is_err() {
                return err_resp(id, "passwords_must_be_distinct");
            }

            proto.set_credentials(h, ap).await;

            let dek_b32 = match generate_dek() {
                Ok(v) => v,
                Err(_) => return crypto_err(id),
            };

            let dek_blob_hex = match wrap_dek_for_server_hex(&dek_b32, &dp) {
                Ok(v) => v,
                Err(_) => return crypto_err(id),
            };

            let capability = match proto.register(&dek_blob_hex.expose()).await {
                Ok(v) => v,
                Err(_) => return protocol_err(id),
            };

            let arr = match Byte32::from_slice(dek_b32.as_slice()) {
                Ok(v) => v,
                Err(_) => return internal_err(id),
            };

            *state.dek_plain.lock().await = Some(arr.clone());

            if let Some(keys) = state.keys.lock().await.clone() {
                let mut km = keys.lock().await;
                km.mk_provider_mut().set_server_dek(arr.clone());
            }

            state.clear_needs_register().await;

            let _ = util::mark_registered(&state.base_dir);

            IpcResponse {
                id,
                ok: true,
                result: Some(json!({
                    "registered": true,
                    "capability": capability.expose()
                })),
                error: None,
            }
        }
        _ => err_resp(id, "internal_state_error"),
    }
}