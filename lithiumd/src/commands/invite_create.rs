use std::sync::Arc;

use serde_json::{json, Value};

use lithium_core::{
    error::LithiumError,
    secrets::{SecretJson, SecretString},
    secrets::bytes::SecretBytes,
};

use crate::{
    commands::invite_codec::{decode_contact_id_hex, encode_invite_code, InvitePublic},
    db::repo::DaemonDbExt,
    ipc::types::{err_resp, internal_err, storage_err, IpcResponse},
    state::DaemonState,
};
use crate::commands::invite_codec::gen_self_state;

fn default_server_string(state: &DaemonState) -> SecretString {
    SecretString::new(state.base_url.to_string().trim_end_matches('/').to_string())
}

pub async fn handle(
    id: u64,
    contact_id_opt: Option<String>,
    server_opt: Option<String>,
    state: Arc<DaemonState>,
) -> IpcResponse {
    let dm_opt = state.local_db.lock().await.clone();
    let Some(dm) = dm_opt else {
        return err_resp(id, "storage_locked");
    };

    if let Some(cid_hex) = contact_id_opt {
        let cid_ss = SecretString::new(cid_hex);
        let contact_id = match decode_contact_id_hex(&cid_ss) {
            Ok(v) => v,
            Err(_) => return err_resp(id, "invalid_contact_id"),
        };

        let row_opt = match dm.get_contact(contact_id.as_slice()).await {
            Ok(v) => v,
            Err(_) => return storage_err(id),
        };

        let Some(row) = row_opt else {
            return err_resp(id, "contact_not_found");
        };

        let self_json = match SecretJson::from_vec(row.self_state.as_slice().to_vec()) {
            Ok(v) => v,
            Err(_) => return err_resp(id, "self_state_corrupt"),
        };

        let server_ss = server_opt
            .map(SecretString::new)
            .unwrap_or_else(|| default_server_string(&state));

        let cid_hex = match self_json.get_string("cid") {
            Ok(v) => v,
            Err(_) => return err_resp(id, "self_state_corrupt"),
        };
        let x_pub = match self_json.get_string("x_pub") {
            Ok(v) => v,
            Err(_) => return err_resp(id, "self_state_corrupt"),
        };
        let k_pub = match self_json.get_string("k_pub") {
            Ok(v) => v,
            Err(_) => return err_resp(id, "self_state_corrupt"),
        };
        let ed_pub = match self_json.get_string("ed_pub") {
            Ok(v) => v,
            Err(_) => return err_resp(id, "self_state_corrupt"),
        };
        let dili_pub = match self_json.get_string("dili_pub") {
            Ok(v) => v,
            Err(_) => return err_resp(id, "self_state_corrupt"),
        };

        let pub_code = InvitePublic {
            server: server_ss,
            cid_hex,
            x_pub_hex: x_pub,
            k_pub_hex: k_pub,
            ed_pub_hex: ed_pub,
            dili_pub_hex: dili_pub,
        };

        let code = match encode_invite_code(&pub_code) {
            Ok(v) => v,
            Err(_) => return internal_err(id),
        };

        return IpcResponse {
            id,
            ok: true,
            result: Some(json!({
                "contact_id": hex::encode(contact_id),
                "code": code.expose()
            })),
            error: None,
        };
    }

    let server_ss = server_opt
        .map(SecretString::new)
        .unwrap_or_else(|| default_server_string(&state));

    let (contact_id, self_json) = match gen_self_state(server_ss.clone()) {
        Ok(v) => v,
        Err(_) => return internal_err(id),
    };

    let peer_val = json!({ "v": 1, "peer": Value::Null });
    let peer_bytes = match serde_json::to_vec(&peer_val) {
        Ok(v) => v,
        Err(_) => return err_resp(id, "json_error"),
    };
    let peer_json = match SecretJson::from_vec(peer_bytes) {
        Ok(v) => v,
        Err(_) => return internal_err(id),
    };

    let self_raw = match self_json.raw_json().ok_or_else(|| LithiumError::internal()) {
        Ok(v) => v,
        Err(_) => return internal_err(id),
    };
    let peer_raw = match peer_json.raw_json().ok_or_else(|| LithiumError::internal()) {
        Ok(v) => v,
        Err(_) => return internal_err(id),
    };

    if dm
        .upsert_contact(
            contact_id.clone(),
            server_ss.expose().to_string(),
            SecretBytes::from_slice(peer_raw.expose().as_bytes()),
            SecretBytes::from_slice(self_raw.expose().as_bytes()),
        )
        .await
        .is_err()
    {
        return storage_err(id);
    }

    let cid_hex = match self_json.get_string("cid") {
        Ok(v) => v,
        Err(_) => return err_resp(id, "self_state_corrupt"),
    };
    let x_pub = match self_json.get_string("x_pub") {
        Ok(v) => v,
        Err(_) => return err_resp(id, "self_state_corrupt"),
    };
    let k_pub = match self_json.get_string("k_pub") {
        Ok(v) => v,
        Err(_) => return err_resp(id, "self_state_corrupt"),
    };
    let ed_pub = match self_json.get_string("ed_pub") {
        Ok(v) => v,
        Err(_) => return err_resp(id, "self_state_corrupt"),
    };
    let dili_pub = match self_json.get_string("dili_pub") {
        Ok(v) => v,
        Err(_) => return err_resp(id, "self_state_corrupt"),
    };

    let pub_code = InvitePublic {
        server: server_ss,
        cid_hex,
        x_pub_hex: x_pub,
        k_pub_hex: k_pub,
        ed_pub_hex: ed_pub,
        dili_pub_hex: dili_pub,
    };

    let code = match encode_invite_code(&pub_code) {
        Ok(v) => v,
        Err(_) => return internal_err(id),
    };

    IpcResponse {
        id,
        ok: true,
        result: Some(json!({
            "contact_id": hex::encode(contact_id),
            "code": code.expose()
        })),
        error: None,
    }
}
