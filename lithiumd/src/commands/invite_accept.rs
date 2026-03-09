use std::sync::Arc;

use serde_json::{json, Value};

use lithium_core::{
    error::LithiumError,
    secrets::{SecretJson, SecretString},
    secrets::bytes::SecretBytes,
};

use crate::{
    commands::invite_codec::{decode_contact_id_hex, decode_invite_code, encode_invite_code, InvitePublic},
    db::repo::DaemonDbExt,
    ipc::types::{err_resp, internal_err, storage_err, IpcResponse},
    state::DaemonState,
};
use crate::commands::invite_codec::gen_self_state;

pub async fn handle(
    id: u64,
    code: String,
    contact_id_opt: Option<String>,
    label: String,
    state: Arc<DaemonState>,
) -> IpcResponse {
    let dm_opt = state.local_db.lock().await.clone();
    let Some(dm) = dm_opt else {
        return err_resp(id, "storage_locked");
    };

    let code_ss = SecretString::new(code);
    let peer = match decode_invite_code(&code_ss) {
        Ok(v) => v,
        Err(_) => return err_resp(id, "invalid_invite_code"),
    };

    let server_ss = peer.server.clone();
    let mut should_return_my_code = false;

    let (contact_id, self_json) = if let Some(cid_hex) = contact_id_opt {
        let cid_ss = SecretString::new(cid_hex);
        let contact_id = match decode_contact_id_hex(&cid_ss) {
            Ok(v) => v,
            Err(_) => return err_resp(id, "invalid_contact_id"),
        };

        match dm.get_contact(contact_id.as_slice()).await {
            Ok(Some(row)) => {
                let existing_peer_json: Value =
                    match serde_json::from_slice(row.peer_state.as_slice()) {
                        Ok(v) => v,
                        Err(_) => return err_resp(id, "peer_state_corrupt"),
                    };

                if let Some(peer_obj) = existing_peer_json.get("peer") {
                    if !peer_obj.is_null() {
                        let existing_cid_hex =
                            peer_obj.get("cid").and_then(|v| v.as_str()).unwrap_or("");

                        let existing_cid = match hex::decode(existing_cid_hex.trim()) {
                            Ok(v) => v,
                            Err(_) => return err_resp(id, "peer_state_corrupt"),
                        };

                        let incoming_cid = match hex::decode(peer.cid_hex.expose().trim()) {
                            Ok(v) => v,
                            Err(_) => return err_resp(id, "invalid_invite_code"),
                        };

                        if existing_cid != incoming_cid {
                            return err_resp(id, "peer_already_set_mismatch");
                        }
                    }
                }

                let sj = match SecretJson::from_vec(row.self_state.as_slice().to_vec()) {
                    Ok(v) => v,
                    Err(_) => return err_resp(id, "self_state_corrupt"),
                };

                (contact_id, sj)
            }
            Ok(None) => return err_resp(id, "contact_not_found"),
            Err(_) => return storage_err(id),
        }
    } else {
        should_return_my_code = true;
        match gen_self_state(server_ss.clone()) {
            Ok(v) => v,
            Err(_) => return internal_err(id),
        }
    };

    let peer_val = json!({
        "v": 1,
        "label": label,
        "peer": {
            "server": peer.server.expose(),
            "cid": peer.cid_hex.expose(),
            "x_pub": peer.x_pub_hex.expose(),
            "k_pub": peer.k_pub_hex.expose(),
            "ed_pub": peer.ed_pub_hex.expose(),
            "dili_pub": peer.dili_pub_hex.expose()
        }
    });

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

    let my_code = if should_return_my_code {
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

        let my_pub = InvitePublic {
            server: server_ss.clone(),
            cid_hex,
            x_pub_hex: x_pub,
            k_pub_hex: k_pub,
            ed_pub_hex: ed_pub,
            dili_pub_hex: dili_pub,
        };

        match encode_invite_code(&my_pub) {
            Ok(v) => v.expose().to_string(),
            Err(_) => return internal_err(id),
        }
    } else {
        String::new()
    };

    IpcResponse {
        id,
        ok: true,
        result: Some(json!({
            "contact_id": hex::encode(contact_id),
            "my_code": my_code
        })),
        error: None,
    }
}