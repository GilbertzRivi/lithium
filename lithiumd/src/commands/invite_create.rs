use std::sync::Arc;

use serde::Serialize;
use serde_json::json;

use lithium_core::{
    secrets::{SecretJson, SecretString},
    secrets::bytes::SecretBytes,
};

use crate::{
    commands::invite_codec::{decode_contact_id_hex, encode_invite_code, gen_self_state, InvitePublic},
    db::repo::DaemonDbExt,
    ipc::types::{err_resp, internal_err, storage_err, IpcResponse},
    state::DaemonState,
};

#[derive(Serialize)]
struct EmptyPeerState {
    v: u8,
    peer: Option<()>,
}

pub async fn handle(
    id: u64,
    contact_id_opt: Option<String>,
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

        let self_json = match SecretJson::from_bytes(row.self_state.expose_as_slice()) {
            Ok(v) => v,
            Err(_) => return err_resp(id, "self_state_corrupt"),
        };

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

        let mbox_in_pub = match self_json.get_string("mbox_in_pub") {
            Ok(v) => v,
            Err(_) => return err_resp(id, "self_state_corrupt"),
        };
        let mbox_out_cur_pub = match self_json.get_string("mbox_out_cur_pub") {
            Ok(v) => v,
            Err(_) => return err_resp(id, "self_state_corrupt"),
        };
        let mbox_out_next_pub = match self_json.get_string("mbox_out_next_pub") {
            Ok(v) => v,
            Err(_) => return err_resp(id, "self_state_corrupt"),
        };

        let pub_code = InvitePublic {
            cid_hex,
            x_pub_hex: x_pub,
            k_pub_hex: k_pub,
            ed_pub_hex: ed_pub,
            dili_pub_hex: dili_pub,

            mbox_in_pub_hex: mbox_in_pub,
            mbox_out_cur_pub_hex: mbox_out_cur_pub,
            mbox_out_next_pub_hex: mbox_out_next_pub,
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

    let (contact_id, self_json) = match gen_self_state() {
        Ok(v) => v,
        Err(_) => return internal_err(id),
    };

    let peer_json = {
        let peer_state = EmptyPeerState { v: 1, peer: None };
        let mut buf = SecretBytes::new(Vec::new());
        if serde_json::to_writer(buf.expose_as_mut_vec(), &peer_state).is_err() {
            return err_resp(id, "json_error");
        }
        match SecretJson::from_bytes(buf.expose_as_slice()) {
            Ok(v) => v,
            Err(_) => return internal_err(id),
        }
    };

    let self_bytes = match self_json.with_exposed(|v| {
        let mut out = SecretBytes::new(Vec::new());
        serde_json::to_writer(out.expose_as_mut_vec(), v).ok()?;
        Some(out)
    }) {
        Some(v) => v,
        None => return err_resp(id, "json_error"),
    };

    let peer_bytes = match peer_json.with_exposed(|v| {
        let mut out = SecretBytes::new(Vec::new());
        serde_json::to_writer(out.expose_as_mut_vec(), v).ok()?;
        Some(out)
    }) {
        Some(v) => v,
        None => return err_resp(id, "json_error"),
    };

    if dm
        .upsert_contact(
            contact_id.clone(),
            peer_bytes,
            self_bytes,
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

    let mbox_in_pub = match self_json.get_string("mbox_in_pub") {
        Ok(v) => v,
        Err(_) => return err_resp(id, "self_state_corrupt"),
    };
    let mbox_out_cur_pub = match self_json.get_string("mbox_out_cur_pub") {
        Ok(v) => v,
        Err(_) => return err_resp(id, "self_state_corrupt"),
    };
    let mbox_out_next_pub = match self_json.get_string("mbox_out_next_pub") {
        Ok(v) => v,
        Err(_) => return err_resp(id, "self_state_corrupt"),
    };

    let pub_code = InvitePublic {
        cid_hex,
        x_pub_hex: x_pub,
        k_pub_hex: k_pub,
        ed_pub_hex: ed_pub,
        dili_pub_hex: dili_pub,

        mbox_in_pub_hex: mbox_in_pub,
        mbox_out_cur_pub_hex: mbox_out_cur_pub,
        mbox_out_next_pub_hex: mbox_out_next_pub,
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