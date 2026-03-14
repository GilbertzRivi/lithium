use std::sync::Arc;

use serde::Serialize;
use serde_json::json;

use lithium_core::{
    secrets::{SecretJson, SecretString},
    secrets::bytes::SecretBytes,
};

use crate::{
    commands::invite_codec::{
        decode_contact_id_hex, decode_invite_code, encode_invite_code, gen_self_state, InvitePublic,
    },
    db::repo::DaemonDbExt,
    ipc::types::{err_resp, internal_err, storage_err, IpcResponse},
    state::DaemonState,
};

#[derive(Serialize)]
struct PeerState<'a> {
    v: u8,
    label: &'a str,
    peer: PeerStatePeer<'a>,
}

#[derive(Serialize)]
struct PeerStatePeer<'a> {
    cid: &'a str,
    x_pub: &'a str,
    k_pub: &'a str,
    ed_pub: &'a str,
    dili_pub: &'a str,

    mbox_in_pub: &'a str,
    mbox_out_cur_pub: &'a str,
    mbox_out_next_pub: &'a str,
}

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

    let mut should_return_my_code = false;

    let (contact_id, self_json) = if let Some(cid_hex) = contact_id_opt {
        let cid_ss = SecretString::new(cid_hex);
        let contact_id = match decode_contact_id_hex(&cid_ss) {
            Ok(v) => v,
            Err(_) => return err_resp(id, "invalid_contact_id"),
        };

        match dm.get_contact(contact_id.as_slice()).await {
            Ok(Some(row)) => {
                let existing_peer_json = match SecretJson::from_bytes(row.peer_state.expose_as_slice()) {
                    Ok(v) => v,
                    Err(_) => return err_resp(id, "peer_state_corrupt"),
                };

                let peer_matches = match existing_peer_json.with_exposed(|existing_peer_json| {
                    if let Some(peer_obj) = existing_peer_json.get("peer") {
                        if !peer_obj.is_null() {
                            let existing_cid_hex =
                                peer_obj.get("cid").and_then(|v| v.as_str()).unwrap_or("");
                            let existing_cid =
                                SecretBytes::from_hex(existing_cid_hex.trim()).ok()?;
                            let incoming_cid =
                                SecretBytes::from_hex(peer.cid_hex.expose().trim()).ok()?;
                            return Some(existing_cid.expose_as_slice() == incoming_cid.expose_as_slice());
                        }
                    }
                    Some(true)
                }) {
                    Some(v) => v,
                    None => return err_resp(id, "peer_state_corrupt"),
                };

                if !peer_matches {
                    return err_resp(id, "peer_already_set_mismatch");
                }

                let sj = match SecretJson::from_bytes(row.self_state.expose_as_slice()) {
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
        match gen_self_state() {
            Ok((contact_id, self_json)) => (contact_id, self_json),
            Err(_) => return internal_err(id),
        }
    };

    let peer_state = PeerState {
        v: 1,
        label: &label,
        peer: PeerStatePeer {
            cid: peer.cid_hex.expose(),
            x_pub: peer.x_pub_hex.expose(),
            k_pub: peer.k_pub_hex.expose(),
            ed_pub: peer.ed_pub_hex.expose(),
            dili_pub: peer.dili_pub_hex.expose(),

            mbox_in_pub: peer.mbox_in_pub_hex.expose(),
            mbox_out_cur_pub: peer.mbox_out_cur_pub_hex.expose(),
            mbox_out_next_pub: peer.mbox_out_next_pub_hex.expose(),
        },
    };

    let peer_json = {
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

        let my_pub = InvitePublic {
            cid_hex,
            x_pub_hex: x_pub,
            k_pub_hex: k_pub,
            ed_pub_hex: ed_pub,
            dili_pub_hex: dili_pub,

            mbox_in_pub_hex: mbox_in_pub,
            mbox_out_cur_pub_hex: mbox_out_cur_pub,
            mbox_out_next_pub_hex: mbox_out_next_pub,
        };

        match encode_invite_code(&my_pub) {
            Ok(v) => v.expose().to_owned(),
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