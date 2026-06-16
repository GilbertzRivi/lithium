use std::sync::Arc;

use serde_json::json;

use lithium_core::secrets::SecretString;

use crate::e2e::state::PeerIdentity;
use crate::e2e::{PeerState, SelfState};
use crate::{
    commands::invite_codec::{
        decode_contact_id_hex, decode_invite_code, encode_invite_code, gen_self_state,
        invite_public_from_self,
    },
    db::repo::DaemonDbExt,
    ipc::types::{err_resp, internal_err, storage_err, IpcResponse},
    state::DaemonState,
};

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

    let (contact_id, self_st) = if let Some(cid_hex) = contact_id_opt {
        let cid_ss = SecretString::new(cid_hex);
        let contact_id = match decode_contact_id_hex(&cid_ss) {
            Ok(v) => v,
            Err(_) => return err_resp(id, "invalid_contact_id"),
        };

        match dm.get_contact(contact_id.as_slice()).await {
            Ok(Some(row)) => {
                let existing_peer = match PeerState::from_bytes(row.peer_state.expose_as_slice()) {
                    Ok(v) => v,
                    Err(_) => return err_resp(id, "peer_state_corrupt"),
                };

                if existing_peer.peer_is_set() {
                    return err_resp(id, "peer_already_set");
                }

                let st = match SelfState::from_bytes(row.self_state.expose_as_slice()) {
                    Ok(v) => v,
                    Err(_) => return err_resp(id, "self_state_corrupt"),
                };

                (contact_id, st)
            }
            Ok(None) => return err_resp(id, "contact_not_found"),
            Err(_) => return storage_err(id),
        }
    } else {
        should_return_my_code = true;
        match gen_self_state() {
            Ok((contact_id, self_st)) => (contact_id, self_st),
            Err(_) => return internal_err(id),
        }
    };

    let mut peer_st = match PeerState::from_bytes(b"{}") {
        Ok(v) => v,
        Err(_) => return internal_err(id),
    };
    peer_st.label = label;
    peer_st.peer = Some(PeerIdentity {
        cid: peer.cid_hex.expose().to_owned(),
        x_pub: peer.x_pub_hex.expose().to_owned(),
        k_pub: peer.k_pub_hex.expose().to_owned(),
        ed_pub: peer.ed_pub_hex.expose().to_owned(),
        dili_pub: peer.dili_pub_hex.expose().to_owned(),
        mbox_in_pub: peer.mbox_in_pub_hex.expose().to_owned(),
        mbox_out_cur_pub: peer.mbox_out_cur_pub_hex.expose().to_owned(),
        mbox_out_next_pub: peer.mbox_out_next_pub_hex.expose().to_owned(),
    });

    let self_bytes = match self_st.to_secret_bytes() {
        Ok(v) => v,
        Err(_) => return err_resp(id, "json_error"),
    };

    let peer_bytes = match peer_st.to_secret_bytes() {
        Ok(v) => v,
        Err(_) => return err_resp(id, "json_error"),
    };

    if dm
        .upsert_contact(contact_id.clone(), peer_bytes, self_bytes)
        .await
        .is_err()
    {
        return storage_err(id);
    }

    let my_code = if should_return_my_code {
        let my_pub = match invite_public_from_self(&self_st) {
            Ok(v) => v,
            Err(_) => return err_resp(id, "self_state_corrupt"),
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
