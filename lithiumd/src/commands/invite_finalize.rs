// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use serde_json::json;
use subtle::ConstantTimeEq;

use lithium_core::secrets::SecretString;

use crate::e2e::PeerState;
use crate::e2e::state::PeerIdentity;
use crate::{
    commands::invite_codec::{decode_contact_id_hex, decode_invite_code, invite_commitment},
    db::repo::DaemonDbExt,
    ipc::types::{IpcResponse, err_resp, storage_err},
    state::DaemonState,
};

pub async fn handle(
    id: u64,
    contact_id_hex: String,
    peer_code: String,
    state: Arc<DaemonState>,
) -> IpcResponse {
    let dm_opt = state.local_db.lock().await.clone();
    let Some(dm) = dm_opt else {
        return err_resp(id, "storage_locked");
    };

    let contact_id = match decode_contact_id_hex(&SecretString::new(contact_id_hex)) {
        Ok(v) => v,
        Err(_) => return err_resp(id, "invalid_contact_id"),
    };

    let peer_code = SecretString::new(peer_code);
    let revealed = match invite_commitment(&peer_code) {
        Ok(v) => v,
        Err(_) => return err_resp(id, "invalid_invite_code"),
    };

    let peer = match decode_invite_code(&peer_code) {
        Ok(v) => v,
        Err(_) => return err_resp(id, "invalid_invite_code"),
    };

    let row = match dm.get_contact(contact_id.as_slice()).await {
        Ok(Some(v)) => v,
        Ok(None) => return err_resp(id, "contact_not_found"),
        Err(_) => return storage_err(id),
    };

    let mut peer_st = match PeerState::from_bytes(row.peer_state.expose_as_slice()) {
        Ok(v) => v,
        Err(_) => return err_resp(id, "peer_state_corrupt"),
    };

    if peer_st.peer_is_set() {
        return err_resp(id, "peer_already_set");
    }

    let Some(expected) = peer_st.pending_commit.as_deref() else {
        return err_resp(id, "no_pending_commit");
    };

    if revealed.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 0 {
        return err_resp(id, "commitment_mismatch");
    }

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
    peer_st.pending_commit = None;

    let peer_bytes = match peer_st.to_secret_bytes() {
        Ok(v) => v,
        Err(_) => return err_resp(id, "json_error"),
    };

    if dm
        .upsert_contact(contact_id.clone(), peer_bytes, row.self_state)
        .await
        .is_err()
    {
        return storage_err(id);
    }

    IpcResponse {
        id,
        ok: true,
        result: Some(json!({ "ok": true })),
        error: None,
    }
}
