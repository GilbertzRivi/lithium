use std::sync::Arc;

use serde_json::json;

use crate::e2e::PeerState;
use crate::{
    commands::invite_codec::{encode_invite_code, gen_self_state, invite_public_from_self},
    db::repo::DaemonDbExt,
    ipc::types::{IpcResponse, err_resp, internal_err, storage_err},
    state::DaemonState,
};

pub async fn handle(
    id: u64,
    commitment: String,
    label: String,
    state: Arc<DaemonState>,
) -> IpcResponse {
    let dm_opt = state.local_db.lock().await.clone();
    let Some(dm) = dm_opt else {
        return err_resp(id, "storage_locked");
    };

    let commitment = match hex::decode(commitment.trim()) {
        Ok(b) if b.len() == 32 => hex::encode(b),
        _ => return err_resp(id, "invalid_commitment"),
    };

    let (contact_id, self_st) = match gen_self_state() {
        Ok(v) => v,
        Err(_) => return internal_err(id),
    };

    let mut peer_st = PeerState::empty();
    peer_st.label = label;
    peer_st.pending_commit = Some(commitment);

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

    let pub_code = match invite_public_from_self(&self_st) {
        Ok(v) => v,
        Err(_) => return err_resp(id, "self_state_corrupt"),
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
