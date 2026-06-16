use std::sync::Arc;

use serde_json::json;

use lithium_core::secrets::SecretString;

use crate::e2e::PeerState;
use crate::{
    commands::invite_codec::{
        decode_contact_id_hex, encode_invite_code, gen_self_state, invite_public_from_self,
    },
    db::repo::DaemonDbExt,
    ipc::types::{err_resp, internal_err, storage_err, IpcResponse},
    state::DaemonState,
};

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

        let self_st = match crate::e2e::SelfState::from_bytes(row.self_state.expose_as_slice()) {
            Ok(v) => v,
            Err(_) => return err_resp(id, "self_state_corrupt"),
        };

        let pub_code = match invite_public_from_self(&self_st) {
            Ok(v) => v,
            Err(_) => return err_resp(id, "self_state_corrupt"),
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

    let (contact_id, self_st) = match gen_self_state() {
        Ok(v) => v,
        Err(_) => return internal_err(id),
    };

    let peer_st = PeerState::empty();

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
