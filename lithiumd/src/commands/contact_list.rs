// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use sea_orm::{EntityTrait, QueryOrder};
use serde_json::json;
use std::sync::Arc;

use crate::e2e::PeerState;
use crate::{
    db::models::contacts,
    ipc::types::{IpcResponse, err_resp, storage_err},
    labels::AAD_CONTACT_PEER,
    state::DaemonState,
};

pub async fn handle(id: u64, state: Arc<DaemonState>) -> IpcResponse {
    let Some(dm) = state.local_db.lock().await.clone() else {
        return err_resp(id, "storage_locked");
    };

    let rows = match contacts::Entity::find()
        .order_by_asc(contacts::Column::Id)
        .all(dm.db())
        .await
    {
        Ok(v) => v,
        Err(_) => return storage_err(id),
    };

    let mut out = Vec::with_capacity(rows.len());

    for r in rows {
        let peer_pt = match dm
            .decrypt_db_blob(
                &lithium_core::secrets::bytes::SecretBytes::new(r.peer_state_enc.clone()),
                &lithium_core::secrets::bytes::SecretBytes::from_slice(AAD_CONTACT_PEER),
            )
            .await
        {
            Ok(v) => v,
            Err(_) => return storage_err(id),
        };

        let peer_st = match PeerState::from_bytes(peer_pt.expose_as_slice()) {
            Ok(v) => v,
            Err(_) => return err_resp(id, "peer_state_corrupt"),
        };

        out.push(json!({
            "contact_id": hex::encode(r.contact_id),
            "label": peer_st.label,
            "peer_set": peer_st.peer_is_set(),
        }));
    }

    IpcResponse {
        id,
        ok: true,
        result: Some(json!({ "contacts": out })),
        error: None,
    }
}
