use std::sync::Arc;
use serde_json::json;
use sea_orm::{EntityTrait, QueryOrder};

use lithium_core::secrets::SecretJson;

use crate::{
    db::models::contacts,
    ipc::types::{err_resp, storage_err, IpcResponse},
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
        let peer_pt = match dm.decrypt_db_blob(
            &lithium_core::secrets::bytes::SecretBytes::new(r.peer_state_enc.clone()),
            &lithium_core::secrets::bytes::SecretBytes::from_slice(b"lithiumd/contact-peer/v1"),
        ).await {
            Ok(v) => v,
            Err(_) => return storage_err(id),
        };

        let peer_json = match SecretJson::from_vec(peer_pt.expose_as_slice().to_vec()) {
            Ok(v) => v,
            Err(_) => return err_resp(id, "peer_state_corrupt"),
        };

        let label = peer_json.with_exposed(|v| {
            v.get("label").and_then(|x| x.as_str()).unwrap_or("").to_string()
        });

        let peer_set = peer_json.with_exposed(|v| {
            v.get("peer").map(|p| !p.is_null()).unwrap_or(false)
        });

        let peer_cid = peer_json.with_exposed(|v| {
            v.get("peer")
                .and_then(|p| p.get("cid"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string()
        });

        out.push(json!({
            "contact_id": hex::encode(r.contact_id),
            "label": label,
            "peer_set": peer_set,
            "peer_cid": peer_cid
        }));
    }

    IpcResponse {
        id,
        ok: true,
        result: Some(json!({ "contacts": out })),
        error: None,
    }
}
