use std::sync::Arc;

use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde_json::json;

use crate::{
    db::models::{contacts, messages, prekeys},
    ipc::types::{IpcResponse, err_resp, storage_err},
    state::DaemonState,
};

pub async fn handle(id: u64, contact_id_hex: String, state: Arc<DaemonState>) -> IpcResponse {
    let Some(dm) = state.local_db.lock().await.clone() else {
        return err_resp(id, "storage_locked");
    };

    let contact_id = match hex::decode(contact_id_hex.trim()) {
        Ok(v) => v,
        Err(_) => return err_resp(id, "invalid_contact_id"),
    };

    let exists = match contacts::Entity::find()
        .filter(contacts::Column::ContactId.eq(contact_id.clone()))
        .one(dm.db())
        .await
    {
        Ok(v) => v.is_some(),
        Err(_) => return storage_err(id),
    };

    if !exists {
        return err_resp(id, "contact_not_found");
    }

    if prekeys::Entity::delete_many()
        .filter(prekeys::Column::ContactId.eq(contact_id.clone()))
        .exec(dm.db())
        .await
        .is_err()
    {
        return storage_err(id);
    }

    if messages::Entity::delete_many()
        .filter(messages::Column::ContactId.eq(contact_id.clone()))
        .exec(dm.db())
        .await
        .is_err()
    {
        return storage_err(id);
    }

    if contacts::Entity::delete_many()
        .filter(contacts::Column::ContactId.eq(contact_id.clone()))
        .exec(dm.db())
        .await
        .is_err()
    {
        return storage_err(id);
    }

    IpcResponse {
        id,
        ok: true,
        result: Some(json!({
            "forgot": true
        })),
        error: None,
    }
}
