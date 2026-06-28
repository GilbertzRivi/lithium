// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use serde_json::json;

use crate::{
    commands::stored_message,
    db::repo::DaemonDbExt,
    ipc::types::{IpcResponse, err_resp, storage_err},
    state::DaemonState,
};

pub async fn handle(
    id: u64,
    contact_id_hex: String,
    limit: Option<u64>,
    before_id: Option<i64>,
    state: Arc<DaemonState>,
) -> IpcResponse {
    let Some(dm) = state.local_db.lock().await.clone() else {
        return err_resp(id, "storage_locked");
    };

    let contact_id = match hex::decode(contact_id_hex.trim()) {
        Ok(v) => v,
        Err(_) => return err_resp(id, "invalid_contact_id"),
    };

    let limit = limit.unwrap_or(50).clamp(1, 200);
    let fetch_n = limit + 1;

    let mut rows = match dm
        .list_messages_page(contact_id.as_slice(), before_id, fetch_n)
        .await
    {
        Ok(v) => v,
        Err(_) => return storage_err(id),
    };

    let has_more = rows.len() as u64 > limit;
    if has_more {
        rows.truncate(limit as usize);
    }

    let next_before_id = rows.last().map(|m| m.id);

    rows.reverse();

    let mut out = Vec::with_capacity(rows.len());

    for row in rows {
        let (kind, text, ui) = match stored_message::decode(row.content.expose_as_slice()) {
            Some(d) => (
                d.kind.unwrap_or_else(|| "unknown".to_string()),
                d.text,
                if d.ui.is_null() { json!({}) } else { d.ui },
            ),
            None => ("unknown".to_string(), None, json!({})),
        };

        out.push(json!({
            "id": row.id,
            "direction": if row.direction == 1 { "out" } else { "in" },
            "kind": kind,
            "text": text,
            "ui": ui,
            "created_at": row.created_at.to_rfc3339()
        }));
    }

    IpcResponse {
        id,
        ok: true,
        result: Some(json!({
            "messages": out,
            "paging": {
                "has_more": has_more,
                "next_before_id": next_before_id
            }
        })),
        error: None,
    }
}
