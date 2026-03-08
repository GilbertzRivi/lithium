use std::sync::Arc;

use serde_json::{json, Value};

use lithium_core::secrets::bytes::SecretBytes;

use crate::{
    commands::contact_mailbox::derive_mailboxes,
    commands::e2e::{
        decrypt_for_prekey,
        decrypt_for_us,
        ensure_peer_e2e,
        ensure_self_keyring,
        local_remove_public_prekey,
        peer_set_need_recover,
        unpack_wire,
    },
    db::repo::DaemonDbExt,
    ipc::types::{crypto_err, err_resp, protocol_err, storage_err, IpcResponse},
    protocol_manager::Endpoint,
    state::DaemonState,
};

fn build_stored_message(
    text: &str,
    ui_meta: &Value,
    mailbox_hex: &str,
) -> Result<SecretBytes, serde_json::Error> {
    let v = json!({
        "v": 1,
        "kind": "text/utf8",
        "text": text,
        "ui": ui_meta,
        "transport": {
            "mailbox": mailbox_hex
        }
    });
    serde_json::to_vec(&v).map(SecretBytes::from_vec)
}

pub async fn handle(id: u64, contact_id_hex: String, state: Arc<DaemonState>) -> IpcResponse {
    let Some(dm) = state.local_db.lock().await.clone() else {
        return err_resp(id, "storage_locked");
    };
    let Some(proto) = state.proto.lock().await.clone() else {
        return err_resp(id, "keystore_locked");
    };

    let contact_id = match hex::decode(contact_id_hex.trim()) {
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

    let self_state_bytes = row.self_state.as_slice().to_vec();
    let peer_state_bytes = row.peer_state.as_slice().to_vec();

    let (_mbox_out, mbox_in) = match derive_mailboxes(&self_state_bytes, &peer_state_bytes) {
        Ok(v) => v,
        Err(_) => return crypto_err(id),
    };
    let mailbox_hex = hex::encode(&mbox_in);

    let mut self_v: Value = match serde_json::from_slice(&self_state_bytes) {
        Ok(v) => v,
        Err(_) => return err_resp(id, "self_state_corrupt"),
    };
    let mut peer_v: Value = match serde_json::from_slice(&peer_state_bytes) {
        Ok(v) => v,
        Err(_) => return err_resp(id, "peer_state_corrupt"),
    };

    if ensure_self_keyring(&mut self_v).is_err() {
        return crypto_err(id);
    }
    if ensure_peer_e2e(&mut peer_v).is_err() {
        return crypto_err(id);
    }

    {
        let new_self_bytes = match serde_json::to_vec(&self_v) {
            Ok(v) => v,
            Err(_) => return err_resp(id, "json_error"),
        };
        let new_peer_bytes = match serde_json::to_vec(&peer_v) {
            Ok(v) => v,
            Err(_) => return err_resp(id, "json_error"),
        };

        if dm.upsert_contact(
            contact_id.clone(),
            row.server.clone(),
            SecretBytes::from_vec(new_peer_bytes),
            SecretBytes::from_vec(new_self_bytes),
        ).await.is_err() {
            return storage_err(id);
        }
    }

    let resp = match proto
        .send(Endpoint::MsgFetch, json!({ "mailbox": mailbox_hex }), json!({}))
        .await
    {
        Ok(v) => v,
        Err(_) => return protocol_err(id),
    };

    let mut out = Vec::new();

    if let Some(arr) = resp.body.get("data").and_then(|v| v.as_array()) {
        for it in arr {
            let Some(h) = it.as_str() else {
                continue;
            };

            let raw = match hex::decode(h) {
                Ok(v) => v,
                Err(_) => {
                    out.push(json!({
                        "ok": false,
                        "err": "invalid_hex"
                    }));
                    continue;
                }
            };

            let w = match unpack_wire(&raw) {
                Ok(v) => v,
                Err(_) => {
                    out.push(json!({
                        "ok": false,
                        "err": "bad_wire"
                    }));
                    continue;
                }
            };

            match decrypt_for_us(&mut self_v, &mut peer_v, &w) {
                Ok((pt, ui)) => {
                    let text = match String::from_utf8(pt.clone()) {
                        Ok(v) => v,
                        Err(_) => {
                            out.push(json!({
                                "ok": false,
                                "err": "invalid_utf8"
                            }));
                            continue;
                        }
                    };

                    let stored = match build_stored_message(&text, &ui, &mailbox_hex) {
                        Ok(v) => v,
                        Err(_) => return err_resp(id, "json_error"),
                    };

                    if dm
                        .add_message(contact_id.clone(), mbox_in.to_vec(), 0, stored)
                        .await
                        .is_err()
                    {
                        return storage_err(id);
                    }

                    out.push(json!({
                        "ok": true,
                        "ui": ui,
                        "text": text
                    }));
                }
                Err(_) => {
                    let prekey_blob = match dm.take_prekey(&w.to_id).await {
                        Ok(v) => v,
                        Err(_) => {
                            out.push(json!({
                                "ok": false,
                                "err": "prekey_lookup_failed"
                            }));
                            continue;
                        }
                    };

                    let Some(blob) = prekey_blob else {
                        peer_set_need_recover(&mut peer_v, true);
                        out.push(json!({
                            "ok": false,
                            "err": "to_id_unknown"
                        }));
                        continue;
                    };

                    match decrypt_for_prekey(&mut peer_v, &w, &blob) {
                        Ok((pt, mut ui)) => {
                            local_remove_public_prekey(&mut self_v, &hex::encode(w.to_id));
                            peer_set_need_recover(&mut peer_v, false);

                            if let Some(obj) = ui.as_object_mut() {
                                obj.insert("recovered".into(), json!(true));
                            }

                            let text = match String::from_utf8(pt.clone()) {
                                Ok(v) => v,
                                Err(_) => {
                                    out.push(json!({
                                        "ok": false,
                                        "err": "invalid_utf8"
                                    }));
                                    continue;
                                }
                            };

                            let stored = match build_stored_message(&text, &ui, &mailbox_hex) {
                                Ok(v) => v,
                                Err(_) => return err_resp(id, "json_error"),
                            };

                            if dm
                                .add_message(contact_id.clone(), mbox_in.to_vec(), 0, stored)
                                .await
                                .is_err()
                            {
                                return storage_err(id);
                            }

                            out.push(json!({
                                "ok": true,
                                "ui": ui,
                                "text": text
                            }));
                        }
                        Err(_) => {
                            peer_set_need_recover(&mut peer_v, true);
                            out.push(json!({
                                "ok": false,
                                "err": "prekey_recovery_failed"
                            }));
                        }
                    }
                }
            }
        }
    }

    let new_self_bytes = match serde_json::to_vec(&self_v) {
        Ok(v) => v,
        Err(_) => return err_resp(id, "json_error"),
    };
    let new_peer_bytes = match serde_json::to_vec(&peer_v) {
        Ok(v) => v,
        Err(_) => return err_resp(id, "json_error"),
    };

    if dm.upsert_contact(
        contact_id.clone(),
        row.server.clone(),
        SecretBytes::from_vec(new_peer_bytes),
        SecretBytes::from_vec(new_self_bytes),
    ).await.is_err() {
        return storage_err(id);
    }

    IpcResponse {
        id,
        ok: true,
        result: Some(json!({
            "messages": out
        })),
        error: None,
    }
}
