use std::sync::Arc;

use serde_json::{json, Value};

use lithium_core::{
    secrets::{SecretJson},
    secrets::bytes::SecretBytes,
};

use crate::{
    commands::contact_mailbox::{
        derive_mailboxes_for_generation_from_values,
        ensure_mailbox_state,
        inbound_fetch_generations,
        note_inbound_generation_seen,
    },
    commands::e2e::{
        decrypt_for_prekey,
        decrypt_for_us,
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
    mailbox_gen: u64,
) -> Result<SecretBytes, serde_json::Error> {
    let v = json!({
        "v": 1,
        "kind": "text/utf8",
        "text": text,
        "ui": ui_meta,
        "transport": {
            "mailbox": mailbox_hex,
            "mailbox_gen": mailbox_gen
        }
    });

    let mut out = SecretBytes::new(Vec::new());
    serde_json::to_writer(out.as_mut_vec(), &v)?;
    Ok(out)
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

    let mut self_v = match SecretJson::from_bytes(row.self_state.as_slice()) {
        Ok(v) => v,
        Err(_) => return err_resp(id, "self_state_corrupt"),
    };
    let mut peer_v = match SecretJson::from_bytes(row.peer_state.as_slice()) {
        Ok(v) => v,
        Err(_) => return err_resp(id, "peer_state_corrupt"),
    };

    if ensure_self_keyring(&mut self_v).is_err() {
        return crypto_err(id);
    }

    self_v.with_exposed_mut(|self_state| {
        peer_v.with_exposed_mut(|peer_state| {
            ensure_mailbox_state(self_state, peer_state);
        });
    });

    {
        let new_self_bytes = match self_v.with_exposed(|v| -> std::result::Result<SecretBytes, serde_json::Error> {
            let mut out = SecretBytes::new(Vec::new());
            serde_json::to_writer(out.as_mut_vec(), v)?;
            Ok(out)
        }) {
            Ok(v) => v,
            Err(_) => return err_resp(id, "json_error"),
        };

        let new_peer_bytes = match peer_v.with_exposed(|v| -> std::result::Result<SecretBytes, serde_json::Error> {
            let mut out = SecretBytes::new(Vec::new());
            serde_json::to_writer(out.as_mut_vec(), v)?;
            Ok(out)
        }) {
            Ok(v) => v,
            Err(_) => return err_resp(id, "json_error"),
        };

        if dm
            .upsert_contact(
                contact_id.clone(),
                row.server.clone(),
                new_peer_bytes,
                new_self_bytes,
            )
            .await
            .is_err()
        {
            return storage_err(id);
        }
    }

    let generations = peer_v.with_exposed(inbound_fetch_generations);
    let mut out = Vec::new();

    for mailbox_gen in generations {
        let (_mbox_out, mbox_in) = match self_v.with_exposed(|self_state| {
            peer_v.with_exposed(|peer_state| {
                derive_mailboxes_for_generation_from_values(self_state, peer_state, mailbox_gen)
            })
        }) {
            Ok(v) => v,
            Err(_) => return crypto_err(id),
        };
        let mailbox_hex = hex::encode(&mbox_in);

        let resp = match proto
            .send(Endpoint::MsgFetch, json!({ "mailbox": mailbox_hex }), json!({}))
            .await
        {
            Ok(v) => v,
            Err(_) => return protocol_err(id),
        };

        if let Some(arr) = resp.body.get("data").and_then(|v| v.as_array()) {
            for it in arr {
                let Some(h) = it.as_str() else {
                    continue;
                };

                let raw = match SecretBytes::from_hex(h.trim()) {
                    Ok(v) => v,
                    Err(_) => {
                        out.push(json!({
                            "ok": false,
                            "err": "invalid_hex",
                            "mailbox_gen": mailbox_gen
                        }));
                        continue;
                    }
                };

                let w = match unpack_wire(raw.as_slice()) {
                    Ok(v) => v,
                    Err(_) => {
                        out.push(json!({
                            "ok": false,
                            "err": "bad_wire",
                            "mailbox_gen": mailbox_gen
                        }));
                        continue;
                    }
                };

                match decrypt_for_us(&mut self_v, &mut peer_v, &w) {
                    Ok((pt, ui)) => {
                        let seen_gen = ui
                            .get("mailbox_gen")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(mailbox_gen);

                        peer_v.with_exposed_mut(|peer_state| {
                            note_inbound_generation_seen(peer_state, seen_gen);
                        });

                        let text = match String::from_utf8(pt) {
                            Ok(v) => v,
                            Err(_) => {
                                out.push(json!({
                                    "ok": false,
                                    "err": "invalid_utf8",
                                    "mailbox_gen": mailbox_gen
                                }));
                                continue;
                            }
                        };

                        let stored = match build_stored_message(&text, &ui, &mailbox_hex, seen_gen) {
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
                            "text": text,
                            "mailbox_gen": seen_gen
                        }));
                    }
                    Err(_) => {
                        let prekey_blob = match dm.take_prekey(&w.to_id).await {
                            Ok(v) => v,
                            Err(_) => {
                                out.push(json!({
                                    "ok": false,
                                    "err": "prekey_lookup_failed",
                                    "mailbox_gen": mailbox_gen
                                }));
                                continue;
                            }
                        };

                        let Some(blob) = prekey_blob else {
                            peer_set_need_recover(&mut peer_v, true);
                            out.push(json!({
                                "ok": false,
                                "err": "to_id_unknown",
                                "mailbox_gen": mailbox_gen
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

                                let seen_gen = ui
                                    .get("mailbox_gen")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(mailbox_gen);

                                peer_v.with_exposed_mut(|peer_state| {
                                    note_inbound_generation_seen(peer_state, seen_gen);
                                });

                                let text = match String::from_utf8(pt) {
                                    Ok(v) => v,
                                    Err(_) => {
                                        out.push(json!({
                                            "ok": false,
                                            "err": "invalid_utf8",
                                            "mailbox_gen": mailbox_gen
                                        }));
                                        continue;
                                    }
                                };

                                let stored =
                                    match build_stored_message(&text, &ui, &mailbox_hex, seen_gen) {
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
                                    "text": text,
                                    "mailbox_gen": seen_gen
                                }));
                            }
                            Err(_) => {
                                peer_set_need_recover(&mut peer_v, true);
                                out.push(json!({
                                    "ok": false,
                                    "err": "prekey_recovery_failed",
                                    "mailbox_gen": mailbox_gen
                                }));
                            }
                        }
                    }
                }
            }
        }
    }

    let new_self_bytes = match self_v.with_exposed(|v| -> std::result::Result<SecretBytes, serde_json::Error> {
        let mut out = SecretBytes::new(Vec::new());
        serde_json::to_writer(out.as_mut_vec(), v)?;
        Ok(out)
    }) {
        Ok(v) => v,
        Err(_) => return err_resp(id, "json_error"),
    };

    let new_peer_bytes = match peer_v.with_exposed(|v| -> std::result::Result<SecretBytes, serde_json::Error> {
        let mut out = SecretBytes::new(Vec::new());
        serde_json::to_writer(out.as_mut_vec(), v)?;
        Ok(out)
    }) {
        Ok(v) => v,
        Err(_) => return err_resp(id, "json_error"),
    };

    if dm
        .upsert_contact(
            contact_id.clone(),
            row.server.clone(),
            new_peer_bytes,
            new_self_bytes,
        )
        .await
        .is_err()
    {
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