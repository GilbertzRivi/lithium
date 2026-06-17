use std::sync::Arc;

use serde_json::json;

use lithium_core::{
    CryptoErrorKind, contract::protocol::field, secrets::SecretString, secrets::bytes::SecretBytes,
};

use crate::e2e::mark_bootstrap_retire_ready;
use crate::e2e::state::{MsgMeta, PeerState, SelfState};
use crate::{
    commands::contact_mailbox::{
        derive_mailboxes_for_generation_from_values, ensure_mailbox_state,
        inbound_fetch_generations, note_inbound_generation_seen,
    },
    commands::stored_message,
    db::repo::DaemonDbExt,
    e2e::{
        decrypt_for_prekey, decrypt_for_us, drop_bootstrap_private_if_established,
        ensure_self_keyring, local_remove_public_prekey, peer_set_need_recover, unpack_wire,
    },
    ipc::types::{IpcResponse, crypto_err, err_resp, protocol_err, storage_err},
    protocol_manager::Endpoint,
    state::DaemonState,
};

fn meta_mailbox_gen(ui: &serde_json::Value, fallback: u64) -> u64 {
    serde_json::from_value::<MsgMeta>(ui.clone())
        .map(|m| m.mailbox_gen)
        .unwrap_or(fallback)
}

fn meta_msg_id(ui: &serde_json::Value) -> Option<Vec<u8>> {
    serde_json::from_value::<MsgMeta>(ui.clone())
        .ok()
        .map(|m| m.msg_id)
        .filter(|s| !s.is_empty())
        .map(|s| s.into_bytes())
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
    if contact_id.len() != 32 {
        return err_resp(id, "invalid_contact_id");
    }

    let contact_lock = state.contact_fetch_lock(contact_id.as_slice()).await;
    let _contact_guard = contact_lock.lock().await;

    let row_opt = match dm.get_contact(contact_id.as_slice()).await {
        Ok(v) => v,
        Err(_) => return storage_err(id),
    };
    let Some(row) = row_opt else {
        return err_resp(id, "contact_not_found");
    };

    let mut self_st = match SelfState::from_bytes(row.self_state.expose_as_slice()) {
        Ok(v) => v,
        Err(_) => return err_resp(id, "self_state_corrupt"),
    };
    let mut peer_st = match PeerState::from_bytes(row.peer_state.expose_as_slice()) {
        Ok(v) => v,
        Err(_) => return err_resp(id, "peer_state_corrupt"),
    };

    if ensure_self_keyring(&mut self_st).is_err() {
        return crypto_err(id);
    }

    if ensure_mailbox_state(&mut peer_st).is_err() {
        return crypto_err(id);
    }

    {
        let new_self_bytes = match self_st.to_secret_bytes() {
            Ok(v) => v,
            Err(_) => return err_resp(id, "json_error"),
        };
        let new_peer_bytes = match peer_st.to_secret_bytes() {
            Ok(v) => v,
            Err(_) => return err_resp(id, "json_error"),
        };

        if dm
            .upsert_contact(contact_id.clone(), new_peer_bytes, new_self_bytes)
            .await
            .is_err()
        {
            return storage_err(id);
        }
    }

    let generations = inbound_fetch_generations(&peer_st);
    let mut out = Vec::new();

    for mailbox_gen in generations {
        let (_mbox_out, mbox_in) =
            match derive_mailboxes_for_generation_from_values(&self_st, &peer_st, mailbox_gen) {
                Ok(v) => v,
                Err(_) => continue,
            };
        let mailbox_hex = hex::encode(mbox_in);

        let resp = match proto
            .send(
                Endpoint::MsgFetch,
                json!({ field::MAILBOX: mailbox_hex }),
                json!({}),
            )
            .await
        {
            Ok(v) => v,
            Err(_) => return protocol_err(id),
        };

        if let Some(arr) = resp.body.get(field::DATA).and_then(|v| v.as_array()) {
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

                let w = match unpack_wire(raw.expose_as_slice()) {
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

                match decrypt_for_us(&mut self_st, &mut peer_st, &w) {
                    Ok((pt, ui)) => {
                        let seen_gen = meta_mailbox_gen(&ui, mailbox_gen);

                        note_inbound_generation_seen(&mut peer_st, seen_gen);

                        let text = match SecretString::from_utf8_vec(pt) {
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

                        let stored = match stored_message::encode(
                            text.expose(),
                            &ui,
                            &mailbox_hex,
                            seen_gen,
                        ) {
                            Ok(v) => v,
                            Err(_) => return err_resp(id, "json_error"),
                        };

                        let msg_id = meta_msg_id(&ui);

                        match dm
                            .add_message(contact_id.clone(), mbox_in.to_vec(), 0, stored, msg_id)
                            .await
                        {
                            Ok(true) => {}
                            Ok(false) => {
                                out.push(json!({
                                    "ok": false,
                                    "err": "duplicate",
                                    "mailbox_gen": seen_gen
                                }));
                                continue;
                            }
                            Err(_) => return storage_err(id),
                        }

                        out.push(json!({
                            "ok": true,
                            "ui": ui,
                            "text": text.expose(),
                            "mailbox_gen": seen_gen
                        }));
                    }
                    Err(err) => {
                        if matches!(&err.kind, CryptoErrorKind::InvalidCredentials { msg } if *msg == "potentially_harmful_message")
                        {
                            out.push(json!({
                                "ok": false,
                                "err": "potentially_harmful_message",
                                "mailbox_gen": mailbox_gen
                            }));
                            continue;
                        }

                        if !matches!(&err.kind, CryptoErrorKind::InvalidCredentials { msg } if *msg == "to_id_unknown")
                        {
                            out.push(json!({
                                "ok": false,
                                "err": "decrypt_failed",
                                "mailbox_gen": mailbox_gen
                            }));
                            continue;
                        }

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
                            peer_set_need_recover(&mut peer_st, true);
                            out.push(json!({
                                "ok": false,
                                "err": "to_id_unknown",
                                "mailbox_gen": mailbox_gen
                            }));
                            continue;
                        };

                        match decrypt_for_prekey(&mut peer_st, &w, &blob) {
                            Ok((pt, mut ui)) => {
                                local_remove_public_prekey(&mut self_st, &hex::encode(w.to_id));
                                peer_set_need_recover(&mut peer_st, false);
                                mark_bootstrap_retire_ready(&mut self_st);
                                drop_bootstrap_private_if_established(&mut self_st, &peer_st);

                                if let Some(obj) = ui.as_object_mut() {
                                    obj.insert("recovered".into(), json!(true));
                                }

                                let seen_gen = meta_mailbox_gen(&ui, mailbox_gen);

                                note_inbound_generation_seen(&mut peer_st, seen_gen);

                                let text = match SecretString::from_utf8_vec(pt) {
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

                                let stored = match stored_message::encode(
                                    text.expose(),
                                    &ui,
                                    &mailbox_hex,
                                    seen_gen,
                                ) {
                                    Ok(v) => v,
                                    Err(_) => return err_resp(id, "json_error"),
                                };

                                let msg_id = meta_msg_id(&ui);

                                match dm
                                    .add_message(
                                        contact_id.clone(),
                                        mbox_in.to_vec(),
                                        0,
                                        stored,
                                        msg_id,
                                    )
                                    .await
                                {
                                    Ok(true) => {}
                                    Ok(false) => {
                                        out.push(json!({
                                            "ok": false,
                                            "err": "duplicate",
                                            "mailbox_gen": seen_gen
                                        }));
                                        continue;
                                    }
                                    Err(_) => return storage_err(id),
                                }

                                out.push(json!({
                                    "ok": true,
                                    "ui": ui,
                                    "text": text.expose(),
                                    "mailbox_gen": seen_gen
                                }));
                            }
                            Err(err) => {
                                if matches!(&err.kind, CryptoErrorKind::InvalidCredentials { msg } if *msg == "potentially_harmful_message")
                                {
                                    out.push(json!({
                                        "ok": false,
                                        "err": "potentially_harmful_message",
                                        "mailbox_gen": mailbox_gen
                                    }));
                                    continue;
                                }

                                peer_set_need_recover(&mut peer_st, true);
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

    let new_self_bytes = match self_st.to_secret_bytes() {
        Ok(v) => v,
        Err(_) => return err_resp(id, "json_error"),
    };
    let new_peer_bytes = match peer_st.to_secret_bytes() {
        Ok(v) => v,
        Err(_) => return err_resp(id, "json_error"),
    };

    if dm
        .upsert_contact(contact_id.clone(), new_peer_bytes, new_self_bytes)
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
