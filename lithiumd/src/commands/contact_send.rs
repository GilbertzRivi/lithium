use std::{sync::Arc, time::Duration};

use serde_json::{json, Value};

use lithium_core::{
    secrets::{Byte32, SecretJson, SecretString},
    secrets::bytes::SecretBytes,
};

use crate::{
    commands::contact_mailbox::{
        derive_mailboxes_for_generation_from_values,
        ensure_mailbox_state,
        mark_outbound_message_sent,
        self_tx_generation,
    },
    commands::e2e::{
        encrypt_for_peer,
        ensure_self_keyring,
        gen_local_prekey_material,
        local_public_prekeys,
        pack_wire,
        peer_need_recover,
        peer_pick_remote_prekey,
        peer_remove_remote_prekey,
        prekeys_mark_advertised,
        prekeys_should_advertise,
        PREKEY_TARGET,
    },
    db::repo::DaemonDbExt,
    ipc::types::{crypto_err, err_resp, protocol_err, storage_err, IpcResponse},
    protocol_manager::Endpoint,
    state::DaemonState,
};
use crate::commands::e2e::drop_bootstrap_private_if_established;

const PREKEY_TTL: Duration = Duration::from_secs(30 * 24 * 3600);

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

async fn ensure_local_prekeys<P: lithium_core::keys::MkProvider + Send + Sync + 'static>(
    dm: &lithium_core::db::manager::DataManager<P>,
    contact_id: &[u8],
    self_v: &mut SecretJson,
) -> Result<(), String> {
    let mut arr = local_public_prekeys(self_v);

    while arr.len() < PREKEY_TARGET {
        let (id_hex, priv_blob, public_item) = match gen_local_prekey_material() {
            Ok(v) => v,
            Err(_) => return Err("crypto_error".into()),
        };

        let id = match Byte32::from_hex(id_hex.trim()) {
            Ok(v) => v,
            Err(_) => return Err("invalid_prekey_id".into()),
        };

        if dm
            .put_prekey(contact_id.to_vec(), id.as_slice().to_vec(), priv_blob, PREKEY_TTL)
            .await
            .is_err()
        {
            return Err("storage_error".into());
        }

        arr.push(public_item);
    }

    self_v.with_exposed_mut(|self_state| {
        self_state["prekeys_local_public"] = Value::Array(arr);
    });

    Ok(())
}

pub async fn handle(
    id: u64,
    contact_id_hex: String,
    plaintext: String,
    state: Arc<DaemonState>,
) -> IpcResponse {
    let Some(dm) = state.local_db.lock().await.clone() else {
        return err_resp(id, "storage_locked");
    };
    let Some(proto) = state.proto.lock().await.clone() else {
        return err_resp(id, "keystore_locked");
    };

    let plaintext = SecretString::new(plaintext);

    let contact_id = match hex::decode(contact_id_hex.trim()) {
        Ok(v) => v,
        Err(_) => return err_resp(id, "invalid_contact_id"),
    };
    if contact_id.len() != 32 {
        return err_resp(id, "invalid_contact_id");
    }

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

    if self_v
        .with_exposed_mut(|self_state| {
            peer_v.with_exposed_mut(|peer_state| ensure_mailbox_state(self_state, peer_state))
        })
        .is_err()
    {
        return crypto_err(id);
    }

    if let Err(e) = ensure_local_prekeys(dm.as_ref(), contact_id.as_slice(), &mut self_v).await {
        return err_resp(id, e);
    }

    let advertise = if prekeys_should_advertise(&self_v) {
        local_public_prekeys(&self_v)
    } else {
        Vec::new()
    };

    let use_recovery = peer_need_recover(&peer_v);

    if use_recovery && peer_pick_remote_prekey(&peer_v).is_none() {
        return err_resp(id, "need_recover_but_no_remote_prekey");
    }

    let used_recovery_prekey = if use_recovery {
        peer_pick_remote_prekey(&peer_v).map(|(id_hex, _, _)| id_hex)
    } else {
        None
    };

    let mailbox_gen = self_v.with_exposed(self_tx_generation);

    let (mbox_out, _mbox_in) = match self_v.with_exposed(|self_state| {
        peer_v.with_exposed(|peer_state| {
            derive_mailboxes_for_generation_from_values(self_state, peer_state, mailbox_gen)
        })
    }) {
        Ok(v) => v,
        Err(_) => return crypto_err(id),
    };
    let mailbox_hex = hex::encode(&mbox_out);

    let (wire, ui_meta) = match encrypt_for_peer(
        &mut self_v,
        &mut peer_v,
        plaintext.expose().as_bytes(),
        "text/utf8",
        &advertise,
        use_recovery,
        mailbox_gen,
    ) {
        Ok(v) => v,
        Err(_) => return crypto_err(id),
    };

    let content_hex = hex::encode(pack_wire(&wire));

    let body = json!({
        "mailbox": mailbox_hex,
        "content": content_hex
    });

    if proto.send(Endpoint::MsgSend, body, json!({})).await.is_err() {
        return protocol_err(id);
    }

    if let Some(id_hex) = used_recovery_prekey {
        peer_remove_remote_prekey(&mut peer_v, &id_hex);
    }

    if !advertise.is_empty() {
        prekeys_mark_advertised(&mut self_v);
    }

    if self_v.with_exposed_mut(mark_outbound_message_sent).is_err() {
        return crypto_err(id);
    }

    drop_bootstrap_private_if_established(&mut self_v, &peer_v);

    let new_self_bytes = match self_v.with_exposed(|v| -> Result<SecretBytes, serde_json::Error> {
        let mut out = SecretBytes::new(Vec::new());
        serde_json::to_writer(out.as_mut_vec(), v)?;
        Ok(out)
    }) {
        Ok(v) => v,
        Err(_) => return err_resp(id, "json_error"),
    };

    let new_peer_bytes = match peer_v.with_exposed(|v| -> Result<SecretBytes, serde_json::Error> {
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

    let stored = match build_stored_message(plaintext.expose(), &ui_meta, &mailbox_hex, mailbox_gen) {
        Ok(v) => v,
        Err(_) => return err_resp(id, "json_error"),
    };

    if dm
        .add_message(contact_id.clone(), mbox_out.to_vec(), 1, stored)
        .await
        .is_err()
    {
        return storage_err(id);
    }

    IpcResponse {
        id,
        ok: true,
        result: Some(json!({
            "sent": true,
            "mailbox_gen": mailbox_gen
        })),
        error: None,
    }
}