use std::{sync::Arc, time::Duration};

use serde_json::json;
use tokio::sync::mpsc::error::TrySendError;

use lithium_proto::contract::protocol::field;

use lithium_core::secrets::{Byte32, SecretString};

use crate::e2e::SelfState;
use crate::e2e::drop_bootstrap_private_if_established;
use crate::{
    commands::contact_mailbox::{
        derive_mailboxes_for_generation_from_values, ensure_mailbox_state,
        mark_outbound_message_sent, self_tx_generation,
    },
    commands::stored_message,
    db::repo::DaemonDbExt,
    e2e::{
        PREKEY_TARGET, PeerState, encrypt_for_peer, ensure_self_keyring, gen_local_prekey_material,
        local_public_prekeys, pack_wire, peer_need_recover, peer_pick_remote_prekey,
        peer_remove_remote_prekey, prekeys_mark_advertised, prekeys_should_advertise,
    },
    ipc::types::{IpcResponse, crypto_err, err_resp, storage_err},
    state::DaemonState,
    traffic::PendingSend,
};

const PREKEY_TTL: Duration = Duration::from_secs(30 * 24 * 3600);

async fn ensure_local_prekeys<P: lithium_core::keys::MkProvider + Send + Sync + 'static>(
    dm: &lithium_proto::db::DataManager<P>,
    contact_id: &[u8],
    self_st: &mut SelfState,
) -> Result<(), String> {
    while self_st.prekeys_local_public.len() < PREKEY_TARGET {
        let (id_hex, priv_blob, public_item) = match gen_local_prekey_material() {
            Ok(v) => v,
            Err(_) => return Err("crypto_error".into()),
        };

        let id = match Byte32::from_hex(id_hex.trim()) {
            Ok(v) => v,
            Err(_) => return Err("invalid_prekey_id".into()),
        };

        if dm
            .put_prekey(
                contact_id.to_vec(),
                id.as_slice().to_vec(),
                priv_blob,
                PREKEY_TTL,
            )
            .await
            .is_err()
        {
            return Err("storage_error".into());
        }

        self_st.prekeys_local_public.push(public_item);
    }

    Ok(())
}

pub async fn handle(
    id: u64,
    contact_id_hex: String,
    plaintext: SecretString,
    state: Arc<DaemonState>,
) -> IpcResponse {
    let Some(dm) = state.local_db.lock().await.clone() else {
        return err_resp(id, "storage_locked");
    };
    if state.proto.lock().await.is_none() {
        return err_resp(id, "keystore_locked");
    }
    let Some(send_tx) = state.send_tx.lock().await.clone() else {
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

    if !peer_st.peer_is_set() {
        return err_resp(id, "peer_not_set");
    }

    if ensure_self_keyring(&mut self_st).is_err() {
        return crypto_err(id);
    }

    if ensure_mailbox_state(&mut peer_st).is_err() {
        return crypto_err(id);
    }

    if let Err(e) = ensure_local_prekeys(dm.as_ref(), contact_id.as_slice(), &mut self_st).await {
        return err_resp(id, e);
    }

    let advertise = if prekeys_should_advertise(&self_st) {
        local_public_prekeys(&self_st)
    } else {
        Vec::new()
    };

    let use_recovery = peer_need_recover(&peer_st);

    if use_recovery && peer_pick_remote_prekey(&peer_st).is_none() {
        return err_resp(id, "need_recover_but_no_remote_prekey");
    }

    let used_recovery_prekey = if use_recovery {
        peer_pick_remote_prekey(&peer_st).map(|(id_hex, _, _)| id_hex)
    } else {
        None
    };

    let mailbox_gen = self_tx_generation(&self_st);

    let (mbox_out, _mbox_in) =
        match derive_mailboxes_for_generation_from_values(&self_st, &peer_st, mailbox_gen) {
            Ok(v) => v,
            Err(_) => return crypto_err(id),
        };
    let mailbox_hex = hex::encode(mbox_out);

    let (wire, ui_meta) = match encrypt_for_peer(
        &mut self_st,
        &mut peer_st,
        plaintext.expose().as_bytes(),
        stored_message::KIND_TEXT,
        &advertise,
        use_recovery,
        mailbox_gen,
    ) {
        Ok(v) => v,
        Err(_) => return crypto_err(id),
    };

    let content_hex = hex::encode(pack_wire(&wire));

    let body = json!({
        field::MAILBOX: mailbox_hex,
        field::CONTENT: content_hex
    });

    if let Err(e) = send_tx.try_send(PendingSend::new(body)) {
        return match e {
            TrySendError::Full(_) => err_resp(id, "send_queue_full"),
            TrySendError::Closed(_) => err_resp(id, "keystore_locked"),
        };
    }

    if let Some(id_hex) = used_recovery_prekey {
        peer_remove_remote_prekey(&mut peer_st, &id_hex);
    }

    if !advertise.is_empty() {
        prekeys_mark_advertised(&mut self_st);
    }

    if mark_outbound_message_sent(&mut self_st).is_err() {
        return crypto_err(id);
    }

    drop_bootstrap_private_if_established(&mut self_st, &peer_st);

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

    let stored =
        match stored_message::encode(plaintext.expose(), &ui_meta, &mailbox_hex, mailbox_gen) {
            Ok(v) => v,
            Err(_) => return err_resp(id, "json_error"),
        };

    if dm
        .add_message(contact_id.clone(), mbox_out.to_vec(), 1, stored, None)
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
