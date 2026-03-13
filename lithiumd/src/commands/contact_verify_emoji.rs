use std::sync::Arc;

use serde_json::json;
use x25519_dalek::{PublicKey, StaticSecret};

use lithium_core::{
    crypto::kdf,
    error::LithiumError,
    secrets::{Byte32, SecretJson},
    secrets::bytes::SecretBytes,
};

use crate::{
    db::repo::DaemonDbExt,
    ipc::types::{err_resp, internal_err, storage_err, IpcResponse},
    state::DaemonState,
};

const VERIFY_EMOJI_TABLE: [&str; 64] = [
    "A","B","C","D","E","F","G","H",
    "J","K","L","M","N","P","Q","R",
    "S","T","U","V","W","X","Y","Z",
    "2","3","4","5","6","7","8","9",
    "!","@","#","$","%","&","*","+",
    "-","=","?","/","~","^","<",">",
    "α","β","γ","δ","λ","μ","π","σ",
    "φ","χ","ψ","ω","Δ","Σ","Φ","Ω",
];

fn peer_field(peer_v: &SecretJson, key: &'static str) -> Result<String, LithiumError> {
    peer_v.with_exposed(|v| {
        v.get("peer")
            .and_then(|p| p.get(key))
            .and_then(|x| x.as_str())
            .map(str::to_owned)
            .ok_or_else(|| LithiumError::json_missing_field(key))
    })
}

fn self_field(self_v: &SecretJson, key: &'static str) -> Result<String, LithiumError> {
    self_v.with_exposed(|v| {
        v.get(key)
            .and_then(|x| x.as_str())
            .map(str::to_owned)
            .ok_or_else(|| LithiumError::json_missing_field(key))
    })
}

fn compute_verify_emojis(
    self_v: &SecretJson,
    peer_v: &SecretJson,
) -> Result<Vec<&'static str>, LithiumError> {
    let self_x_priv = Byte32::from_hex(self_field(self_v, "x_priv")?.trim())?;
    let self_cid = Byte32::from_hex(self_field(self_v, "cid")?.trim())?;

    let peer_x_pub = Byte32::from_hex(peer_field(peer_v, "x_pub")?.trim())?;
    let peer_cid = Byte32::from_hex(peer_field(peer_v, "cid")?.trim())?;

    let ss = StaticSecret::from(*self_x_priv.as_array())
        .diffie_hellman(&PublicKey::from(*peer_x_pub.as_array()));

    let (cid_a, cid_b) = if self_cid.as_slice() <= peer_cid.as_slice() {
        (self_cid.as_slice(), peer_cid.as_slice())
    } else {
        (peer_cid.as_slice(), self_cid.as_slice())
    };

    let mut info = Vec::with_capacity(32);
    info.extend_from_slice(b"lithiumd/contact-verify-emoji/v1");
    info.extend_from_slice(cid_a);
    info.extend_from_slice(cid_b);

    let derived = kdf::derive32(
        &SecretBytes::from_slice(ss.as_bytes()),
        None,
        &SecretBytes::from_vec(info),
    )?;

    let mut out = Vec::with_capacity(6);
    for b in &derived.as_slice()[..6] {
        out.push(VERIFY_EMOJI_TABLE[*b as usize % VERIFY_EMOJI_TABLE.len()]);
    }

    Ok(out)
}

pub async fn handle(
    id: u64,
    contact_id_hex: String,
    state: Arc<DaemonState>,
) -> IpcResponse {
    let Some(dm) = state.local_db.lock().await.clone() else {
        return err_resp(id, "storage_locked");
    };

    let contact_id = match hex::decode(contact_id_hex.trim()) {
        Ok(v) => v,
        Err(_) => return err_resp(id, "invalid_contact_id"),
    };

    let row = match dm.get_contact(contact_id.as_slice()).await {
        Ok(Some(v)) => v,
        Ok(None) => return err_resp(id, "contact_not_found"),
        Err(_) => return storage_err(id),
    };

    let self_v = match SecretJson::from_bytes(row.self_state.expose_as_slice()) {
        Ok(v) => v,
        Err(_) => return err_resp(id, "self_state_corrupt"),
    };

    let peer_v = match SecretJson::from_bytes(row.peer_state.expose_as_slice()) {
        Ok(v) => v,
        Err(_) => return err_resp(id, "peer_state_corrupt"),
    };

    let peer_set = peer_v.with_exposed(|v| {
        v.get("peer").map(|p| !p.is_null()).unwrap_or(false)
    });

    if !peer_set {
        return err_resp(id, "peer_not_set");
    }

    let emojis = match compute_verify_emojis(&self_v, &peer_v) {
        Ok(v) => v,
        Err(_) => return internal_err(id),
    };

    IpcResponse {
        id,
        ok: true,
        result: Some(json!({
            "emojis": emojis
        })),
        error: None,
    }
}