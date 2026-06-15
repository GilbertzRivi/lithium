use std::sync::Arc;

use serde_json::json;
use x25519_dalek::{PublicKey, StaticSecret};

use lithium_core::{
    crypto::kdf,
    error::LithiumError,
    secrets::{Byte32, SecretJson},
    secrets::bytes::SecretBytes,
};

use crate::state_fields as sf;
use crate::{
    db::repo::DaemonDbExt,
    ipc::types::{err_resp, internal_err, storage_err, IpcResponse},
    labels::{PARTY_TRANSCRIPT_LABEL, VERIFY_EMOJI_LABEL},
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

fn decode_hex_field(s: &str) -> Result<Vec<u8>, LithiumError> {
    hex::decode(s.trim()).map_err(|_| LithiumError::internal())
}

#[allow(clippy::too_many_arguments)]
fn party_transcript(
    cid: &[u8], x_pub: &[u8], ed_pub: &[u8], dili_pub: &[u8], k_pub: &[u8],
    mbox_in: &[u8], mbox_cur: &[u8], mbox_next: &[u8],
) -> Result<[u8; 32], LithiumError> {
    let mut bundle = Vec::new();
    for part in [cid, x_pub, ed_pub, dili_pub, k_pub, mbox_in, mbox_cur, mbox_next] {
        bundle.extend_from_slice(part);
    }
    let derived = kdf::derive32(
        &SecretBytes::from_slice(&bundle),
        None,
        &SecretBytes::from_slice(PARTY_TRANSCRIPT_LABEL),
    )?;
    Ok(*derived.as_array())
}

fn compute_verify_emojis(
    self_v: &SecretJson,
    peer_v: &SecretJson,
) -> Result<Vec<&'static str>, LithiumError> {
    let self_x_priv = Byte32::from_hex(self_field(self_v, "x_priv")?.trim())?;

    let self_cid = decode_hex_field(&self_field(self_v, sf::CID)?)?;
    let self_x_pub = decode_hex_field(&self_field(self_v, "x_pub")?)?;
    let self_ed_pub = decode_hex_field(&self_field(self_v, sf::ED_PUB)?)?;
    let self_dili_pub = decode_hex_field(&self_field(self_v, sf::DILI_PUB)?)?;
    let self_k_pub = decode_hex_field(&self_field(self_v, "k_pub")?)?;
    let self_mbox_in_pub = decode_hex_field(&self_field(self_v, "mbox_in_pub")?)?;
    let self_mbox_out_cur_pub = decode_hex_field(&self_field(self_v, "mbox_out_cur_pub")?)?;
    let self_mbox_out_next_pub = decode_hex_field(&self_field(self_v, "mbox_out_next_pub")?)?;

    let peer_x_pub_bytes = decode_hex_field(&peer_field(peer_v, "x_pub")?)?;
    let peer_cid = decode_hex_field(&peer_field(peer_v, sf::CID)?)?;
    let peer_ed_pub = decode_hex_field(&peer_field(peer_v, sf::ED_PUB)?)?;
    let peer_dili_pub = decode_hex_field(&peer_field(peer_v, sf::DILI_PUB)?)?;
    let peer_k_pub = decode_hex_field(&peer_field(peer_v, "k_pub")?)?;
    let peer_mbox_in_pub = decode_hex_field(&peer_field(peer_v, "mbox_in_pub")?)?;
    let peer_mbox_out_cur_pub = decode_hex_field(&peer_field(peer_v, "mbox_out_cur_pub")?)?;
    let peer_mbox_out_next_pub = decode_hex_field(&peer_field(peer_v, "mbox_out_next_pub")?)?;

    let peer_x_pub_arr: [u8; 32] = peer_x_pub_bytes
        .as_slice()
        .try_into()
        .map_err(|_| LithiumError::internal())?;

    let ss = StaticSecret::from(*self_x_priv.as_array())
        .diffie_hellman(&PublicKey::from(peer_x_pub_arr));

    let t_self = party_transcript(
        &self_cid, &self_x_pub, &self_ed_pub, &self_dili_pub, &self_k_pub,
        &self_mbox_in_pub, &self_mbox_out_cur_pub, &self_mbox_out_next_pub,
    )?;
    let t_peer = party_transcript(
        &peer_cid, &peer_x_pub_bytes, &peer_ed_pub, &peer_dili_pub, &peer_k_pub,
        &peer_mbox_in_pub, &peer_mbox_out_cur_pub, &peer_mbox_out_next_pub,
    )?;

    let (t_a, t_b) = if t_self <= t_peer { (t_self, t_peer) } else { (t_peer, t_self) };

    let mut info = Vec::with_capacity(32 + 64);
    info.extend_from_slice(VERIFY_EMOJI_LABEL);
    info.extend_from_slice(&t_a);
    info.extend_from_slice(&t_b);

    let derived = kdf::derive32(
        &SecretBytes::from_slice(ss.as_bytes()),
        None,
        &SecretBytes::new(info),
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

#[cfg(test)]
mod tests {
    use super::*;
    use lithium_core::crypto::keys;
    use serde_json::Value;

    fn hex32() -> String {
        keys::random_32().unwrap().to_hex().expose().to_owned()
    }

    fn x_pair() -> (String, String) {
        let (priv_fb, pub_fb) = keys::random_x25519_keypair().unwrap();
        (
            priv_fb.to_hex().expose().to_owned(),
            pub_fb.to_hex().expose().to_owned(),
        )
    }

    fn bundle(x_pub: &str) -> Value {
        json!({
            "cid": hex32(),
            "x_pub": x_pub,
            "ed_pub": hex32(),
            "dili_pub": hex32(),
            "k_pub": hex32(),
            "mbox_in_pub": hex32(),
            "mbox_out_cur_pub": hex32(),
            "mbox_out_next_pub": hex32(),
        })
    }

    fn self_view(x_priv: &str, b: &Value) -> SecretJson {
        let mut v = b.clone();
        v["x_priv"] = json!(x_priv);
        SecretJson::from(v)
    }

    fn peer_view(b: &Value) -> SecretJson {
        SecretJson::from(json!({ "peer": b }))
    }

    #[test]
    fn both_parties_derive_identical_emojis() {
        let (a_priv, a_pub) = x_pair();
        let (b_priv, b_pub) = x_pair();
        let alice = bundle(&a_pub);
        let bob = bundle(&b_pub);

        let alice_side =
            compute_verify_emojis(&self_view(&a_priv, &alice), &peer_view(&bob)).unwrap();
        let bob_side =
            compute_verify_emojis(&self_view(&b_priv, &bob), &peer_view(&alice)).unwrap();

        assert_eq!(alice_side.len(), 6);
        assert_eq!(
            alice_side, bob_side,
            "both sides must read the same SAS from the same key bundles"
        );
    }

    #[test]
    fn swapping_any_non_x_peer_key_changes_emojis() {
        let (a_priv, a_pub) = x_pair();
        let (_b_priv, b_pub) = x_pair();
        let alice = bundle(&a_pub);
        let bob = bundle(&b_pub);

        let baseline =
            compute_verify_emojis(&self_view(&a_priv, &alice), &peer_view(&bob)).unwrap();

        for field in [
            "cid",
            "ed_pub",
            "dili_pub",
            "k_pub",
            "mbox_in_pub",
            "mbox_out_cur_pub",
            "mbox_out_next_pub",
        ] {
            let mut tampered = bob.clone();
            tampered[field] = json!(hex32());
            let got =
                compute_verify_emojis(&self_view(&a_priv, &alice), &peer_view(&tampered)).unwrap();
            assert_ne!(baseline, got, "swapping peer.{field} must change the SAS");
        }
    }
}
