use std::sync::Arc;

use serde_json::json;
use x25519_dalek::{PublicKey, StaticSecret};

use lithium_core::{
    crypto::kdf, error::LithiumError, secrets::Byte32, secrets::bytes::SecretBytes,
};

use crate::e2e::state::{PeerState, SelfState};
use crate::{
    db::repo::DaemonDbExt,
    ipc::types::{IpcResponse, err_resp, internal_err, storage_err},
    labels::{PARTY_TRANSCRIPT_LABEL, VERIFY_EMOJI_LABEL},
    state::DaemonState,
};

const VERIFY_EMOJI_TABLE: [&str; 64] = [
    "A", "B", "C", "D", "E", "F", "G", "H", "J", "K", "L", "M", "N", "P", "Q", "R", "S", "T", "U",
    "V", "W", "X", "Y", "Z", "2", "3", "4", "5", "6", "7", "8", "9", "!", "@", "#", "$", "%", "&",
    "*", "+", "-", "=", "?", "/", "~", "^", "<", ">", "α", "β", "γ", "δ", "λ", "μ", "π", "σ", "φ",
    "χ", "ψ", "ω", "Δ", "Σ", "Φ", "Ω",
];

const VERIFY_EMOJI_LEN: usize = 12;

fn decode_hex_field(s: &str) -> Result<Vec<u8>, LithiumError> {
    hex::decode(s.trim()).map_err(|_| LithiumError::internal())
}

#[allow(clippy::too_many_arguments)]
fn party_transcript(
    cid: &[u8],
    x_pub: &[u8],
    ed_pub: &[u8],
    dili_pub: &[u8],
    k_pub: &[u8],
    mbox_in: &[u8],
    mbox_cur: &[u8],
    mbox_next: &[u8],
) -> Result<[u8; 32], LithiumError> {
    let mut bundle = Vec::new();
    for part in [
        cid, x_pub, ed_pub, dili_pub, k_pub, mbox_in, mbox_cur, mbox_next,
    ] {
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
    self_st: &SelfState,
    peer_st: &PeerState,
) -> Result<Vec<&'static str>, LithiumError> {
    let peer = peer_st
        .peer
        .as_ref()
        .ok_or_else(|| LithiumError::json_missing_field("peer"))?;

    let self_x_priv = Byte32::from_hex(
        self_st
            .x_priv
            .as_ref()
            .ok_or_else(|| LithiumError::json_missing_field("x_priv"))?
            .trim(),
    )?;

    let self_cid = decode_hex_field(&self_st.cid)?;
    let self_x_pub = decode_hex_field(&self_st.x_pub)?;
    let self_ed_pub = decode_hex_field(&self_st.ed_pub)?;
    let self_dili_pub = decode_hex_field(&self_st.dili_pub)?;
    let self_k_pub = decode_hex_field(&self_st.k_pub)?;
    let self_mbox_in_pub = decode_hex_field(&self_st.mbox_in_pub)?;
    let self_mbox_out_cur_pub = decode_hex_field(&self_st.mbox_out_cur_pub)?;
    let self_mbox_out_next_pub = decode_hex_field(&self_st.mbox_out_next_pub)?;

    let peer_x_pub_bytes = decode_hex_field(&peer.x_pub)?;
    let peer_cid = decode_hex_field(&peer.cid)?;
    let peer_ed_pub = decode_hex_field(&peer.ed_pub)?;
    let peer_dili_pub = decode_hex_field(&peer.dili_pub)?;
    let peer_k_pub = decode_hex_field(&peer.k_pub)?;
    let peer_mbox_in_pub = decode_hex_field(&peer.mbox_in_pub)?;
    let peer_mbox_out_cur_pub = decode_hex_field(&peer.mbox_out_cur_pub)?;
    let peer_mbox_out_next_pub = decode_hex_field(&peer.mbox_out_next_pub)?;

    let peer_x_pub_arr: [u8; 32] = peer_x_pub_bytes
        .as_slice()
        .try_into()
        .map_err(|_| LithiumError::internal())?;

    let ss = StaticSecret::from(*self_x_priv.as_array())
        .diffie_hellman(&PublicKey::from(peer_x_pub_arr));

    let t_self = party_transcript(
        &self_cid,
        &self_x_pub,
        &self_ed_pub,
        &self_dili_pub,
        &self_k_pub,
        &self_mbox_in_pub,
        &self_mbox_out_cur_pub,
        &self_mbox_out_next_pub,
    )?;
    let t_peer = party_transcript(
        &peer_cid,
        &peer_x_pub_bytes,
        &peer_ed_pub,
        &peer_dili_pub,
        &peer_k_pub,
        &peer_mbox_in_pub,
        &peer_mbox_out_cur_pub,
        &peer_mbox_out_next_pub,
    )?;

    let (t_a, t_b) = if t_self <= t_peer {
        (t_self, t_peer)
    } else {
        (t_peer, t_self)
    };

    let mut info = Vec::with_capacity(32 + 64);
    info.extend_from_slice(VERIFY_EMOJI_LABEL);
    info.extend_from_slice(&t_a);
    info.extend_from_slice(&t_b);

    let derived = kdf::derive32(
        &SecretBytes::from_slice(ss.as_bytes()),
        None,
        &SecretBytes::new(info),
    )?;

    let mut out = Vec::with_capacity(VERIFY_EMOJI_LEN);
    for b in &derived.as_slice()[..VERIFY_EMOJI_LEN] {
        out.push(VERIFY_EMOJI_TABLE[*b as usize % VERIFY_EMOJI_TABLE.len()]);
    }

    Ok(out)
}

pub async fn handle(id: u64, contact_id_hex: String, state: Arc<DaemonState>) -> IpcResponse {
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

    let self_st = match SelfState::from_bytes(row.self_state.expose_as_slice()) {
        Ok(v) => v,
        Err(_) => return err_resp(id, "self_state_corrupt"),
    };

    let peer_st = match PeerState::from_bytes(row.peer_state.expose_as_slice()) {
        Ok(v) => v,
        Err(_) => return err_resp(id, "peer_state_corrupt"),
    };

    if !peer_st.peer_is_set() {
        return err_resp(id, "peer_not_set");
    }

    let emojis = match compute_verify_emojis(&self_st, &peer_st) {
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
    use crate::commands::invite_codec::gen_self_state;
    use crate::e2e::state::PeerIdentity;

    fn peer_identity_from(self_st: &SelfState) -> PeerIdentity {
        PeerIdentity {
            cid: self_st.cid.clone(),
            x_pub: self_st.x_pub.clone(),
            k_pub: self_st.k_pub.clone(),
            ed_pub: self_st.ed_pub.clone(),
            dili_pub: self_st.dili_pub.clone(),
            mbox_in_pub: self_st.mbox_in_pub.clone(),
            mbox_out_cur_pub: self_st.mbox_out_cur_pub.clone(),
            mbox_out_next_pub: self_st.mbox_out_next_pub.clone(),
        }
    }

    fn peer_state_with(identity: PeerIdentity) -> PeerState {
        let mut p = PeerState::empty();
        p.peer = Some(identity);
        p
    }

    #[test]
    fn both_parties_derive_identical_emojis() {
        let (_a, alice) = gen_self_state().unwrap();
        let (_b, bob) = gen_self_state().unwrap();

        let alice_side =
            compute_verify_emojis(&alice, &peer_state_with(peer_identity_from(&bob))).unwrap();
        let bob_side =
            compute_verify_emojis(&bob, &peer_state_with(peer_identity_from(&alice))).unwrap();

        assert_eq!(alice_side.len(), VERIFY_EMOJI_LEN);
        assert_eq!(alice_side, bob_side, "both sides must read the same SAS");
    }

    #[test]
    fn swapping_any_non_x_peer_key_changes_emojis() {
        let (_a, alice) = gen_self_state().unwrap();
        let (_b, bob) = gen_self_state().unwrap();
        let baseline =
            compute_verify_emojis(&alice, &peer_state_with(peer_identity_from(&bob))).unwrap();

        let bogus = || {
            lithium_core::crypto::keys::random_32()
                .unwrap()
                .to_hex()
                .expose()
                .to_owned()
        };

        let mutate: [fn(&mut PeerIdentity, String); 7] = [
            |p, v| p.cid = v,
            |p, v| p.ed_pub = v,
            |p, v| p.dili_pub = v,
            |p, v| p.k_pub = v,
            |p, v| p.mbox_in_pub = v,
            |p, v| p.mbox_out_cur_pub = v,
            |p, v| p.mbox_out_next_pub = v,
        ];

        for apply in mutate {
            let mut tampered = peer_identity_from(&bob);
            apply(&mut tampered, bogus());
            let got = compute_verify_emojis(&alice, &peer_state_with(tampered)).unwrap();
            assert_ne!(baseline, got, "swapping a peer key must change the SAS");
        }
    }
}
