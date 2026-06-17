use lithium_core::{
    crypto::{kdf, keys},
    error::{LithiumError, Result},
    secrets::Byte32,
    secrets::bytes::SecretBytes,
};

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::e2e::state::{PeerState, SelfState};
use crate::labels::LABEL_MAILBOX;

pub const MAILBOX_FETCH_PAST_GENS: u64 = 2;
pub const MAILBOX_FETCH_FUTURE_GENS: u64 = 1;

fn mailbox_salt(
    sender_cid: &SecretBytes,
    receiver_cid: &SecretBytes,
    generation: u64,
) -> SecretBytes {
    let mut salt = SecretBytes::new(Vec::with_capacity(
        sender_cid.len() + receiver_cid.len() + 8,
    ));
    salt.expose_as_mut_vec()
        .extend_from_slice(sender_cid.expose_as_slice());
    salt.expose_as_mut_vec()
        .extend_from_slice(receiver_cid.expose_as_slice());
    salt.expose_as_mut_vec()
        .extend_from_slice(&generation.to_be_bytes());
    salt
}

fn derive_mailbox(
    our_priv: &Byte32,
    their_pub: &Byte32,
    sender_cid: &SecretBytes,
    receiver_cid: &SecretBytes,
    generation: u64,
) -> Result<[u8; 32]> {
    let shared = StaticSecret::from(*our_priv.as_array())
        .diffie_hellman(&PublicKey::from(*their_pub.as_array()));
    let out = kdf::derive32(
        &SecretBytes::from_slice(shared.as_bytes()),
        Some(&mailbox_salt(sender_cid, receiver_cid, generation)),
        &SecretBytes::from_slice(LABEL_MAILBOX),
    )?;
    Ok(*out.as_array())
}

fn peer_sender_pub_for_generation(peer_st: &PeerState, generation: u64) -> Result<Byte32> {
    if let Some(hex) = peer_st.mailbox.sender_pubs.get(&generation.to_string()) {
        return Byte32::from_hex(hex.trim());
    }

    let peer = peer_st
        .peer
        .as_ref()
        .ok_or_else(|| LithiumError::invalid_credentials("peer_not_set"))?;

    if generation == 0 {
        return Byte32::from_hex(peer.mbox_out_cur_pub.trim());
    }
    if generation == 1 {
        return Byte32::from_hex(peer.mbox_out_next_pub.trim());
    }

    Err(LithiumError::invalid_credentials(
        "missing_peer_mailbox_key",
    ))
}

pub fn current_outbound_mailbox_pubs(self_st: &SelfState) -> (String, String) {
    (
        self_st.mbox_out_cur_pub.clone(),
        self_st.mbox_out_next_pub.clone(),
    )
}

pub fn peer_store_mailbox_sender_keys(
    peer_st: &mut PeerState,
    generation: u64,
    cur_pub_hex: &str,
    next_pub_hex: &str,
) {
    peer_st
        .mailbox
        .sender_pubs
        .insert(generation.to_string(), cur_pub_hex.to_owned());
    peer_st.mailbox.sender_pubs.insert(
        generation.saturating_add(1).to_string(),
        next_pub_hex.to_owned(),
    );

    if let Some(peer) = peer_st.peer.as_mut() {
        peer.mbox_out_cur_pub = cur_pub_hex.to_owned();
        peer.mbox_out_next_pub = next_pub_hex.to_owned();
    }
}

pub fn ensure_mailbox_state(peer_st: &mut PeerState) -> Result<()> {
    let (cur, next) = {
        let peer = peer_st
            .peer
            .as_ref()
            .ok_or_else(|| LithiumError::json_missing_field("peer.x_pub"))?;
        (
            peer.mbox_out_cur_pub.clone(),
            peer.mbox_out_next_pub.clone(),
        )
    };

    peer_st.mailbox.sender_pubs.entry("0".into()).or_insert(cur);
    peer_st
        .mailbox
        .sender_pubs
        .entry("1".into())
        .or_insert(next);

    Ok(())
}

pub fn self_tx_generation(self_st: &SelfState) -> u64 {
    self_st.mailbox.tx_gen
}

pub fn derive_mailboxes_for_generation_from_values(
    self_st: &SelfState,
    peer_st: &PeerState,
    generation: u64,
) -> Result<([u8; 32], [u8; 32])> {
    let self_cid = SecretBytes::from_hex(self_st.cid.trim())?;
    let self_in_priv = Byte32::from_hex(self_st.mbox_in_priv.trim())?;
    let self_out_cur_priv = Byte32::from_hex(self_st.mbox_out_cur_priv.trim())?;

    let peer = peer_st
        .peer
        .as_ref()
        .ok_or_else(|| LithiumError::invalid_credentials("peer_not_set"))?;
    let peer_cid = SecretBytes::from_hex(peer.cid.trim())?;
    let peer_in_pub = Byte32::from_hex(peer.mbox_in_pub.trim())?;
    let peer_sender_pub = peer_sender_pub_for_generation(peer_st, generation)?;

    let out = derive_mailbox(
        &self_out_cur_priv,
        &peer_in_pub,
        &self_cid,
        &peer_cid,
        generation,
    )?;
    let inn = derive_mailbox(
        &self_in_priv,
        &peer_sender_pub,
        &peer_cid,
        &self_cid,
        generation,
    )?;

    Ok((out, inn))
}

pub fn mark_outbound_message_sent(self_st: &mut SelfState) -> Result<u64> {
    let rotate_every = self_st.mailbox.rotate_every.clamp(1, 4096);
    let tx_sent = self_st.mailbox.tx_sent.saturating_add(1);

    if tx_sent >= rotate_every {
        let (new_next_priv, new_next_pub) = keys::random_x25519_keypair()?;

        self_st.mailbox.tx_gen = self_st.mailbox.tx_gen.saturating_add(1);
        self_st.mailbox.tx_sent = 0;

        let promoted_priv = std::mem::take(&mut self_st.mbox_out_next_priv);
        let promoted_pub = std::mem::take(&mut self_st.mbox_out_next_pub);

        let mut retired_priv = std::mem::replace(&mut self_st.mbox_out_cur_priv, promoted_priv);
        retired_priv.zeroize();
        self_st.mbox_out_cur_pub = promoted_pub;

        self_st.mbox_out_next_priv = new_next_priv.to_hex().expose().to_owned();
        self_st.mbox_out_next_pub = new_next_pub.to_hex().expose().to_owned();

        Ok(self_st.mailbox.tx_gen)
    } else {
        self_st.mailbox.tx_sent = tx_sent;
        Ok(self_st.mailbox.tx_gen)
    }
}

pub fn note_inbound_generation_seen(peer_st: &mut PeerState, generation: u64) {
    if generation > peer_st.mailbox.peer_tx_gen_seen {
        let cur_pub = peer_st
            .mailbox
            .sender_pubs
            .get(&generation.to_string())
            .cloned();
        let next_pub = peer_st
            .mailbox
            .sender_pubs
            .get(&generation.saturating_add(1).to_string())
            .cloned();

        if let Some(peer) = peer_st.peer.as_mut() {
            if let Some(cur_pub) = cur_pub {
                peer.mbox_out_cur_pub = cur_pub;
            }
            if let Some(next_pub) = next_pub {
                peer.mbox_out_next_pub = next_pub;
            }
        }

        peer_st.mailbox.peer_tx_gen_seen = generation;
    }
}

pub fn inbound_fetch_generations(peer_st: &PeerState) -> Vec<u64> {
    let seen = peer_st.mailbox.peer_tx_gen_seen;
    let start = seen.saturating_sub(MAILBOX_FETCH_PAST_GENS);
    let end = seen.saturating_add(MAILBOX_FETCH_FUTURE_GENS);
    (start..=end).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::invite_codec::gen_self_state;
    use crate::e2e::state::PeerIdentity;
    use lithium_core::crypto::keys;

    fn hex32() -> String {
        keys::random_32().unwrap().to_hex().expose().to_owned()
    }

    fn x_pub_hex() -> String {
        let (_, p) = keys::random_x25519_keypair().unwrap();
        p.to_hex().expose().to_owned()
    }

    fn make_self() -> SelfState {
        let (_cid, st) = gen_self_state().unwrap();
        st
    }

    fn make_peer() -> PeerState {
        let mut p = PeerState::empty();
        p.peer = Some(PeerIdentity {
            cid: hex32(),
            x_pub: x_pub_hex(),
            k_pub: hex32(),
            ed_pub: hex32(),
            dili_pub: hex32(),
            mbox_in_pub: x_pub_hex(),
            mbox_out_cur_pub: x_pub_hex(),
            mbox_out_next_pub: x_pub_hex(),
        });
        p
    }

    fn set_peer_mailbox(p: &mut PeerState, seen: u64, pubs: &[(&str, &str)]) {
        p.mailbox.peer_tx_gen_seen = seen;
        for (k, v) in pubs {
            p.mailbox
                .sender_pubs
                .insert((*k).to_owned(), (*v).to_owned());
        }
    }

    #[test]
    fn ensure_mailbox_initializes_peer_fields() {
        let mut p = make_peer();
        ensure_mailbox_state(&mut p).unwrap();
        assert!(
            !p.mailbox.sender_pubs.is_empty(),
            "ensure must seed sender_pubs 0/1"
        );
    }

    #[test]
    fn ensure_mailbox_idempotent() {
        let mut p = make_peer();
        ensure_mailbox_state(&mut p).unwrap();
        let before = p.mailbox.sender_pubs.clone();
        ensure_mailbox_state(&mut p).unwrap();
        assert_eq!(p.mailbox.sender_pubs, before);
    }

    #[test]
    fn ensure_mailbox_state_fails_without_peer() {
        let mut p = PeerState::empty();
        assert!(ensure_mailbox_state(&mut p).is_err());
    }

    #[test]
    fn self_tx_generation_zero_initially() {
        let st = make_self();
        assert_eq!(self_tx_generation(&st), 0);
    }

    #[test]
    fn current_outbound_mailbox_pubs_returns_both_keys() {
        let st = make_self();
        let (cur, next) = current_outbound_mailbox_pubs(&st);
        assert!(!cur.is_empty());
        assert!(!next.is_empty());
        assert_ne!(cur, next);
    }

    #[test]
    fn mark_outbound_message_sent_increments_tx_sent() {
        let mut st = make_self();
        let mbox_gen = mark_outbound_message_sent(&mut st).unwrap();
        assert_eq!(mbox_gen, 0, "generation should still be 0 before rotate");
        assert_eq!(st.mailbox.tx_sent, 1);
    }

    #[test]
    fn mark_outbound_message_sent_rotates_on_threshold() {
        let mut st = make_self();
        st.mailbox.rotate_every = 2;
        mark_outbound_message_sent(&mut st).unwrap();
        let mbox_gen = mark_outbound_message_sent(&mut st).unwrap();
        assert_eq!(mbox_gen, 1, "generation should advance to 1 after rotation");
        assert_eq!(st.mailbox.tx_gen, 1);
        assert_eq!(st.mailbox.tx_sent, 0);
    }

    #[test]
    fn mark_outbound_rotates_cur_to_next() {
        let mut st = make_self();
        let next_pub_before = st.mbox_out_next_pub.clone();
        st.mailbox.rotate_every = 1;
        mark_outbound_message_sent(&mut st).unwrap();
        assert_eq!(
            st.mbox_out_cur_pub, next_pub_before,
            "next becomes cur after rotation"
        );
    }

    #[test]
    fn note_inbound_generation_seen_updates_peer_seen() {
        let mut p = make_peer();
        set_peer_mailbox(&mut p, 0, &[]);
        note_inbound_generation_seen(&mut p, 3);
        assert_eq!(p.mailbox.peer_tx_gen_seen, 3);
    }

    #[test]
    fn note_inbound_generation_seen_ignores_older_generation() {
        let mut p = make_peer();
        set_peer_mailbox(&mut p, 5, &[]);
        note_inbound_generation_seen(&mut p, 2);
        assert_eq!(p.mailbox.peer_tx_gen_seen, 5);
    }

    #[test]
    fn inbound_fetch_generations_initial_state() {
        let mut p = make_peer();
        set_peer_mailbox(&mut p, 0, &[]);
        assert_eq!(inbound_fetch_generations(&p), vec![0, 1]);
    }

    #[test]
    fn inbound_fetch_generations_with_seen() {
        let mut p = make_peer();
        set_peer_mailbox(&mut p, 5, &[]);
        assert_eq!(inbound_fetch_generations(&p), vec![3, 4, 5, 6]);
    }

    #[test]
    fn inbound_fetch_generations_no_underflow() {
        let mut p = make_peer();
        set_peer_mailbox(&mut p, 1, &[]);
        assert_eq!(inbound_fetch_generations(&p), vec![0, 1, 2]);
    }

    #[test]
    fn peer_store_mailbox_sender_keys_stores_both() {
        let mut p = make_peer();
        let cur = hex32();
        let next = hex32();
        peer_store_mailbox_sender_keys(&mut p, 2, &cur, &next);
        assert_eq!(
            p.mailbox.sender_pubs.get("2").map(String::as_str),
            Some(cur.as_str())
        );
        assert_eq!(
            p.mailbox.sender_pubs.get("3").map(String::as_str),
            Some(next.as_str())
        );
    }

    #[test]
    fn peer_store_mailbox_sender_keys_overwrites_existing_generation() {
        let mut p = make_peer();
        set_peer_mailbox(&mut p, 0, &[("5", "old_pub")]);
        let new_cur = hex32();
        let new_next = hex32();
        peer_store_mailbox_sender_keys(&mut p, 5, &new_cur, &new_next);
        assert_eq!(
            p.mailbox.sender_pubs.get("5").map(String::as_str),
            Some(new_cur.as_str())
        );
        assert_eq!(
            p.mailbox.sender_pubs.get("6").map(String::as_str),
            Some(new_next.as_str())
        );
    }

    #[test]
    fn peer_store_mailbox_sender_keys_also_updates_peer_object() {
        let mut p = make_peer();
        let cur = hex32();
        let next = hex32();
        peer_store_mailbox_sender_keys(&mut p, 0, &cur, &next);
        assert_eq!(p.peer.as_ref().unwrap().mbox_out_cur_pub, cur);
        assert_eq!(p.peer.as_ref().unwrap().mbox_out_next_pub, next);
    }

    #[test]
    fn mark_outbound_multiple_rotations_gen_sequence() {
        let mut st = make_self();
        st.mailbox.rotate_every = 1;
        assert_eq!(mark_outbound_message_sent(&mut st).unwrap(), 1);
        assert_eq!(mark_outbound_message_sent(&mut st).unwrap(), 2);
        assert_eq!(mark_outbound_message_sent(&mut st).unwrap(), 3);
        assert_eq!(st.mailbox.tx_gen, 3);
        assert_eq!(st.mailbox.tx_sent, 0);
    }

    #[test]
    fn mark_outbound_cur_key_advances_every_rotation() {
        let mut st = make_self();
        st.mailbox.rotate_every = 1;
        let pub_before_1 = st.mbox_out_cur_pub.clone();
        mark_outbound_message_sent(&mut st).unwrap();
        let pub_after_1 = st.mbox_out_cur_pub.clone();
        mark_outbound_message_sent(&mut st).unwrap();
        let pub_after_2 = st.mbox_out_cur_pub.clone();
        assert_ne!(pub_before_1, pub_after_1);
        assert_ne!(pub_after_1, pub_after_2);
        assert_ne!(pub_before_1, pub_after_2);
    }

    #[test]
    fn mark_outbound_next_priv_regenerated_each_rotation() {
        let mut st = make_self();
        st.mailbox.rotate_every = 1;
        let next_pub_0 = st.mbox_out_next_pub.clone();
        mark_outbound_message_sent(&mut st).unwrap();
        let next_pub_1 = st.mbox_out_next_pub.clone();
        mark_outbound_message_sent(&mut st).unwrap();
        let next_pub_2 = st.mbox_out_next_pub.clone();
        assert_ne!(next_pub_0, next_pub_1);
        assert_ne!(next_pub_1, next_pub_2);
    }

    #[test]
    fn note_inbound_updates_peer_keys_from_sender_pubs() {
        let mut p = make_peer();
        let gen3_pub = hex32();
        let gen4_pub = hex32();
        set_peer_mailbox(&mut p, 0, &[("3", &gen3_pub), ("4", &gen4_pub)]);

        note_inbound_generation_seen(&mut p, 3);

        let peer = p.peer.as_ref().unwrap();
        assert_eq!(peer.mbox_out_cur_pub, gen3_pub);
        assert_eq!(peer.mbox_out_next_pub, gen4_pub);
        assert_eq!(p.mailbox.peer_tx_gen_seen, 3);
    }

    #[test]
    fn note_inbound_does_not_regress_peer_keys() {
        let mut p = make_peer();
        let original_pub = p.peer.as_ref().unwrap().mbox_out_cur_pub.clone();
        let p3 = hex32();
        let p4 = hex32();
        set_peer_mailbox(&mut p, 5, &[("3", &p3), ("4", &p4)]);
        note_inbound_generation_seen(&mut p, 3);
        assert_eq!(p.peer.as_ref().unwrap().mbox_out_cur_pub, original_pub);
    }

    #[test]
    fn derive_mailboxes_different_in_and_out() {
        let st = make_self();
        let mut p = make_peer();
        ensure_mailbox_state(&mut p).unwrap();
        let (out, inn) = derive_mailboxes_for_generation_from_values(&st, &p, 0).unwrap();
        assert_ne!(out, inn);
    }

    #[test]
    fn derive_mailboxes_generation_0_vs_1_differ() {
        let st = make_self();
        let mut p = make_peer();
        ensure_mailbox_state(&mut p).unwrap();
        let (out0, _) = derive_mailboxes_for_generation_from_values(&st, &p, 0).unwrap();
        let (out1, _) = derive_mailboxes_for_generation_from_values(&st, &p, 1).unwrap();
        assert_ne!(out0, out1);
    }

    #[test]
    fn derive_mailboxes_deterministic() {
        let st = make_self();
        let mut p = make_peer();
        ensure_mailbox_state(&mut p).unwrap();
        let (out1, in1) = derive_mailboxes_for_generation_from_values(&st, &p, 0).unwrap();
        let (out2, in2) = derive_mailboxes_for_generation_from_values(&st, &p, 0).unwrap();
        assert_eq!(out1, out2);
        assert_eq!(in1, in2);
    }

    #[test]
    fn inbound_fetch_generations_seen_large_value() {
        let mut p = make_peer();
        set_peer_mailbox(&mut p, 100, &[]);
        assert_eq!(inbound_fetch_generations(&p), vec![98, 99, 100, 101]);
    }

    #[test]
    fn inbound_fetch_generations_no_mailbox_defaults() {
        let p = make_peer();
        assert_eq!(inbound_fetch_generations(&p), vec![0, 1]);
    }
}
