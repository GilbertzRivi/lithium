use lithium_core::{
    crypto::{kdf, keys},
    error::{LithiumError, Result},
    secrets::Byte32,
    secrets::bytes::SecretBytes,
};
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::labels::LABEL_MAILBOX;
use crate::state_fields as sf;

pub const MAILBOX_ROTATE_EVERY_DEFAULT: u64 = 32;
pub const MAILBOX_FETCH_PAST_GENS: u64 = 2;
pub const MAILBOX_FETCH_FUTURE_GENS: u64 = 1;

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
struct SelfMailbox {
    tx_gen: u64,
    tx_sent: u64,
    rotate_every: u64,
}

impl Default for SelfMailbox {
    fn default() -> Self {
        Self { tx_gen: 0, tx_sent: 0, rotate_every: MAILBOX_ROTATE_EVERY_DEFAULT }
    }
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(default)]
struct PeerMailbox {
    peer_tx_gen_seen: u64,
    sender_pubs: BTreeMap<String, String>,
}

fn load_self_mailbox(self_v: &Value) -> SelfMailbox {
    self_v.get(sf::MAILBOX).and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default()
}

fn store_self_mailbox(self_v: &mut Value, m: &SelfMailbox) {
    if let Ok(v) = serde_json::to_value(m) {
        self_v[sf::MAILBOX] = v;
    }
}

fn load_peer_mailbox(peer_v: &Value) -> PeerMailbox {
    peer_v.get(sf::MAILBOX).and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default()
}

fn store_peer_mailbox(peer_v: &mut Value, m: &PeerMailbox) {
    if let Ok(v) = serde_json::to_value(m) {
        peer_v[sf::MAILBOX] = v;
    }
}

fn get_str<'a>(v: &'a Value, key: &'static str) -> Result<&'a str> {
    v.get(key)
        .and_then(|x| x.as_str())
        .ok_or_else(|| LithiumError::json_missing_field(key))
}

fn peer_obj(peer_v: &Value) -> Option<&Value> {
    let peer = peer_v.get(sf::PEER)?;
    if peer.is_null() {
        return None;
    }
    Some(peer)
}

fn peer_obj_mut(peer_v: &mut Value) -> Option<&mut Value> {
    let peer = peer_v.get_mut(sf::PEER)?;
    if peer.is_null() {
        return None;
    }
    Some(peer)
}

fn mailbox_salt(sender_cid: &SecretBytes, receiver_cid: &SecretBytes, generation: u64) -> SecretBytes {
    let mut salt = SecretBytes::new(Vec::with_capacity(sender_cid.len() + receiver_cid.len() + 8));
    salt.expose_as_mut_vec().extend_from_slice(sender_cid.expose_as_slice());
    salt.expose_as_mut_vec().extend_from_slice(receiver_cid.expose_as_slice());
    salt.expose_as_mut_vec().extend_from_slice(&generation.to_be_bytes());
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

fn peer_sender_pub_for_generation(peer_v: &Value, generation: u64) -> Result<Byte32> {
    if let Some(hex) = load_peer_mailbox(peer_v).sender_pubs.get(&generation.to_string()) {
        return Byte32::from_hex(hex.trim());
    }

    let peer = peer_obj(peer_v).ok_or_else(|| LithiumError::invalid_credentials("peer_not_set"))?;

    if generation == 0 {
        return Byte32::from_hex(get_str(peer, sf::MBOX_OUT_CUR_PUB)?.trim());
    }
    if generation == 1 {
        return Byte32::from_hex(get_str(peer, sf::MBOX_OUT_NEXT_PUB)?.trim());
    }

    Err(LithiumError::invalid_credentials("missing_peer_mailbox_key"))
}

pub fn current_outbound_mailbox_pubs(self_v: &Value) -> Option<(String, String)> {
    let cur = self_v.get(sf::MBOX_OUT_CUR_PUB)?.as_str()?.to_owned();
    let next = self_v.get(sf::MBOX_OUT_NEXT_PUB)?.as_str()?.to_owned();
    Some((cur, next))
}

pub fn peer_store_mailbox_sender_keys(
    peer_v: &mut Value,
    generation: u64,
    cur_pub_hex: &str,
    next_pub_hex: &str,
) {
    let mut pm = load_peer_mailbox(peer_v);
    pm.sender_pubs.insert(generation.to_string(), cur_pub_hex.to_owned());
    pm.sender_pubs.insert(generation.saturating_add(1).to_string(), next_pub_hex.to_owned());
    store_peer_mailbox(peer_v, &pm);

    if let Some(peer) = peer_obj_mut(peer_v) {
        peer[sf::MBOX_OUT_CUR_PUB] = json!(cur_pub_hex);
        peer[sf::MBOX_OUT_NEXT_PUB] = json!(next_pub_hex);
    }
}

pub fn ensure_mailbox_state(self_v: &mut Value, peer_v: &mut Value) -> Result<()> {
    store_self_mailbox(self_v, &load_self_mailbox(self_v));

    // self stable receiver
    if self_v.get(sf::MBOX_IN_PRIV).is_none() {
        let legacy = get_str(self_v, sf::X_PRIV)?.to_owned();
        self_v[sf::MBOX_IN_PRIV] = json!(legacy);
    }
    if self_v.get(sf::MBOX_IN_PUB).is_none() {
        let legacy = get_str(self_v, sf::X_PUB)?.to_owned();
        self_v[sf::MBOX_IN_PUB] = json!(legacy);
    }

    // self rotating sender current
    if self_v.get(sf::MBOX_OUT_CUR_PRIV).is_none() {
        let legacy = get_str(self_v, sf::X_PRIV)?.to_owned();
        self_v[sf::MBOX_OUT_CUR_PRIV] = json!(legacy);
    }
    if self_v.get(sf::MBOX_OUT_CUR_PUB).is_none() {
        let legacy = get_str(self_v, sf::X_PUB)?.to_owned();
        self_v[sf::MBOX_OUT_CUR_PUB] = json!(legacy);
    }

    // self rotating sender next
    if self_v.get(sf::MBOX_OUT_NEXT_PRIV).is_none() || self_v.get(sf::MBOX_OUT_NEXT_PUB).is_none() {
        let (priv_fb, pub_fb) = keys::random_x25519_keypair()?;
        let priv_hex = priv_fb.to_hex();
        let pub_hex = pub_fb.to_hex();

        self_v[sf::MBOX_OUT_NEXT_PRIV] = json!(priv_hex.expose());
        self_v[sf::MBOX_OUT_NEXT_PUB] = json!(pub_hex.expose());
    }

    // najpierw odczyt peer danych bez trzymania mutable borrow
    let peer_legacy_x = peer_v
        .get(sf::PEER)
        .and_then(|v| v.get(sf::X_PUB))
        .and_then(|v| v.as_str())
        .ok_or_else(|| LithiumError::json_missing_field("peer.x_pub"))?
        .to_owned();

    let peer_in_pub = peer_v
        .get(sf::PEER)
        .and_then(|v| v.get(sf::MBOX_IN_PUB))
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| peer_legacy_x.clone());

    let peer_out_cur_pub = peer_v
        .get(sf::PEER)
        .and_then(|v| v.get(sf::MBOX_OUT_CUR_PUB))
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| peer_legacy_x.clone());

    let peer_out_next_pub = peer_v
        .get(sf::PEER)
        .and_then(|v| v.get(sf::MBOX_OUT_NEXT_PUB))
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| peer_out_cur_pub.clone());

    // teraz osobno mutujemy peer
    if let Some(peer) = peer_obj_mut(peer_v) {
        if peer.get(sf::MBOX_IN_PUB).is_none() {
            peer[sf::MBOX_IN_PUB] = json!(peer_in_pub.clone());
        }
        if peer.get(sf::MBOX_OUT_CUR_PUB).is_none() {
            peer[sf::MBOX_OUT_CUR_PUB] = json!(peer_out_cur_pub.clone());
        }
        if peer.get(sf::MBOX_OUT_NEXT_PUB).is_none() {
            peer[sf::MBOX_OUT_NEXT_PUB] = json!(peer_out_next_pub.clone());
        }
    }

    // i dopiero osobno mutujemy sender_pubs
    let mut pm = load_peer_mailbox(peer_v);
    pm.sender_pubs.entry("0".into()).or_insert(peer_out_cur_pub);
    pm.sender_pubs.entry("1".into()).or_insert(peer_out_next_pub);
    store_peer_mailbox(peer_v, &pm);

    Ok(())
}

pub fn self_tx_generation(self_v: &Value) -> u64 {
    load_self_mailbox(self_v).tx_gen
}

pub fn derive_mailboxes_for_generation_from_values(
    self_v: &Value,
    peer_v: &Value,
    generation: u64,
) -> Result<([u8; 32], [u8; 32])> {
    let self_cid = SecretBytes::from_hex(get_str(self_v, sf::CID)?.trim())?;
    let self_in_priv = Byte32::from_hex(get_str(self_v, sf::MBOX_IN_PRIV)?.trim())?;
    let self_out_cur_priv = Byte32::from_hex(get_str(self_v, sf::MBOX_OUT_CUR_PRIV)?.trim())?;

    let peer = peer_obj(peer_v).ok_or_else(|| LithiumError::invalid_credentials("peer_not_set"))?;
    let peer_cid = SecretBytes::from_hex(get_str(peer, sf::CID)?.trim())?;
    let peer_in_pub = Byte32::from_hex(get_str(peer, sf::MBOX_IN_PUB)?.trim())?;
    let peer_sender_pub = peer_sender_pub_for_generation(peer_v, generation)?;

    let out = derive_mailbox(&self_out_cur_priv, &peer_in_pub, &self_cid, &peer_cid, generation)?;
    let inn = derive_mailbox(&self_in_priv, &peer_sender_pub, &peer_cid, &self_cid, generation)?;

    Ok((out, inn))
}

pub fn mark_outbound_message_sent(self_v: &mut Value) -> Result<u64> {
    let mut m = load_self_mailbox(self_v);
    let rotate_every = m.rotate_every.clamp(1, 4096);
    let tx_sent = m.tx_sent.saturating_add(1);

    if tx_sent >= rotate_every {
        let next_cur_priv = get_str(self_v, sf::MBOX_OUT_NEXT_PRIV)?.to_owned();
        let next_cur_pub = get_str(self_v, sf::MBOX_OUT_NEXT_PUB)?.to_owned();

        let (new_next_priv, new_next_pub) = keys::random_x25519_keypair()?;

        m.tx_gen = m.tx_gen.saturating_add(1);
        m.tx_sent = 0;
        store_self_mailbox(self_v, &m);

        self_v[sf::MBOX_OUT_CUR_PRIV] = json!(next_cur_priv);
        self_v[sf::MBOX_OUT_CUR_PUB] = json!(next_cur_pub);
        self_v[sf::MBOX_OUT_NEXT_PRIV] = json!(new_next_priv.to_hex().expose());
        self_v[sf::MBOX_OUT_NEXT_PUB] = json!(new_next_pub.to_hex().expose());

        Ok(m.tx_gen)
    } else {
        m.tx_sent = tx_sent;
        let cur_gen = m.tx_gen;
        store_self_mailbox(self_v, &m);
        Ok(cur_gen)
    }
}

pub fn note_inbound_generation_seen(peer_v: &mut Value, generation: u64) {
    let mut pm = load_peer_mailbox(peer_v);

    if generation > pm.peer_tx_gen_seen {
        let cur_pub = pm.sender_pubs.get(&generation.to_string()).cloned();
        let next_pub = pm.sender_pubs.get(&generation.saturating_add(1).to_string()).cloned();

        if let Some(peer) = peer_obj_mut(peer_v) {
            if let Some(cur_pub) = cur_pub {
                peer[sf::MBOX_OUT_CUR_PUB] = json!(cur_pub);
            }
            if let Some(next_pub) = next_pub {
                peer[sf::MBOX_OUT_NEXT_PUB] = json!(next_pub);
            }
        }

        pm.peer_tx_gen_seen = generation;
        store_peer_mailbox(peer_v, &pm);
    }
}

pub fn inbound_fetch_generations(peer_v: &Value) -> Vec<u64> {
    let seen = load_peer_mailbox(peer_v).peer_tx_gen_seen;

    let start = seen.saturating_sub(MAILBOX_FETCH_PAST_GENS);
    let end = seen.saturating_add(MAILBOX_FETCH_FUTURE_GENS);
    (start..=end).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use lithium_core::crypto::keys;
    use serde_json::json;

    fn hex32() -> String {
        keys::random_32().unwrap().to_hex().expose().to_owned()
    }

    fn set_rotate(sv: &mut Value, n: u64) {
        let mut m = load_self_mailbox(sv);
        m.rotate_every = n;
        store_self_mailbox(sv, &m);
    }

    fn set_peer_mailbox(pv: &mut Value, seen: u64, pubs: &[(&str, &str)]) {
        let mut m = PeerMailbox { peer_tx_gen_seen: seen, ..Default::default() };
        for (k, v) in pubs {
            m.sender_pubs.insert((*k).to_owned(), (*v).to_owned());
        }
        store_peer_mailbox(pv, &m);
    }

    /// Minimal self_v with x_priv/x_pub and mailbox keys.
    fn make_self_v() -> Value {
        let (x_priv_fb, x_pub_fb) = keys::random_x25519_keypair().unwrap();
        let x_priv = x_priv_fb.to_hex().expose().to_owned();
        let x_pub  = x_pub_fb.to_hex().expose().to_owned();
        let (mbox_out_next_priv, mbox_out_next_pub) = keys::random_x25519_keypair().unwrap();
        json!({
            sf::CID: hex32(),
            sf::X_PRIV: x_priv,
            sf::X_PUB: x_pub,
            sf::MBOX_IN_PRIV: x_priv.clone(),
            sf::MBOX_IN_PUB: x_pub.clone(),
            sf::MBOX_OUT_CUR_PRIV: x_priv,
            sf::MBOX_OUT_CUR_PUB: x_pub,
            sf::MBOX_OUT_NEXT_PRIV: mbox_out_next_priv.to_hex().expose(),
            sf::MBOX_OUT_NEXT_PUB: mbox_out_next_pub.to_hex().expose(),
        })
    }

    /// Minimal peer_v — contains peer sub-object with x_pub, mbox_in_pub, mbox_out_*_pub.
    fn make_peer_v() -> Value {
        let (_, x_pub_fb) = keys::random_x25519_keypair().unwrap();
        let x_pub = x_pub_fb.to_hex().expose().to_owned();
        let (_, mbox_out_next_pub) = keys::random_x25519_keypair().unwrap();
        json!({
            sf::PEER: {
                sf::CID: hex32(),
                sf::X_PUB: x_pub.clone(),
                sf::MBOX_IN_PUB: x_pub.clone(),
                sf::MBOX_OUT_CUR_PUB: x_pub.clone(),
                sf::MBOX_OUT_NEXT_PUB: mbox_out_next_pub.to_hex().expose()
            }
        })
    }

    // ── ensure_mailbox_state ──────────────────────────────────────────────

    #[test]
    fn ensure_mailbox_initializes_self_tx_fields() {
        let mut sv = make_self_v();
        let mut pv = make_peer_v();
        ensure_mailbox_state(&mut sv, &mut pv).unwrap();

        assert_eq!(Some(load_self_mailbox(&sv).tx_gen), Some(0));
        assert_eq!(Some(load_self_mailbox(&sv).tx_sent), Some(0));
        assert_eq!(
            Some(load_self_mailbox(&sv).rotate_every),
            Some(MAILBOX_ROTATE_EVERY_DEFAULT)
        );
    }

    #[test]
    fn ensure_mailbox_initializes_peer_fields() {
        let mut sv = make_self_v();
        let mut pv = make_peer_v();
        ensure_mailbox_state(&mut sv, &mut pv).unwrap();

        assert!(!load_peer_mailbox(&pv).sender_pubs.is_empty(), "ensure must seed sender_pubs 0/1");
    }

    #[test]
    fn ensure_mailbox_idempotent() {
        let mut sv = make_self_v();
        let mut pv = make_peer_v();
        ensure_mailbox_state(&mut sv, &mut pv).unwrap();
        let tx_gen_before = Some(load_self_mailbox(&sv).tx_gen);
        ensure_mailbox_state(&mut sv, &mut pv).unwrap();
        assert_eq!(Some(load_self_mailbox(&sv).tx_gen), tx_gen_before);
    }

    #[test]
    fn ensure_mailbox_state_fails_without_peer_x_pub() {
        let mut sv = make_self_v();
        let mut bad_peer_v = json!({ sf::PEER: {} }); // missing x_pub
        let result = ensure_mailbox_state(&mut sv, &mut bad_peer_v);
        assert!(result.is_err());
    }

    // ── self_tx_generation ────────────────────────────────────────────────

    #[test]
    fn self_tx_generation_zero_initially() {
        let mut sv = make_self_v();
        let mut pv = make_peer_v();
        ensure_mailbox_state(&mut sv, &mut pv).unwrap();
        assert_eq!(self_tx_generation(&sv), 0);
    }

    // ── current_outbound_mailbox_pubs ─────────────────────────────────────

    #[test]
    fn current_outbound_mailbox_pubs_returns_both_keys() {
        let sv = make_self_v();
        let (cur, next) = current_outbound_mailbox_pubs(&sv).expect("must return Some");
        assert!(!cur.is_empty());
        assert!(!next.is_empty());
        assert_ne!(cur, next);
    }

    #[test]
    fn current_outbound_mailbox_pubs_missing_returns_none() {
        let sv = json!({});
        assert!(current_outbound_mailbox_pubs(&sv).is_none());
    }

    // ── mark_outbound_message_sent ────────────────────────────────────────

    #[test]
    fn mark_outbound_message_sent_increments_tx_sent() {
        let mut sv = make_self_v();
        let mut pv = make_peer_v();
        ensure_mailbox_state(&mut sv, &mut pv).unwrap();

        let mbox_gen = mark_outbound_message_sent(&mut sv).unwrap();
        assert_eq!(mbox_gen, 0, "generation should still be 0 before rotate");
        assert_eq!(Some(load_self_mailbox(&sv).tx_sent), Some(1));
    }

    #[test]
    fn mark_outbound_message_sent_rotates_on_threshold() {
        let mut sv = make_self_v();
        let mut pv = make_peer_v();
        ensure_mailbox_state(&mut sv, &mut pv).unwrap();

        // Set rotate_every = 2 to trigger rotation quickly
        set_rotate(&mut sv, 2);
        let _ = mark_outbound_message_sent(&mut sv).unwrap(); // tx_sent = 1
        let mbox_gen = mark_outbound_message_sent(&mut sv).unwrap(); // tx_sent >= 2 → rotate

        assert_eq!(mbox_gen, 1, "generation should advance to 1 after rotation");
        assert_eq!(Some(load_self_mailbox(&sv).tx_gen), Some(1));
        assert_eq!(Some(load_self_mailbox(&sv).tx_sent), Some(0));
    }

    #[test]
    fn mark_outbound_rotates_cur_to_next() {
        let mut sv = make_self_v();
        let mut pv = make_peer_v();
        ensure_mailbox_state(&mut sv, &mut pv).unwrap();

        let next_pub_before = sv[sf::MBOX_OUT_NEXT_PUB].as_str().unwrap().to_owned();
        set_rotate(&mut sv, 1);
        mark_outbound_message_sent(&mut sv).unwrap();

        let cur_pub_after = sv[sf::MBOX_OUT_CUR_PUB].as_str().unwrap().to_owned();
        assert_eq!(cur_pub_after, next_pub_before, "next becomes cur after rotation");
    }

    // ── note_inbound_generation_seen ──────────────────────────────────────

    #[test]
    fn note_inbound_generation_seen_updates_peer_seen() {
        let mut pv = make_peer_v();
        set_peer_mailbox(&mut pv, 0, &[]);

        note_inbound_generation_seen(&mut pv, 3);
        assert_eq!(load_peer_mailbox(&pv).peer_tx_gen_seen, 3);
    }

    #[test]
    fn note_inbound_generation_seen_ignores_older_generation() {
        let mut pv = make_peer_v();
        set_peer_mailbox(&mut pv, 5, &[]);

        note_inbound_generation_seen(&mut pv, 2); // older than 5
        assert_eq!(load_peer_mailbox(&pv).peer_tx_gen_seen, 5);
    }

    // ── inbound_fetch_generations ─────────────────────────────────────────

    #[test]
    fn inbound_fetch_generations_initial_state() {
        let mut pv = json!({});
        set_peer_mailbox(&mut pv, 0, &[]);
        let gens = inbound_fetch_generations(&pv);
        // seen=0 → start=max(0,0-2)=0, end=0+1=1 → [0,1]
        assert_eq!(gens, vec![0, 1]);
    }

    #[test]
    fn inbound_fetch_generations_with_seen() {
        let mut pv = json!({});
        set_peer_mailbox(&mut pv, 5, &[]);
        let gens = inbound_fetch_generations(&pv);
        // start=5-2=3, end=5+1=6 → [3,4,5,6]
        assert_eq!(gens, vec![3, 4, 5, 6]);
    }

    #[test]
    fn inbound_fetch_generations_no_underflow() {
        let mut pv = json!({});
        set_peer_mailbox(&mut pv, 1, &[]);
        let gens = inbound_fetch_generations(&pv);
        // start=max(0,1-2)=0, end=1+1=2 → [0,1,2]
        assert_eq!(gens, vec![0, 1, 2]);
    }

    // ── peer_store_mailbox_sender_keys ────────────────────────────────────

    #[test]
    fn peer_store_mailbox_sender_keys_stores_both() {
        let mut pv = make_peer_v();
        set_peer_mailbox(&mut pv, 0, &[]);

        let cur = hex32();
        let next = hex32();
        peer_store_mailbox_sender_keys(&mut pv, 2, &cur, &next);

        let map = load_peer_mailbox(&pv).sender_pubs;
        assert_eq!(map.get("2").map(String::as_str), Some(cur.as_str()));
        assert_eq!(map.get("3").map(String::as_str), Some(next.as_str()));
    }

    // ── multiple rotations ────────────────────────────────────────────────

    #[test]
    fn mark_outbound_multiple_rotations_gen_sequence() {
        let mut sv = make_self_v();
        let mut pv = make_peer_v();
        ensure_mailbox_state(&mut sv, &mut pv).unwrap();

        // rotate_every=1: every message triggers rotation
        set_rotate(&mut sv, 1);

        let g0 = mark_outbound_message_sent(&mut sv).unwrap(); // rotation: gen → 1
        assert_eq!(g0, 1);
        let g1 = mark_outbound_message_sent(&mut sv).unwrap(); // gen → 2
        assert_eq!(g1, 2);
        let g2 = mark_outbound_message_sent(&mut sv).unwrap(); // gen → 3
        assert_eq!(g2, 3);

        assert_eq!(Some(load_self_mailbox(&sv).tx_gen), Some(3));
        assert_eq!(Some(load_self_mailbox(&sv).tx_sent), Some(0));
    }

    #[test]
    fn mark_outbound_cur_key_advances_every_rotation() {
        let mut sv = make_self_v();
        let mut pv = make_peer_v();
        ensure_mailbox_state(&mut sv, &mut pv).unwrap();
        set_rotate(&mut sv, 1);

        let pub_before_1 = sv[sf::MBOX_OUT_CUR_PUB].as_str().unwrap().to_owned();
        mark_outbound_message_sent(&mut sv).unwrap();
        let pub_after_1 = sv[sf::MBOX_OUT_CUR_PUB].as_str().unwrap().to_owned();

        let pub_before_2 = pub_after_1.clone();
        mark_outbound_message_sent(&mut sv).unwrap();
        let pub_after_2 = sv[sf::MBOX_OUT_CUR_PUB].as_str().unwrap().to_owned();

        assert_ne!(pub_before_1, pub_after_1, "key must change on rotation 1");
        assert_ne!(pub_before_2, pub_after_2, "key must change on rotation 2");
        assert_ne!(pub_before_1, pub_after_2, "key after rotation 2 differs from initial");
    }

    #[test]
    fn mark_outbound_next_priv_regenerated_each_rotation() {
        let mut sv = make_self_v();
        let mut pv = make_peer_v();
        ensure_mailbox_state(&mut sv, &mut pv).unwrap();
        set_rotate(&mut sv, 1);

        let next_pub_0 = sv[sf::MBOX_OUT_NEXT_PUB].as_str().unwrap().to_owned();
        mark_outbound_message_sent(&mut sv).unwrap();
        let next_pub_1 = sv[sf::MBOX_OUT_NEXT_PUB].as_str().unwrap().to_owned();
        mark_outbound_message_sent(&mut sv).unwrap();
        let next_pub_2 = sv[sf::MBOX_OUT_NEXT_PUB].as_str().unwrap().to_owned();

        // every rotation generates a fresh next key
        assert_ne!(next_pub_0, next_pub_1);
        assert_ne!(next_pub_1, next_pub_2);
    }

    // ── negative / wrong-type state tests ────────────────────────────────

    #[test]
    fn mark_outbound_corrupt_mailbox_defaults_gracefully() {
        let mut sv = make_self_v();
        let mut pv = make_peer_v();
        ensure_mailbox_state(&mut sv, &mut pv).unwrap();

        // Non-object mailbox: load falls back to default, mark still succeeds.
        sv[sf::MAILBOX] = json!("not_a_number");
        let result = mark_outbound_message_sent(&mut sv);
        assert!(result.is_ok());
        assert_eq!(load_self_mailbox(&sv).tx_sent, 1);
    }

    #[test]
    fn mark_outbound_without_next_priv_on_rotation_fails() {
        let mut sv = make_self_v();
        let mut pv = make_peer_v();
        ensure_mailbox_state(&mut sv, &mut pv).unwrap();
        set_rotate(&mut sv, 1);

        // remove mbox_out_next_priv so rotation cannot proceed
        sv.as_object_mut().unwrap().remove(sf::MBOX_OUT_NEXT_PRIV);

        let result = mark_outbound_message_sent(&mut sv);
        assert!(result.is_err(), "rotation without next_priv must fail");
    }

    #[test]
    fn ensure_mailbox_state_partial_mailbox_fills_missing_fields() {
        let mut sv = make_self_v();
        let mut pv = make_peer_v();

        // Only tx_gen carried over; ensure must keep it and default the rest.
        store_self_mailbox(&mut sv, &SelfMailbox { tx_gen: 7, ..Default::default() });
        ensure_mailbox_state(&mut sv, &mut pv).unwrap();

        let m = load_self_mailbox(&sv);
        assert_eq!(m.tx_gen, 7);
        assert_eq!(m.tx_sent, 0);
        assert_eq!(m.rotate_every, MAILBOX_ROTATE_EVERY_DEFAULT);
    }

    #[test]
    fn ensure_mailbox_state_mailbox_is_null_reinitializes() {
        let mut sv = make_self_v();
        let mut pv = make_peer_v();
        sv[sf::MAILBOX] = json!(null);

        ensure_mailbox_state(&mut sv, &mut pv).unwrap();
        assert_eq!(Some(load_self_mailbox(&sv).tx_gen), Some(0));
    }

    #[test]
    fn ensure_mailbox_state_peer_mailbox_is_null_reinitializes() {
        let mut sv = make_self_v();
        let mut pv = make_peer_v();
        pv[sf::MAILBOX] = json!(null);

        ensure_mailbox_state(&mut sv, &mut pv).unwrap();
        assert_eq!(load_peer_mailbox(&pv).peer_tx_gen_seen, 0);
        assert!(!load_peer_mailbox(&pv).sender_pubs.is_empty());
    }

    // ── note_inbound_generation_seen updates peer keys ────────────────────

    #[test]
    fn note_inbound_updates_peer_keys_from_sender_pubs() {
        let mut pv = make_peer_v();
        let gen3_pub = hex32();
        let gen4_pub = hex32();

        set_peer_mailbox(&mut pv, 0, &[("3", &gen3_pub), ("4", &gen4_pub)]);

        note_inbound_generation_seen(&mut pv, 3);

        // peer.mbox_out_cur_pub and mbox_out_next_pub should be updated from sender_pubs
        let cur = pv[sf::PEER][sf::MBOX_OUT_CUR_PUB].as_str().unwrap();
        let next = pv[sf::PEER][sf::MBOX_OUT_NEXT_PUB].as_str().unwrap();
        assert_eq!(cur, gen3_pub, "cur_pub must be updated to gen3 key");
        assert_eq!(next, gen4_pub, "next_pub must be updated to gen4 key");
        assert_eq!(load_peer_mailbox(&pv).peer_tx_gen_seen, 3);
    }

    #[test]
    fn note_inbound_does_not_regress_peer_keys() {
        // Seen = 5, call with gen=3 (lower) → no update
        let mut pv = make_peer_v();
        let original_pub = pv[sf::PEER][sf::MBOX_OUT_CUR_PUB].as_str().unwrap().to_owned();

        let p3 = hex32();
        let p4 = hex32();
        set_peer_mailbox(&mut pv, 5, &[("3", &p3), ("4", &p4)]);

        note_inbound_generation_seen(&mut pv, 3);

        let cur = pv[sf::PEER][sf::MBOX_OUT_CUR_PUB].as_str().unwrap();
        assert_eq!(cur, original_pub, "keys must not regress to lower generation");
    }

    // ── derive_mailboxes_for_generation ───────────────────────────────────

    #[test]
    fn derive_mailboxes_different_in_and_out() {
        let mut sv = make_self_v();
        let mut pv = make_peer_v();
        ensure_mailbox_state(&mut sv, &mut pv).unwrap();

        let (out, inn) = derive_mailboxes_for_generation_from_values(&sv, &pv, 0).unwrap();

        // outbound and inbound are different ECDH combinations
        assert_ne!(out, inn, "outbound and inbound mailbox addresses must differ");
    }

    #[test]
    fn derive_mailboxes_generation_0_vs_1_differ() {
        let mut sv = make_self_v();
        let mut pv = make_peer_v();
        ensure_mailbox_state(&mut sv, &mut pv).unwrap();

        let (out0, _) = derive_mailboxes_for_generation_from_values(&sv, &pv, 0).unwrap();
        let (out1, _) = derive_mailboxes_for_generation_from_values(&sv, &pv, 1).unwrap();

        assert_ne!(out0, out1, "different generations must produce different mailbox addresses");
    }

    #[test]
    fn derive_mailboxes_deterministic() {
        let mut sv = make_self_v();
        let mut pv = make_peer_v();
        ensure_mailbox_state(&mut sv, &mut pv).unwrap();

        let (out1, in1) = derive_mailboxes_for_generation_from_values(&sv, &pv, 0).unwrap();
        let (out2, in2) = derive_mailboxes_for_generation_from_values(&sv, &pv, 0).unwrap();

        assert_eq!(out1, out2);
        assert_eq!(in1, in2);
    }

    // ── inbound_fetch_generations edge cases ──────────────────────────────

    #[test]
    fn inbound_fetch_generations_seen_large_value() {
        let mut pv = json!({});
        set_peer_mailbox(&mut pv, 100, &[]);
        let gens = inbound_fetch_generations(&pv);
        // start=100-2=98, end=100+1=101 → [98,99,100,101]
        assert_eq!(gens, vec![98, 99, 100, 101]);
    }

    #[test]
    fn inbound_fetch_generations_no_mailbox_defaults() {
        let pv = json!({});
        let gens = inbound_fetch_generations(&pv);
        // seen defaults to 0 → [0, 1]
        assert_eq!(gens, vec![0, 1]);
    }

    // ── peer_store_mailbox_sender_keys: update existing + no peer obj ─────

    #[test]
    fn peer_store_mailbox_sender_keys_overwrites_existing_generation() {
        let mut pv = make_peer_v();
        set_peer_mailbox(&mut pv, 0, &[("5", "old_pub")]);

        let new_cur = hex32();
        let new_next = hex32();
        peer_store_mailbox_sender_keys(&mut pv, 5, &new_cur, &new_next);

        let map = load_peer_mailbox(&pv).sender_pubs;
        assert_eq!(map.get("5").map(String::as_str), Some(new_cur.as_str()), "gen 5 must be overwritten");
        assert_eq!(map.get("6").map(String::as_str), Some(new_next.as_str()), "gen 6 = next must be stored");
    }

    #[test]
    fn peer_store_mailbox_sender_keys_also_updates_peer_object() {
        let mut pv = make_peer_v();
        set_peer_mailbox(&mut pv, 0, &[]);

        let cur = hex32();
        let next = hex32();
        peer_store_mailbox_sender_keys(&mut pv, 0, &cur, &next);

        // peer sub-object must also be updated
        assert_eq!(pv[sf::PEER][sf::MBOX_OUT_CUR_PUB].as_str(), Some(cur.as_str()));
        assert_eq!(pv[sf::PEER][sf::MBOX_OUT_NEXT_PUB].as_str(), Some(next.as_str()));
    }
}