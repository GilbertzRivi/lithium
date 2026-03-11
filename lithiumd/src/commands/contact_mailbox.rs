use lithium_core::{
    crypto::{kdf, keys},
    error::{LithiumError, Result},
    secrets::Byte32,
    secrets::bytes::SecretBytes,
};
use serde_json::{json, Map, Value};
use x25519_dalek::{PublicKey, StaticSecret};

const LABEL_MAILBOX: &[u8] = b"lithium/mbox/address/v1";

pub const MAILBOX_ROTATE_EVERY_DEFAULT: u64 = 32;
pub const MAILBOX_FETCH_PAST_GENS: u64 = 2;
pub const MAILBOX_FETCH_FUTURE_GENS: u64 = 1;

fn get_str<'a>(v: &'a Value, key: &'static str) -> Result<&'a str> {
    v.get(key)
        .and_then(|x| x.as_str())
        .ok_or_else(|| LithiumError::json_missing_field(key))
}

fn peer_obj(peer_v: &Value) -> Option<&Value> {
    let peer = peer_v.get("peer")?;
    if peer.is_null() {
        return None;
    }
    Some(peer)
}

fn peer_obj_mut(peer_v: &mut Value) -> Option<&mut Value> {
    let peer = peer_v.get_mut("peer")?;
    if peer.is_null() {
        return None;
    }
    Some(peer)
}

fn sender_pub_map(peer_v: &Value) -> Option<&Map<String, Value>> {
    peer_v
        .get("mailbox")
        .and_then(|v| v.get("sender_pubs"))
        .and_then(|v| v.as_object())
}

fn sender_pub_map_mut(peer_v: &mut Value) -> Option<&mut Map<String, Value>> {
    peer_v
        .get_mut("mailbox")
        .and_then(|v| v.get_mut("sender_pubs"))
        .and_then(|v| v.as_object_mut())
}

fn mailbox_salt(sender_cid: &SecretBytes, receiver_cid: &SecretBytes, generation: u64) -> SecretBytes {
    let mut salt = SecretBytes::new(Vec::with_capacity(sender_cid.len() + receiver_cid.len() + 8));
    salt.as_mut_vec().extend_from_slice(sender_cid.as_slice());
    salt.as_mut_vec().extend_from_slice(receiver_cid.as_slice());
    salt.as_mut_vec().extend_from_slice(&generation.to_be_bytes());
    salt
}

fn derive_outbound_mailbox(
    sender_priv: &Byte32,
    receiver_pub: &Byte32,
    sender_cid: &SecretBytes,
    receiver_cid: &SecretBytes,
    generation: u64,
) -> Result<[u8; 32]> {
    let sk = StaticSecret::from(*sender_priv.as_array());
    let pk = PublicKey::from(*receiver_pub.as_array());
    let shared = sk.diffie_hellman(&pk);

    let out = kdf::derive32(
        &SecretBytes::from_slice(shared.as_bytes()),
        Some(&mailbox_salt(sender_cid, receiver_cid, generation)),
        &SecretBytes::from_slice(LABEL_MAILBOX),
    )?;

    Ok(*out.as_array())
}

fn derive_inbound_mailbox(
    receiver_priv: &Byte32,
    sender_pub: &Byte32,
    sender_cid: &SecretBytes,
    receiver_cid: &SecretBytes,
    generation: u64,
) -> Result<[u8; 32]> {
    let sk = StaticSecret::from(*receiver_priv.as_array());
    let pk = PublicKey::from(*sender_pub.as_array());
    let shared = sk.diffie_hellman(&pk);

    let out = kdf::derive32(
        &SecretBytes::from_slice(shared.as_bytes()),
        Some(&mailbox_salt(sender_cid, receiver_cid, generation)),
        &SecretBytes::from_slice(LABEL_MAILBOX),
    )?;

    Ok(*out.as_array())
}

fn peer_sender_pub_for_generation(peer_v: &Value, generation: u64) -> Result<Byte32> {
    if let Some(map) = sender_pub_map(peer_v) {
        if let Some(v) = map.get(&generation.to_string()).and_then(|v| v.as_str()) {
            return Byte32::from_hex(v.trim());
        }
    }

    let peer = peer_obj(peer_v).ok_or_else(|| LithiumError::invalid_credentials("peer_not_set"))?;

    if generation == 0 {
        return Byte32::from_hex(get_str(peer, "mbox_out_cur_pub")?.trim());
    }
    if generation == 1 {
        return Byte32::from_hex(get_str(peer, "mbox_out_next_pub")?.trim());
    }

    Err(LithiumError::invalid_credentials("missing_peer_mailbox_key"))
}

pub fn current_outbound_mailbox_pubs(self_v: &Value) -> Option<(String, String)> {
    let cur = self_v.get("mbox_out_cur_pub")?.as_str()?.to_owned();
    let next = self_v.get("mbox_out_next_pub")?.as_str()?.to_owned();
    Some((cur, next))
}

pub fn peer_store_mailbox_sender_keys(
    peer_v: &mut Value,
    generation: u64,
    cur_pub_hex: &str,
    next_pub_hex: &str,
) {
    if peer_v.get("mailbox").is_none() || !peer_v["mailbox"].is_object() {
        peer_v["mailbox"] = json!({});
    }
    if peer_v["mailbox"].get("sender_pubs").is_none() || !peer_v["mailbox"]["sender_pubs"].is_object() {
        peer_v["mailbox"]["sender_pubs"] = json!({});
    }

    if let Some(map) = sender_pub_map_mut(peer_v) {
        map.insert(generation.to_string(), json!(cur_pub_hex));
        map.insert(generation.saturating_add(1).to_string(), json!(next_pub_hex));
    }

    if let Some(peer) = peer_obj_mut(peer_v) {
        peer["mbox_out_cur_pub"] = json!(cur_pub_hex);
        peer["mbox_out_next_pub"] = json!(next_pub_hex);
    }
}

pub fn ensure_mailbox_state(self_v: &mut Value, peer_v: &mut Value) -> Result<()> {
    if self_v.get("mailbox").is_none() || !self_v["mailbox"].is_object() {
        self_v["mailbox"] = json!({});
    }
    if self_v["mailbox"].get("tx_gen").is_none() {
        self_v["mailbox"]["tx_gen"] = json!(0u64);
    }
    if self_v["mailbox"].get("tx_sent").is_none() {
        self_v["mailbox"]["tx_sent"] = json!(0u64);
    }
    if self_v["mailbox"].get("rotate_every").is_none() {
        self_v["mailbox"]["rotate_every"] = json!(MAILBOX_ROTATE_EVERY_DEFAULT);
    }

    if peer_v.get("mailbox").is_none() || !peer_v["mailbox"].is_object() {
        peer_v["mailbox"] = json!({});
    }
    if peer_v["mailbox"].get("peer_tx_gen_seen").is_none() {
        peer_v["mailbox"]["peer_tx_gen_seen"] = json!(0u64);
    }
    if peer_v["mailbox"].get("sender_pubs").is_none()
        || !peer_v["mailbox"]["sender_pubs"].is_object()
    {
        peer_v["mailbox"]["sender_pubs"] = json!({});
    }

    // self stable receiver
    if self_v.get("mbox_in_priv").is_none() {
        let legacy = get_str(self_v, "x_priv")?.to_owned();
        self_v["mbox_in_priv"] = json!(legacy);
    }
    if self_v.get("mbox_in_pub").is_none() {
        let legacy = get_str(self_v, "x_pub")?.to_owned();
        self_v["mbox_in_pub"] = json!(legacy);
    }

    // self rotating sender current
    if self_v.get("mbox_out_cur_priv").is_none() {
        let legacy = get_str(self_v, "x_priv")?.to_owned();
        self_v["mbox_out_cur_priv"] = json!(legacy);
    }
    if self_v.get("mbox_out_cur_pub").is_none() {
        let legacy = get_str(self_v, "x_pub")?.to_owned();
        self_v["mbox_out_cur_pub"] = json!(legacy);
    }

    // self rotating sender next
    if self_v.get("mbox_out_next_priv").is_none() || self_v.get("mbox_out_next_pub").is_none() {
        let (priv_fb, pub_fb) = keys::random_x25519_keypair()?;
        let priv_hex = priv_fb.to_hex();
        let pub_hex = pub_fb.to_hex();

        self_v["mbox_out_next_priv"] = json!(priv_hex.expose());
        self_v["mbox_out_next_pub"] = json!(pub_hex.expose());
    }

    // najpierw odczyt peer danych bez trzymania mutable borrow
    let peer_legacy_x = peer_v
        .get("peer")
        .and_then(|v| v.get("x_pub"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| LithiumError::json_missing_field("peer.x_pub"))?
        .to_owned();

    let peer_in_pub = peer_v
        .get("peer")
        .and_then(|v| v.get("mbox_in_pub"))
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| peer_legacy_x.clone());

    let peer_out_cur_pub = peer_v
        .get("peer")
        .and_then(|v| v.get("mbox_out_cur_pub"))
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| peer_legacy_x.clone());

    let peer_out_next_pub = peer_v
        .get("peer")
        .and_then(|v| v.get("mbox_out_next_pub"))
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| peer_out_cur_pub.clone());

    // teraz osobno mutujemy peer
    if let Some(peer) = peer_obj_mut(peer_v) {
        if peer.get("mbox_in_pub").is_none() {
            peer["mbox_in_pub"] = json!(peer_in_pub.clone());
        }
        if peer.get("mbox_out_cur_pub").is_none() {
            peer["mbox_out_cur_pub"] = json!(peer_out_cur_pub.clone());
        }
        if peer.get("mbox_out_next_pub").is_none() {
            peer["mbox_out_next_pub"] = json!(peer_out_next_pub.clone());
        }
    }

    // i dopiero osobno mutujemy sender_pubs
    if let Some(map) = sender_pub_map_mut(peer_v) {
        if !map.contains_key("0") {
            map.insert("0".into(), json!(peer_out_cur_pub));
        }
        if !map.contains_key("1") {
            map.insert("1".into(), json!(peer_out_next_pub));
        }
    }

    Ok(())
}

pub fn self_tx_generation(self_v: &Value) -> u64 {
    self_v
        .get("mailbox")
        .and_then(|v| v.get("tx_gen"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}

pub fn derive_mailboxes_for_generation_from_values(
    self_v: &Value,
    peer_v: &Value,
    generation: u64,
) -> Result<([u8; 32], [u8; 32])> {
    let self_cid = SecretBytes::from_hex(get_str(self_v, "cid")?.trim())?;
    let self_in_priv = Byte32::from_hex(get_str(self_v, "mbox_in_priv")?.trim())?;
    let self_out_cur_priv = Byte32::from_hex(get_str(self_v, "mbox_out_cur_priv")?.trim())?;

    let peer = peer_obj(peer_v).ok_or_else(|| LithiumError::invalid_credentials("peer_not_set"))?;
    let peer_cid = SecretBytes::from_hex(get_str(peer, "cid")?.trim())?;
    let peer_in_pub = Byte32::from_hex(get_str(peer, "mbox_in_pub")?.trim())?;
    let peer_sender_pub = peer_sender_pub_for_generation(peer_v, generation)?;

    let out = derive_outbound_mailbox(
        &self_out_cur_priv,
        &peer_in_pub,
        &self_cid,
        &peer_cid,
        generation,
    )?;

    let inn = derive_inbound_mailbox(
        &self_in_priv,
        &peer_sender_pub,
        &peer_cid,
        &self_cid,
        generation,
    )?;

    Ok((out, inn))
}

pub fn mark_outbound_message_sent(self_v: &mut Value) -> Result<u64> {
    let rotate_every = self_v
        .get("mailbox")
        .and_then(|v| v.get("rotate_every"))
        .and_then(|v| v.as_u64())
        .unwrap_or(MAILBOX_ROTATE_EVERY_DEFAULT)
        .clamp(1, 4096);

    let tx_gen = self_tx_generation(self_v);
    let tx_sent = self_v
        .get("mailbox")
        .and_then(|v| v.get("tx_sent"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
        .saturating_add(1);

    if tx_sent >= rotate_every {
        let next_cur_priv = get_str(self_v, "mbox_out_next_priv")?.to_owned();
        let next_cur_pub = get_str(self_v, "mbox_out_next_pub")?.to_owned();

        let (new_next_priv, new_next_pub) = keys::random_x25519_keypair()?;

        let next_gen = tx_gen.saturating_add(1);
        self_v["mailbox"]["tx_gen"] = json!(next_gen);
        self_v["mailbox"]["tx_sent"] = json!(0u64);

        self_v["mbox_out_cur_priv"] = json!(next_cur_priv);
        self_v["mbox_out_cur_pub"] = json!(next_cur_pub);
        self_v["mbox_out_next_priv"] = json!(new_next_priv.to_hex().expose());
        self_v["mbox_out_next_pub"] = json!(new_next_pub.to_hex().expose());

        Ok(next_gen)
    } else {
        self_v["mailbox"]["tx_sent"] = json!(tx_sent);
        Ok(tx_gen)
    }
}

pub fn note_inbound_generation_seen(peer_v: &mut Value, generation: u64) {
    let cur = peer_v
        .get("mailbox")
        .and_then(|v| v.get("peer_tx_gen_seen"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    if generation > cur {
        let cur_key = generation.to_string();
        let next_key = generation.saturating_add(1).to_string();

        let cur_pub = sender_pub_map(peer_v)
            .and_then(|map| map.get(&cur_key))
            .and_then(|v| v.as_str())
            .map(str::to_owned);

        let next_pub = sender_pub_map(peer_v)
            .and_then(|map| map.get(&next_key))
            .and_then(|v| v.as_str())
            .map(str::to_owned);

        if let Some(peer) = peer_obj_mut(peer_v) {
            if let Some(cur_pub) = cur_pub {
                peer["mbox_out_cur_pub"] = json!(cur_pub);
            }
            if let Some(next_pub) = next_pub {
                peer["mbox_out_next_pub"] = json!(next_pub);
            }
        }

        peer_v["mailbox"]["peer_tx_gen_seen"] = json!(generation);
    }
}

pub fn inbound_fetch_generations(peer_v: &Value) -> Vec<u64> {
    let seen = peer_v
        .get("mailbox")
        .and_then(|v| v.get("peer_tx_gen_seen"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let start = seen.saturating_sub(MAILBOX_FETCH_PAST_GENS);
    let end = seen.saturating_add(MAILBOX_FETCH_FUTURE_GENS);
    (start..=end).collect()
}