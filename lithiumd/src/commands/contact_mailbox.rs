use lithium_core::{
    crypto::kdf,
    error::{LithiumError, Result},
    secrets::bytes::SecretBytes,
};
use serde_json::{json, Value};
use x25519_dalek::{PublicKey, StaticSecret};

const LABEL_LOW_TO_HIGH: &[u8] = b"lithium/mbox/low->high/v1";
const LABEL_HIGH_TO_LOW: &[u8] = b"lithium/mbox/high->low/v1";

pub const MAILBOX_ROTATE_EVERY_DEFAULT: u64 = 32;
pub const MAILBOX_FETCH_PAST_GENS: u64 = 2;
pub const MAILBOX_FETCH_FUTURE_GENS: u64 = 8;

fn hex_to_32(s: &str) -> Result<[u8; 32]> {
    let b = hex::decode(s.trim()).map_err(LithiumError::invalid_hex)?;
    if b.len() != 32 {
        return Err(LithiumError::invalid_len(32, b.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Ok(out)
}

fn hex_to_vec(s: &str) -> Result<Vec<u8>> {
    hex::decode(s.trim()).map_err(LithiumError::invalid_hex)
}

fn mailbox_materials(self_v: &Value, peer_v: &Value) -> Result<(SecretBytes, SecretBytes, bool)> {
    let self_cid_hex = self_v
        .get("cid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LithiumError::json_missing_field("cid"))?;
    let self_x_priv_hex = self_v
        .get("x_priv")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LithiumError::json_missing_field("x_priv"))?;

    let peer_obj = peer_v
        .get("peer")
        .ok_or_else(|| LithiumError::json_missing_field("peer"))?;
    if peer_obj.is_null() {
        return Err(LithiumError::invalid_credentials("peer_not_set"));
    }

    let peer_cid_hex = peer_obj
        .get("cid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LithiumError::json_missing_field("peer.cid"))?;
    let peer_x_pub_hex = peer_obj
        .get("x_pub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LithiumError::json_missing_field("peer.x_pub"))?;

    let self_cid = hex_to_vec(self_cid_hex)?;
    let peer_cid = hex_to_vec(peer_cid_hex)?;

    let self_sk = StaticSecret::from(hex_to_32(self_x_priv_hex)?);
    let peer_pk = PublicKey::from(hex_to_32(peer_x_pub_hex)?);

    let shared = self_sk.diffie_hellman(&peer_pk);
    let shared_sb = SecretBytes::from_slice(shared.as_bytes());

    let (low, high, i_am_low) = if self_cid <= peer_cid {
        (self_cid.clone(), peer_cid.clone(), true)
    } else {
        (peer_cid.clone(), self_cid.clone(), false)
    };

    let mut salt = Vec::with_capacity(low.len() + high.len());
    salt.extend_from_slice(&low);
    salt.extend_from_slice(&high);

    Ok((shared_sb, SecretBytes::from_vec(salt), i_am_low))
}

fn mailbox_salt_for_generation(base_salt: &SecretBytes, generation: u64) -> SecretBytes {
    if generation == 0 {
        return SecretBytes::from_slice(base_salt.as_slice());
    }

    let mut salt = Vec::with_capacity(base_salt.as_slice().len() + 8);
    salt.extend_from_slice(base_salt.as_slice());
    salt.extend_from_slice(&generation.to_be_bytes());
    SecretBytes::from_vec(salt)
}

pub fn derive_mailboxes_for_generation_from_values(
    self_v: &Value,
    peer_v: &Value,
    generation: u64,
) -> Result<([u8; 32], [u8; 32])> {
    let (shared_sb, base_salt, i_am_low) = mailbox_materials(self_v, peer_v)?;
    let salt_sb = mailbox_salt_for_generation(&base_salt, generation);

    let m_low_to_high = kdf::derive32(
        &shared_sb,
        Some(&salt_sb),
        &SecretBytes::from_slice(LABEL_LOW_TO_HIGH),
    )?;
    let m_high_to_low = kdf::derive32(
        &shared_sb,
        Some(&salt_sb),
        &SecretBytes::from_slice(LABEL_HIGH_TO_LOW),
    )?;

    let (out, inn) = if i_am_low {
        (*m_low_to_high.as_array(), *m_high_to_low.as_array())
    } else {
        (*m_high_to_low.as_array(), *m_low_to_high.as_array())
    };

    Ok((out, inn))
}

pub fn derive_mailboxes(
    self_state_json: &[u8],
    peer_state_json: &[u8],
) -> Result<([u8; 32], [u8; 32])> {
    derive_mailboxes_for_generation(self_state_json, peer_state_json, 0)
}

pub fn derive_mailboxes_for_generation(
    self_state_json: &[u8],
    peer_state_json: &[u8],
    generation: u64,
) -> Result<([u8; 32], [u8; 32])> {
    let self_v: Value =
        serde_json::from_slice(self_state_json).map_err(LithiumError::json_parse)?;
    let peer_v: Value =
        serde_json::from_slice(peer_state_json).map_err(LithiumError::json_parse)?;
    derive_mailboxes_for_generation_from_values(&self_v, &peer_v, generation)
}

pub fn ensure_mailbox_state(self_v: &mut Value, peer_v: &mut Value) {
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
}

pub fn self_tx_generation(self_v: &Value) -> u64 {
    self_v
        .get("mailbox")
        .and_then(|v| v.get("tx_gen"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}

pub fn mark_outbound_message_sent(self_v: &mut Value) -> u64 {
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
        let next_gen = tx_gen.saturating_add(1);
        self_v["mailbox"]["tx_gen"] = json!(next_gen);
        self_v["mailbox"]["tx_sent"] = json!(0u64);
        next_gen
    } else {
        self_v["mailbox"]["tx_sent"] = json!(tx_sent);
        tx_gen
    }
}

pub fn note_inbound_generation_seen(peer_v: &mut Value, generation: u64) {
    let cur = peer_v
        .get("mailbox")
        .and_then(|v| v.get("peer_tx_gen_seen"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    if generation > cur {
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