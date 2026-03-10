use lithium_core::{
    crypto::kdf,
    error::{LithiumError, Result},
    secrets::{Byte32, SecretJson},
    secrets::bytes::SecretBytes,
};
use serde_json::{json, Value};
use x25519_dalek::{PublicKey, StaticSecret};

const LABEL_LOW_TO_HIGH: &[u8] = b"lithium/mbox/low->high/v1";
const LABEL_HIGH_TO_LOW: &[u8] = b"lithium/mbox/high->low/v1";

pub const MAILBOX_ROTATE_EVERY_DEFAULT: u64 = 32;
pub const MAILBOX_FETCH_PAST_GENS: u64 = 2;
pub const MAILBOX_FETCH_FUTURE_GENS: u64 = 8;

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

    let self_cid = SecretBytes::from_hex(self_cid_hex.trim())?;
    let peer_cid = SecretBytes::from_hex(peer_cid_hex.trim())?;

    let self_sk = StaticSecret::from(*Byte32::from_hex(self_x_priv_hex.trim())?.as_array());
    let peer_pk = PublicKey::from(*Byte32::from_hex(peer_x_pub_hex.trim())?.as_array());

    let shared = self_sk.diffie_hellman(&peer_pk);
    let shared_sb = SecretBytes::from_slice(shared.as_bytes());

    let i_am_low = self_cid.as_slice() <= peer_cid.as_slice();

    let mut salt = SecretBytes::new(Vec::with_capacity(self_cid.len() + peer_cid.len()));
    if i_am_low {
        salt.as_mut_vec().extend_from_slice(self_cid.as_slice());
        salt.as_mut_vec().extend_from_slice(peer_cid.as_slice());
    } else {
        salt.as_mut_vec().extend_from_slice(peer_cid.as_slice());
        salt.as_mut_vec().extend_from_slice(self_cid.as_slice());
    }

    Ok((shared_sb, salt, i_am_low))
}

fn mailbox_salt_for_generation(base_salt: &SecretBytes, generation: u64) -> SecretBytes {
    if generation == 0 {
        return SecretBytes::from_slice(base_salt.as_slice());
    }

    let mut salt = SecretBytes::new(Vec::with_capacity(base_salt.len() + 8));
    salt.as_mut_vec().extend_from_slice(base_salt.as_slice());
    salt.as_mut_vec().extend_from_slice(&generation.to_be_bytes());
    salt
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