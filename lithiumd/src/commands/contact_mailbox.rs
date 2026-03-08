use lithium_core::{
    crypto::kdf,
    error::{LithiumError, Result},
    secrets::bytes::SecretBytes,
};
use serde_json::Value;
use x25519_dalek::{PublicKey, StaticSecret};

const LABEL_LOW_TO_HIGH: &[u8] = b"lithium/mbox/low->high/v1";
const LABEL_HIGH_TO_LOW: &[u8] = b"lithium/mbox/high->low/v1";

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

pub fn derive_mailboxes(self_state_json: &[u8], peer_state_json: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    let self_v: Value = serde_json::from_slice(self_state_json).map_err(LithiumError::json_parse)?;
    let peer_v: Value = serde_json::from_slice(peer_state_json).map_err(LithiumError::json_parse)?;

    let self_cid_hex = self_v.get("cid").and_then(|v| v.as_str()).ok_or_else(|| LithiumError::json_missing_field("cid"))?;
    let self_x_priv_hex = self_v.get("x_priv").and_then(|v| v.as_str()).ok_or_else(|| LithiumError::json_missing_field("x_priv"))?;

    let peer_obj = peer_v.get("peer").ok_or_else(|| LithiumError::json_missing_field("peer"))?;
    if peer_obj.is_null() {
        return Err(LithiumError::invalid_credentials("peer_not_set"));
    }

    let peer_cid_hex = peer_obj.get("cid").and_then(|v| v.as_str()).ok_or_else(|| LithiumError::json_missing_field("peer.cid"))?;
    let peer_x_pub_hex = peer_obj.get("x_pub").and_then(|v| v.as_str()).ok_or_else(|| LithiumError::json_missing_field("peer.x_pub"))?;

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
    let salt_sb = SecretBytes::from_vec(salt);

    let m_low_to_high = kdf::derive32(&shared_sb, Some(&salt_sb), &SecretBytes::from_slice(LABEL_LOW_TO_HIGH))?;
    let m_high_to_low = kdf::derive32(&shared_sb, Some(&salt_sb), &SecretBytes::from_slice(LABEL_HIGH_TO_LOW))?;

    let (out, inn) = if i_am_low {
        (*m_low_to_high.as_array(), *m_high_to_low.as_array())
    } else {
        (*m_high_to_low.as_array(), *m_low_to_high.as_array())
    };

    Ok((out, inn))
}
