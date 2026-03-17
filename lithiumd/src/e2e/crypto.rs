use lithium_core::{
    crypto::{kdf, sign},
    error::{LithiumError, Result},
    secrets::{Byte32, SecretJson, bytes::SecretBytes},
};
use serde_json::{Value, json};

use super::wire::E2E_SIG_LABEL;

pub(crate) fn id_from_peer_pubs(peer_x_pub_hex: &str, peer_k_pub_hex: &str) -> Result<[u8; 32]> {
    const KID_LABEL: &[u8] = b"lithiumd/e2e-peer-kid/v1";

    let x = Byte32::from_hex(peer_x_pub_hex.trim())?;
    let k = SecretBytes::from_hex(peer_k_pub_hex.trim())?;

    let mut inb = Vec::with_capacity(32 + k.len());
    inb.extend_from_slice(x.as_slice());
    inb.extend_from_slice(k.expose_as_slice());

    let id = kdf::derive32(
        &SecretBytes::new(inb),
        None,
        &SecretBytes::from_slice(KID_LABEL),
    )?;

    Ok(*id.as_array())
}

pub(crate) fn malicious_message_err() -> LithiumError {
    LithiumError::invalid_credentials("potentially_harmful_message")
}

pub(crate) fn json_get_str<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(|x| x.as_str())
}

pub(crate) fn get_self_identity_privs(self_v: &SecretJson) -> Result<(Byte32, SecretBytes)> {
    self_v.with_exposed(|self_v| {
        let ed_priv_hex = self_v
            .get("ed_priv")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("ed_priv"))?;

        let dili_priv_hex = self_v
            .get("dili_priv")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("dili_priv"))?;

        Ok((
            Byte32::from_hex(ed_priv_hex.trim())?,
            SecretBytes::from_hex(dili_priv_hex.trim())?,
        ))
    })
}

pub(crate) fn get_peer_identity_pubs(peer_v: &Value) -> Result<(Byte32, SecretBytes)> {
    let peer_obj = peer_v.get("peer").filter(|v| v.is_object()).unwrap_or(peer_v);

    let ed_pub_hex = json_get_str(peer_obj, "ed_pub")
        .ok_or_else(|| LithiumError::json_missing_field("ed_pub"))?;

    let dili_pub_hex = json_get_str(peer_obj, "dili_pub")
        .ok_or_else(|| LithiumError::json_missing_field("dili_pub"))?;

    Ok((
        Byte32::from_hex(ed_pub_hex.trim())?,
        SecretBytes::from_hex(dili_pub_hex.trim())?,
    ))
}

pub(crate) fn build_sig_input(
    to_id: &[u8; 32],
    from_x_pub: &[u8; 32],
    hdr_unsigned: &[u8],
    pt_body: &[u8],
) -> SecretBytes {
    let mut out = SecretBytes::new(Vec::with_capacity(
        E2E_SIG_LABEL.len() + 32 + 32 + 4 + hdr_unsigned.len() + 4 + pt_body.len(),
    ));

    out.expose_as_mut_vec().extend_from_slice(E2E_SIG_LABEL);
    out.expose_as_mut_vec().extend_from_slice(to_id);
    out.expose_as_mut_vec().extend_from_slice(from_x_pub);
    out.expose_as_mut_vec()
        .extend_from_slice(&(hdr_unsigned.len() as u32).to_be_bytes());
    out.expose_as_mut_vec().extend_from_slice(hdr_unsigned);
    out.expose_as_mut_vec()
        .extend_from_slice(&(pt_body.len() as u32).to_be_bytes());
    out.expose_as_mut_vec().extend_from_slice(pt_body);

    out
}

// Returns (sig_ed_hex, sig_dili_hex).
pub(crate) fn sign_e2e_payload(
    self_v: &SecretJson,
    to_id: &[u8; 32],
    from_x_pub: &[u8; 32],
    hdr_unsigned: &[u8],
    pt_body: &[u8],
) -> Result<(String, String)> {
    let (ed_priv, dili_priv) = get_self_identity_privs(self_v)?;
    let sig_input = build_sig_input(to_id, from_x_pub, hdr_unsigned, pt_body);

    let sig_ed = sign::sign_message(sig_input.expose_as_slice(), ed_priv.as_slice())?;
    let sig_dili =
        sign::sign_message_dili(sig_input.expose_as_slice(), dili_priv.expose_as_slice())?;

    Ok((
        sig_ed.to_hex().expose().to_owned(),
        sig_dili.to_hex().expose().to_owned(),
    ))
}

// Returns (hdr_unsigned_bytes, sig_ed_hex, sig_dili_hex).
pub(crate) fn signed_header_parts(hdr_v: &Value) -> Result<(Vec<u8>, String, String)> {
    let v = hdr_v
        .get("v")
        .cloned()
        .ok_or_else(|| LithiumError::json_missing_field("v"))?;
    let mode = hdr_v
        .get("mode")
        .cloned()
        .ok_or_else(|| LithiumError::json_missing_field("mode"))?;
    let ts_ms = hdr_v
        .get("ts_ms")
        .cloned()
        .ok_or_else(|| LithiumError::json_missing_field("ts_ms"))?;
    let msg_id = hdr_v
        .get("msg_id")
        .cloned()
        .ok_or_else(|| LithiumError::json_missing_field("msg_id"))?;
    let kind = hdr_v
        .get("kind")
        .cloned()
        .ok_or_else(|| LithiumError::json_missing_field("kind"))?;
    let step = hdr_v
        .get("step")
        .cloned()
        .ok_or_else(|| LithiumError::json_missing_field("step"))?;
    let mbox_gen = hdr_v
        .get("mbox_gen")
        .cloned()
        .ok_or_else(|| LithiumError::json_missing_field("mbox_gen"))?;
    let mailbox = hdr_v
        .get("mailbox")
        .cloned()
        .ok_or_else(|| LithiumError::json_missing_field("mailbox"))?;
    let reply = hdr_v
        .get("reply")
        .cloned()
        .ok_or_else(|| LithiumError::json_missing_field("reply"))?;
    let prekeys = hdr_v
        .get("prekeys")
        .cloned()
        .ok_or_else(|| LithiumError::json_missing_field("prekeys"))?;

    let auth = hdr_v
        .get("auth")
        .and_then(|v| v.as_object())
        .ok_or_else(|| LithiumError::json_missing_field("auth"))?;

    let sig_ed = auth
        .get("sig_ed")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LithiumError::json_missing_field("auth.sig_ed"))?
        .to_string();

    let sig_dili = auth
        .get("sig_dili")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LithiumError::json_missing_field("auth.sig_dili"))?
        .to_string();

    let hdr_unsigned = serde_json::to_vec(&json!({
        "v": v, "mode": mode, "ts_ms": ts_ms, "msg_id": msg_id,
        "kind": kind, "step": step, "mbox_gen": mbox_gen,
        "mailbox": mailbox, "reply": reply, "prekeys": prekeys
    }))
    .map_err(LithiumError::json_parse)?;

    Ok((hdr_unsigned, sig_ed, sig_dili))
}

pub(crate) fn verify_e2e_payload(
    peer_v: &Value,
    to_id: &[u8; 32],
    from_x_pub: &[u8; 32],
    hdr_unsigned: &[u8],
    pt_body: &[u8],
    sig_ed_hex: &str,
    sig_dili_hex: &str,
) -> Result<()> {
    let (ed_pub, dili_pub) = get_peer_identity_pubs(peer_v)?;
    let sig_input = build_sig_input(to_id, from_x_pub, hdr_unsigned, pt_body);

    let sig_ed = SecretBytes::from_hex(sig_ed_hex.trim())
        .map_err(|_| LithiumError::invalid_credentials("bad_sig_ed_hex"))?;
    let sig_dili = SecretBytes::from_hex(sig_dili_hex.trim())
        .map_err(|_| LithiumError::invalid_credentials("bad_sig_dili_hex"))?;

    if !sign::verify_signature(sig_input.expose_as_slice(), sig_ed.expose_as_slice(), &ed_pub) {
        return Err(malicious_message_err());
    }

    if !sign::verify_signature_dili(
        sig_input.expose_as_slice(),
        sig_dili.expose_as_slice(),
        &dili_pub,
    ) {
        return Err(malicious_message_err());
    }

    Ok(())
}