// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::{
    crypto::{kdf, sign},
    error::{LithiumError, Result},
    secrets::{Byte32, bytes::SecretBytes},
};

use super::state::{PeerState, SelfState};

use crate::labels::{E2E_SIG_LABEL, KID_LABEL};

pub(crate) fn id_from_peer_pubs(peer_x_pub_hex: &str, peer_k_pub_hex: &str) -> Result<[u8; 32]> {
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

pub(crate) fn replayed_message_err() -> LithiumError {
    LithiumError::invalid_credentials("replayed_message")
}

pub(crate) fn get_self_identity_privs(self_st: &SelfState) -> Result<(Byte32, SecretBytes)> {
    Ok((
        Byte32::from_hex(self_st.ed_priv.trim())?,
        SecretBytes::from_hex(self_st.dili_priv.trim())?,
    ))
}

pub(crate) fn get_peer_identity_pubs(peer_st: &PeerState) -> Result<(Byte32, SecretBytes)> {
    let peer = peer_st
        .peer
        .as_ref()
        .ok_or_else(|| LithiumError::json_missing_field("peer"))?;

    Ok((
        Byte32::from_hex(peer.ed_pub.trim())?,
        SecretBytes::from_hex(peer.dili_pub.trim())?,
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
    self_st: &SelfState,
    to_id: &[u8; 32],
    from_x_pub: &[u8; 32],
    hdr_unsigned: &[u8],
    pt_body: &[u8],
) -> Result<(String, String)> {
    let (ed_priv, dili_priv) = get_self_identity_privs(self_st)?;
    let sig_input = build_sig_input(to_id, from_x_pub, hdr_unsigned, pt_body);

    let sig_ed = sign::sign_message(sig_input.expose_as_slice(), ed_priv.as_slice())?;
    let sig_dili =
        sign::sign_message_dili(sig_input.expose_as_slice(), dili_priv.expose_as_slice())?;

    Ok((
        sig_ed.to_hex().expose().to_owned(),
        sig_dili.to_hex().expose().to_owned(),
    ))
}

pub(crate) fn verify_e2e_payload(
    peer_st: &PeerState,
    to_id: &[u8; 32],
    from_x_pub: &[u8; 32],
    hdr_unsigned: &[u8],
    pt_body: &[u8],
    sig_ed_hex: &str,
    sig_dili_hex: &str,
) -> Result<()> {
    let (ed_pub, dili_pub) = get_peer_identity_pubs(peer_st)?;
    let sig_input = build_sig_input(to_id, from_x_pub, hdr_unsigned, pt_body);

    let sig_ed = SecretBytes::from_hex(sig_ed_hex.trim())
        .map_err(|_| LithiumError::invalid_credentials("bad_sig_ed_hex"))?;
    let sig_dili = SecretBytes::from_hex(sig_dili_hex.trim())
        .map_err(|_| LithiumError::invalid_credentials("bad_sig_dili_hex"))?;

    if !sign::verify_signature(
        sig_input.expose_as_slice(),
        sig_ed.expose_as_slice(),
        &ed_pub,
    ) {
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
