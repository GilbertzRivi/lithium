// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::{
    error::Result,
    secrets::{Byte32, bytes::SecretBytes},
};
use zeroize::Zeroize;

use super::{
    crypto::id_from_peer_pubs,
    state::{PeerState, RxKey, SelfState},
    wire::now_ms,
};

pub(crate) fn set_active_reply_key(self_st: &mut SelfState, id_hex: &str, key: RxKey) {
    self_st.e2e_rx.active = id_hex.to_owned();
    self_st.e2e_rx.keys.insert(id_hex.to_owned(), key);
}

pub(crate) fn advance_ack(self_st: &mut SelfState, seq: u64) {
    if seq > self_st.e2e_rx.ack_seq {
        self_st.e2e_rx.ack_seq = seq;
    }
}

pub fn drop_bootstrap_private_if_established(self_st: &mut SelfState, peer_st: &PeerState) {
    let peer_established = peer_st.e2e_peer.is_some();
    let retire_ok = self_st.e2e_rx.ack_seq > 0 || self_st.bootstrap.retire_ok;

    if !(peer_established && retire_ok) {
        return;
    }

    if let Some(mut s) = self_st.x_priv.take() {
        s.zeroize();
    }
    if let Some(mut s) = self_st.k_priv.take() {
        s.zeroize();
    }

    self_st.bootstrap.rx_used = true;
    self_st.bootstrap.retire_ok = true;
    self_st.bootstrap.retired_at_ms = now_ms();
}

pub fn mark_bootstrap_retire_ready(self_st: &mut SelfState) {
    self_st.bootstrap.retire_ok = true;
}

pub fn ensure_self_keyring(self_st: &mut SelfState) -> Result<()> {
    let bootstrap_id_hex = hex::encode(id_from_peer_pubs(&self_st.x_pub, &self_st.k_pub)?);

    // Remove any stale seq=0 bootstrap slot from the ratchet key map.
    if self_st.e2e_rx.keys.get(&bootstrap_id_hex).map(|k| k.seq) == Some(0) {
        self_st.e2e_rx.keys.remove(&bootstrap_id_hex);
    }

    if self_st.e2e_rx.active == bootstrap_id_hex {
        self_st.e2e_rx.active = String::new();
    }

    Ok(())
}

pub(crate) fn self_bootstrap_rx_privs(
    self_st: &SelfState,
    to_id: &[u8; 32],
) -> Option<(Byte32, SecretBytes)> {
    let bootstrap_id = id_from_peer_pubs(&self_st.x_pub, &self_st.k_pub).ok()?;
    if &bootstrap_id != to_id {
        return None;
    }

    let x_priv = Byte32::from_hex(self_st.x_priv.as_ref()?.trim()).ok()?;
    let k_priv = SecretBytes::from_hex(self_st.k_priv.as_ref()?.trim()).ok()?;
    Some((x_priv, k_priv))
}

pub(crate) fn self_next_seq(self_st: &mut SelfState) -> u64 {
    let n = self_st.e2e_rx.next_seq;
    self_st.e2e_rx.next_seq = n + 1;
    n
}

pub(crate) fn self_find_seq(self_st: &SelfState, to_id: &[u8; 32]) -> Option<u64> {
    self_st.e2e_rx.keys.get(&hex::encode(to_id)).map(|k| k.seq)
}

pub(crate) fn self_get_rx_privs(
    self_st: &SelfState,
    to_id: &[u8; 32],
) -> Option<(Byte32, SecretBytes)> {
    let rk = self_st.e2e_rx.keys.get(&hex::encode(to_id))?;
    Some((
        Byte32::from_hex(rk.x_priv.trim()).ok()?,
        SecretBytes::from_hex(rk.k_priv.trim()).ok()?,
    ))
}

pub(crate) fn gc_after_ack(self_st: &mut SelfState) {
    let min_keep_seq = self_st.e2e_rx.ack_seq.saturating_sub(self_st.e2e_rx.window);
    // Evicted RxKeys zeroize their privates on drop.
    self_st
        .e2e_rx
        .keys
        .retain(|_, k| k.seq == 0 || k.seq >= min_keep_seq);
}

pub(crate) fn next_tx_step(self_st: &mut SelfState) -> u64 {
    self_st.e2e_tx.step += 1;
    self_st.e2e_tx.step
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::invite_codec::gen_self_state;
    use crate::e2e::wire::DEFAULT_WINDOW;

    #[test]
    fn ensure_self_keyring_initializes_e2e_fields() {
        let (_cid, mut st) = gen_self_state().unwrap();
        ensure_self_keyring(&mut st).unwrap();

        assert!(st.e2e_rx.active.is_empty());
        assert_eq!(st.e2e_rx.ack_seq, 0);
        assert_eq!(st.e2e_rx.next_seq, 1);
        assert_eq!(st.e2e_rx.window, DEFAULT_WINDOW);
    }

    #[test]
    fn ensure_self_keyring_idempotent() {
        let (_cid, mut st) = gen_self_state().unwrap();
        ensure_self_keyring(&mut st).unwrap();
        let ack_before = st.e2e_rx.ack_seq;
        ensure_self_keyring(&mut st).unwrap();
        assert_eq!(st.e2e_rx.ack_seq, ack_before);
    }

    #[test]
    fn mark_bootstrap_retire_ready_sets_flag() {
        let (_cid, mut st) = gen_self_state().unwrap();
        ensure_self_keyring(&mut st).unwrap();
        mark_bootstrap_retire_ready(&mut st);
        assert!(st.bootstrap.retire_ok);
    }
}
