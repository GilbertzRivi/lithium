// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::{
    error::{LithiumError, Result},
    secrets::Byte32,
};
use serde_json::Value;

use super::{
    crypto::id_from_peer_pubs,
    state::{PeerState, RemotePrekey},
    wire::now_ms,
};

pub(crate) fn merge_remote_prekeys_into_peer(
    peer_st: &mut PeerState,
    incoming: &[Value],
    max_keep: usize,
) {
    for item in incoming {
        let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("");
        if id.is_empty() || peer_st.prekeys_remote.iter().any(|p| p.id == id) {
            continue;
        }

        let x_pub = item.get("x_pub").and_then(|v| v.as_str()).unwrap_or("");
        let k_pub = item.get("k_pub").and_then(|v| v.as_str()).unwrap_or("");
        if x_pub.is_empty() || k_pub.is_empty() {
            continue;
        }

        peer_st.prekeys_remote.push(RemotePrekey {
            id: id.to_owned(),
            x_pub: x_pub.to_owned(),
            k_pub: k_pub.to_owned(),
            seen_at_ms: now_ms(),
        });
    }

    while peer_st.prekeys_remote.len() > max_keep {
        peer_st.prekeys_remote.remove(0);
    }
}

pub fn ensure_peer_e2e(peer_st: &mut PeerState) -> Result<([u8; 32], String, String, u64)> {
    let had_e2e = peer_st.e2e_peer.is_some();

    if peer_st.bootstrap.tx_used.is_none() {
        peer_st.bootstrap.tx_used = Some(had_e2e);
    }

    if let Some(e2e) = &peer_st.e2e_peer
        && !e2e.id.is_empty()
        && !e2e.x_pub.is_empty()
        && !e2e.k_pub.is_empty()
    {
        let id = Byte32::from_hex(e2e.id.trim())?;
        return Ok((
            *id.as_array(),
            e2e.x_pub.clone(),
            e2e.k_pub.clone(),
            e2e.step,
        ));
    }

    Err(LithiumError::invalid_credentials("e2e_peer_not_set"))
}

pub(crate) fn peer_bootstrap_target(peer_st: &PeerState) -> Option<([u8; 32], String, String)> {
    if peer_st.e2e_peer.is_some() {
        return None;
    }

    let peer = peer_st.peer.as_ref()?;
    let id = id_from_peer_pubs(&peer.x_pub, &peer.k_pub).ok()?;
    Some((id, peer.x_pub.clone(), peer.k_pub.clone()))
}

pub fn peer_need_recover(peer_st: &PeerState) -> bool {
    peer_st.need_recover
}

pub fn peer_set_need_recover(peer_st: &mut PeerState, v: bool) {
    peer_st.need_recover = v;
}

pub fn peer_pick_remote_prekey(peer_st: &PeerState) -> Option<(String, String, String)> {
    let pk = peer_st.prekeys_remote.first()?;
    Some((pk.id.clone(), pk.x_pub.clone(), pk.k_pub.clone()))
}

pub fn peer_remove_remote_prekey(peer_st: &mut PeerState, id_hex: &str) {
    peer_st.prekeys_remote.retain(|p| p.id != id_hex);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2e::state::PeerIdentity;
    use crate::e2e::wire::PREKEY_TARGET;
    use serde_json::json;

    fn empty_peer() -> PeerState {
        PeerState::empty()
    }

    fn peer_with_remote(items: &[(&str, &str, &str)]) -> PeerState {
        let mut p = empty_peer();
        for (id, x, k) in items {
            p.prekeys_remote.push(RemotePrekey {
                id: (*id).to_owned(),
                x_pub: (*x).to_owned(),
                k_pub: (*k).to_owned(),
                seen_at_ms: 0,
            });
        }
        p
    }

    #[test]
    fn peer_need_recover_false_by_default() {
        assert!(!peer_need_recover(&empty_peer()));
    }

    #[test]
    fn peer_set_and_get_need_recover() {
        let mut p = empty_peer();
        peer_set_need_recover(&mut p, true);
        assert!(peer_need_recover(&p));
        peer_set_need_recover(&mut p, false);
        assert!(!peer_need_recover(&p));
    }

    #[test]
    fn peer_pick_and_remove_remote_prekey() {
        let mut p = peer_with_remote(&[("aabb", "pppp", "kkkk"), ("ccdd", "qqqq", "llll")]);

        let picked = peer_pick_remote_prekey(&p).unwrap();
        assert_eq!(picked.0, "aabb");

        peer_remove_remote_prekey(&mut p, "aabb");
        let after = peer_pick_remote_prekey(&p).unwrap();
        assert_eq!(after.0, "ccdd", "first prekey must be removed");
    }

    #[test]
    fn peer_pick_remote_prekey_empty_returns_none() {
        assert!(peer_pick_remote_prekey(&empty_peer()).is_none());
    }

    #[test]
    fn merge_deduplicates_and_caps() {
        let mut p = peer_with_remote(&[("aa", "x1", "k1")]);
        let incoming = vec![
            json!({"id": "aa", "x_pub": "x1", "k_pub": "k1"}),
            json!({"id": "bb", "x_pub": "x2", "k_pub": "k2"}),
            json!({"id": "cc", "x_pub": "x3", "k_pub": "k3"}),
        ];
        merge_remote_prekeys_into_peer(&mut p, &incoming, 2);
        assert_eq!(p.prekeys_remote.len(), 2, "cap at max_keep=2");
        assert!(p.prekeys_remote.iter().any(|v| v.id == "bb"));
        assert!(p.prekeys_remote.iter().any(|v| v.id == "cc"));
    }

    #[test]
    fn merge_ignores_entries_without_pub_keys() {
        let mut p = empty_peer();
        let incoming = vec![json!({"id": "aa"})];
        merge_remote_prekeys_into_peer(&mut p, &incoming, PREKEY_TARGET);
        assert!(p.prekeys_remote.is_empty());
    }

    #[test]
    fn peer_bootstrap_target_none_without_peer() {
        assert!(peer_bootstrap_target(&empty_peer()).is_none());
    }

    #[test]
    fn peer_bootstrap_target_some_with_peer() {
        let mut p = empty_peer();
        let (_, x_pub) = lithium_core::crypto::keys::random_x25519_keypair().unwrap();
        let (_, k_pub) = lithium_core::crypto::keys::random_kyber_mlkem1024_keypair().unwrap();
        p.peer = Some(PeerIdentity {
            cid: "00".repeat(32),
            x_pub: x_pub.to_hex().expose().to_owned(),
            k_pub: k_pub.to_hex().expose().to_owned(),
            ed_pub: "11".repeat(32),
            dili_pub: "22".repeat(32),
            mbox_in_pub: "33".repeat(32),
            mbox_out_cur_pub: "44".repeat(32),
            mbox_out_next_pub: "55".repeat(32),
        });
        assert!(peer_bootstrap_target(&p).is_some());
    }
}
