use lithium_core::{
    error::{LithiumError, Result},
    secrets::{Byte32, SecretJson},
};
use serde_json::{Value, json};

use crate::state_fields as sf;

use super::{
    crypto::id_from_peer_pubs,
    state::{BootstrapState, E2ePeer, RemotePrekey},
    wire::now_ms,
};

pub(crate) fn merge_remote_prekeys_into_peer(
    peer_v: &mut Value,
    incoming: &[Value],
    max_keep: usize,
) {
    let mut arr: Vec<RemotePrekey> = peer_v
        .get(sf::PREKEYS_REMOTE)
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    for item in incoming {
        let id = item.get(sf::ID).and_then(|v| v.as_str()).unwrap_or("");
        if id.is_empty() || arr.iter().any(|p| p.id == id) {
            continue;
        }

        let x_pub = item.get(sf::X_PUB).and_then(|v| v.as_str()).unwrap_or("");
        let k_pub = item.get(sf::K_PUB).and_then(|v| v.as_str()).unwrap_or("");
        if x_pub.is_empty() || k_pub.is_empty() {
            continue;
        }

        arr.push(RemotePrekey {
            id: id.to_owned(),
            x_pub: x_pub.to_owned(),
            k_pub: k_pub.to_owned(),
            seen_at_ms: now_ms(),
        });
    }

    while arr.len() > max_keep {
        arr.remove(0);
    }

    peer_v[sf::PREKEYS_REMOTE] = serde_json::to_value(&arr).unwrap_or_else(|_| json!([]));
}

pub fn ensure_peer_e2e(peer_v: &mut SecretJson) -> Result<([u8; 32], String, String, u64)> {
    peer_v.with_exposed_mut(|peer_v| {
        let had_e2e = peer_v.get(sf::E2E_PEER).is_some();

        let mut b: BootstrapState = peer_v
            .get(sf::BOOTSTRAP)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        if b.tx_used.is_none() {
            b.tx_used = Some(had_e2e);
        }
        if let Ok(v) = serde_json::to_value(b) {
            peer_v[sf::BOOTSTRAP] = v;
        }

        if let Some(e2e) = peer_v
            .get(sf::E2E_PEER)
            .and_then(|v| serde_json::from_value::<E2ePeer>(v.clone()).ok())
            && !e2e.id.is_empty()
            && !e2e.x_pub.is_empty()
            && !e2e.k_pub.is_empty()
        {
            let id = Byte32::from_hex(e2e.id.trim())?;
            return Ok((*id.as_array(), e2e.x_pub, e2e.k_pub, e2e.step));
        }

        Err(LithiumError::invalid_credentials("e2e_peer_not_set"))
    })
}

pub(crate) fn peer_bootstrap_target(peer_v: &SecretJson) -> Option<([u8; 32], String, String)> {
    peer_v.with_exposed(|peer_v| {
        if peer_v.get(sf::E2E_PEER).is_some() {
            return None;
        }

        let peer_obj = peer_v.get(sf::PEER)?;
        if peer_obj.is_null() {
            return None;
        }

        let x_pub = peer_obj.get(sf::X_PUB)?.as_str()?.to_string();
        let k_pub = peer_obj.get(sf::K_PUB)?.as_str()?.to_string();
        let id = id_from_peer_pubs(&x_pub, &k_pub).ok()?;

        Some((id, x_pub, k_pub))
    })
}

pub fn peer_need_recover(peer_v: &SecretJson) -> bool {
    peer_v.with_exposed(|peer_v| {
        peer_v
            .get(sf::NEED_RECOVER)
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    })
}

pub fn peer_set_need_recover(peer_v: &mut SecretJson, v: bool) {
    peer_v.with_exposed_mut(|peer_v| {
        peer_v[sf::NEED_RECOVER] = json!(v);
    });
}

pub fn peer_pick_remote_prekey(peer_v: &SecretJson) -> Option<(String, String, String)> {
    peer_v.with_exposed(|peer_v| {
        let first = peer_v.get(sf::PREKEYS_REMOTE)?.as_array()?.first()?;
        let pk: RemotePrekey = serde_json::from_value(first.clone()).ok()?;
        Some((pk.id, pk.x_pub, pk.k_pub))
    })
}

pub fn peer_remove_remote_prekey(peer_v: &mut SecretJson, id_hex: &str) {
    peer_v.with_exposed_mut(|peer_v| {
        let Some(arr) = peer_v
            .get_mut(sf::PREKEYS_REMOTE)
            .and_then(|v| v.as_array_mut())
        else {
            return;
        };
        arr.retain(|v| v.get(sf::ID).and_then(|x| x.as_str()) != Some(id_hex));
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2e::wire::PREKEY_TARGET;

    #[test]
    fn peer_need_recover_false_by_default() {
        let pv = SecretJson::from(json!({}));
        assert!(!peer_need_recover(&pv));
    }

    #[test]
    fn peer_set_and_get_need_recover() {
        let mut pv = SecretJson::from(json!({}));
        peer_set_need_recover(&mut pv, true);
        assert!(peer_need_recover(&pv));
        peer_set_need_recover(&mut pv, false);
        assert!(!peer_need_recover(&pv));
    }

    #[test]
    fn peer_pick_and_remove_remote_prekey() {
        let mut pv = SecretJson::from(json!({
            sf::PREKEYS_REMOTE: [
                {sf::ID: "aabb", sf::X_PUB: "pppp", sf::K_PUB: "kkkk"},
                {sf::ID: "ccdd", sf::X_PUB: "qqqq", sf::K_PUB: "llll"}
            ]
        }));

        let picked = peer_pick_remote_prekey(&pv).unwrap();
        assert_eq!(picked.0, "aabb");

        peer_remove_remote_prekey(&mut pv, "aabb");
        let after = peer_pick_remote_prekey(&pv).unwrap();
        assert_eq!(after.0, "ccdd", "first prekey must be removed");
    }

    #[test]
    fn peer_pick_remote_prekey_empty_returns_none() {
        let pv = SecretJson::from(json!({ sf::PREKEYS_REMOTE: [] }));
        assert!(peer_pick_remote_prekey(&pv).is_none());
    }

    #[test]
    fn merge_deduplicates_and_caps() {
        let mut pv = json!({
            sf::PREKEYS_REMOTE: [
                {sf::ID: "aa", sf::X_PUB: "x1", sf::K_PUB: "k1"}
            ]
        });
        let incoming = vec![
            json!({sf::ID: "aa", sf::X_PUB: "x1", sf::K_PUB: "k1"}), // duplicate
            json!({sf::ID: "bb", sf::X_PUB: "x2", sf::K_PUB: "k2"}),
            json!({sf::ID: "cc", sf::X_PUB: "x3", sf::K_PUB: "k3"}),
        ];
        merge_remote_prekeys_into_peer(&mut pv, &incoming, 2);
        let arr = pv[sf::PREKEYS_REMOTE].as_array().unwrap();
        assert_eq!(arr.len(), 2, "cap at max_keep=2");
        // oldest (aa) evicted; bb and cc remain
        assert!(arr.iter().any(|v| v[sf::ID] == "bb"));
        assert!(arr.iter().any(|v| v[sf::ID] == "cc"));
    }

    #[test]
    fn merge_ignores_entries_without_pub_keys() {
        let mut pv = json!({ sf::PREKEYS_REMOTE: [] });
        let incoming = vec![
            json!({sf::ID: "aa"}), // no x_pub / k_pub
        ];
        merge_remote_prekeys_into_peer(&mut pv, &incoming, PREKEY_TARGET);
        assert!(pv[sf::PREKEYS_REMOTE].as_array().unwrap().is_empty());
    }
}