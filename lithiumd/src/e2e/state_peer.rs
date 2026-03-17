use lithium_core::{
    error::{LithiumError, Result},
    secrets::{Byte32, SecretJson},
};
use serde_json::{Value, json};

use super::{
    crypto::id_from_peer_pubs,
    wire::now_ms,
};

pub(crate) fn merge_remote_prekeys_into_peer(
    peer_v: &mut Value,
    incoming: &[Value],
    max_keep: usize,
) {
    if peer_v.get("prekeys_remote").is_none() {
        peer_v["prekeys_remote"] = json!([]);
    }

    let Some(arr) = peer_v.get_mut("prekeys_remote").and_then(|v| v.as_array_mut()) else {
        return;
    };

    for item in incoming {
        let Some(id) = item.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        let exists = arr.iter().any(|v| v.get("id").and_then(|x| x.as_str()) == Some(id));
        if exists {
            continue;
        }

        let x_pub = item.get("x_pub").and_then(|v| v.as_str()).unwrap_or("");
        let k_pub = item.get("k_pub").and_then(|v| v.as_str()).unwrap_or("");
        if x_pub.is_empty() || k_pub.is_empty() {
            continue;
        }

        arr.push(json!({
            "id": id,
            "x_pub": x_pub,
            "k_pub": k_pub,
            "seen_at_ms": now_ms()
        }));
    }

    while arr.len() > max_keep {
        arr.remove(0);
    }
}

pub fn ensure_peer_e2e(peer_v: &mut SecretJson) -> Result<([u8; 32], String, String, u64)> {
    peer_v.with_exposed_mut(|peer_v| {
        let had_e2e = peer_v.get("e2e_peer").is_some();

        if peer_v.get("bootstrap").is_none() || !peer_v["bootstrap"].is_object() {
            peer_v["bootstrap"] = json!({ "tx_used": had_e2e });
        } else if peer_v["bootstrap"].get("tx_used").is_none() {
            peer_v["bootstrap"]["tx_used"] = json!(had_e2e);
        }

        if let Some(e2e) = peer_v.get("e2e_peer") {
            let id_hex = e2e.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let x_pub = e2e.get("x_pub").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let k_pub = e2e.get("k_pub").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let step = e2e.get("step").and_then(|v| v.as_u64()).unwrap_or(0);

            if !id_hex.is_empty() && !x_pub.is_empty() && !k_pub.is_empty() {
                let id = Byte32::from_hex(id_hex.trim())?;
                return Ok((*id.as_array(), x_pub, k_pub, step));
            }
        }

        Err(LithiumError::invalid_credentials("e2e_peer_not_set"))
    })
}

pub(crate) fn peer_bootstrap_target(peer_v: &SecretJson) -> Option<([u8; 32], String, String)> {
    peer_v.with_exposed(|peer_v| {
        if peer_v.get("e2e_peer").is_some() {
            return None;
        }

        let peer_obj = peer_v.get("peer")?;
        if peer_obj.is_null() {
            return None;
        }

        let x_pub = peer_obj.get("x_pub")?.as_str()?.to_string();
        let k_pub = peer_obj.get("k_pub")?.as_str()?.to_string();
        let id = id_from_peer_pubs(&x_pub, &k_pub).ok()?;

        Some((id, x_pub, k_pub))
    })
}

pub fn peer_need_recover(peer_v: &SecretJson) -> bool {
    peer_v.with_exposed(|peer_v| {
        peer_v
            .get("need_recover")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    })
}

pub fn peer_set_need_recover(peer_v: &mut SecretJson, v: bool) {
    peer_v.with_exposed_mut(|peer_v| {
        peer_v["need_recover"] = json!(v);
    });
}

pub fn peer_pick_remote_prekey(peer_v: &SecretJson) -> Option<(String, String, String)> {
    peer_v.with_exposed(|peer_v| {
        let arr = peer_v.get("prekeys_remote")?.as_array()?;
        let pk = arr.first()?.as_object()?;
        let id = pk.get("id")?.as_str()?.to_string();
        let x_pub = pk.get("x_pub")?.as_str()?.to_string();
        let k_pub = pk.get("k_pub")?.as_str()?.to_string();
        Some((id, x_pub, k_pub))
    })
}

pub fn peer_remove_remote_prekey(peer_v: &mut SecretJson, id_hex: &str) {
    peer_v.with_exposed_mut(|peer_v| {
        let Some(arr) = peer_v
            .get_mut("prekeys_remote")
            .and_then(|v| v.as_array_mut())
        else {
            return;
        };
        arr.retain(|v| v.get("id").and_then(|x| x.as_str()) != Some(id_hex));
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
            "prekeys_remote": [
                {"id": "aabb", "x_pub": "pppp", "k_pub": "kkkk"},
                {"id": "ccdd", "x_pub": "qqqq", "k_pub": "llll"}
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
        let pv = SecretJson::from(json!({ "prekeys_remote": [] }));
        assert!(peer_pick_remote_prekey(&pv).is_none());
    }

    #[test]
    fn merge_deduplicates_and_caps() {
        let mut pv = json!({
            "prekeys_remote": [
                {"id": "aa", "x_pub": "x1", "k_pub": "k1"}
            ]
        });
        let incoming = vec![
            json!({"id": "aa", "x_pub": "x1", "k_pub": "k1"}), // duplicate
            json!({"id": "bb", "x_pub": "x2", "k_pub": "k2"}),
            json!({"id": "cc", "x_pub": "x3", "k_pub": "k3"}),
        ];
        merge_remote_prekeys_into_peer(&mut pv, &incoming, 2);
        let arr = pv["prekeys_remote"].as_array().unwrap();
        assert_eq!(arr.len(), 2, "cap at max_keep=2");
        // oldest (aa) evicted; bb and cc remain
        assert!(arr.iter().any(|v| v["id"] == "bb"));
        assert!(arr.iter().any(|v| v["id"] == "cc"));
    }

    #[test]
    fn merge_ignores_entries_without_pub_keys() {
        let mut pv = json!({ "prekeys_remote": [] });
        let incoming = vec![
            json!({"id": "aa"}), // no x_pub / k_pub
        ];
        merge_remote_prekeys_into_peer(&mut pv, &incoming, PREKEY_TARGET);
        assert!(pv["prekeys_remote"].as_array().unwrap().is_empty());
    }
}