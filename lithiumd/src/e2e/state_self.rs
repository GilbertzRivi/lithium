use lithium_core::{
    error::{LithiumError, Result},
    secrets::{Byte32, SecretJson, bytes::SecretBytes},
};
use serde_json::json;

use super::{
    crypto::id_from_peer_pubs,
    wire::{drop_removed_json_key, now_ms, DEFAULT_WINDOW},
};

pub fn drop_bootstrap_private_if_established(self_v: &mut SecretJson, peer_v: &SecretJson) {
    let peer_established = peer_v.with_exposed(|peer_v| peer_v.get("e2e_peer").is_some());

    let retire_ok = self_v.with_exposed(|self_v| {
        let ack_seq = self_v
            .get("e2e_rx")
            .and_then(|v| v.get("ack_seq"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let marked = self_v
            .get("bootstrap")
            .and_then(|v| v.get("retire_ok"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        ack_seq > 0 || marked
    });

    if !(peer_established && retire_ok) {
        return;
    }

    self_v.with_exposed_mut(|self_v| {
        if self_v.get("bootstrap").is_none() || !self_v["bootstrap"].is_object() {
            self_v["bootstrap"] = json!({});
        }

        if let Some(obj) = self_v.as_object_mut() {
            drop_removed_json_key(obj, "x_priv");
            drop_removed_json_key(obj, "k_priv");
        }

        self_v["bootstrap"]["rx_used"] = json!(true);
        self_v["bootstrap"]["retire_ok"] = json!(true);
        self_v["bootstrap"]["retired_at_ms"] = json!(now_ms());
    });
}

pub fn mark_bootstrap_retire_ready(self_v: &mut SecretJson) {
    self_v.with_exposed_mut(|self_v| {
        if self_v.get("bootstrap").is_none() || !self_v["bootstrap"].is_object() {
            self_v["bootstrap"] = json!({});
        }
        self_v["bootstrap"]["retire_ok"] = json!(true);
    });
}

pub fn ensure_self_keyring(self_v: &mut SecretJson) -> Result<()> {
    self_v.with_exposed_mut(|self_v| {
        if self_v.get("e2e_tx").is_none() {
            self_v["e2e_tx"] = json!({ "step": 0u64 });
        }

        if self_v.get("bootstrap").is_none() || !self_v["bootstrap"].is_object() {
            self_v["bootstrap"] = json!({ "rx_used": false, "retire_ok": false });
        } else {
            if self_v["bootstrap"].get("rx_used").is_none() {
                self_v["bootstrap"]["rx_used"] = json!(false);
            }
            if self_v["bootstrap"].get("retire_ok").is_none() {
                self_v["bootstrap"]["retire_ok"] = json!(false);
            }
        }

        if self_v.get("e2e_rx").is_some() {
            if self_v["e2e_rx"].get("window").is_none() {
                self_v["e2e_rx"]["window"] = json!(DEFAULT_WINDOW);
            }
            if self_v["e2e_rx"].get("ack_seq").is_none() {
                self_v["e2e_rx"]["ack_seq"] = json!(0u64);
            }
            if self_v["e2e_rx"].get("next_seq").is_none() {
                self_v["e2e_rx"]["next_seq"] = json!(1u64);
            }
            if self_v["e2e_rx"].get("keys").is_none() {
                self_v["e2e_rx"]["keys"] = json!({});
            }
            if self_v["e2e_rx"].get("active").is_none() {
                self_v["e2e_rx"]["active"] = json!("");
            }
        } else {
            self_v["e2e_rx"] = json!({
                "active": "",
                "ack_seq": 0u64,
                "next_seq": 1u64,
                "window": DEFAULT_WINDOW,
                "keys": {}
            });
        }

        let x_pub = self_v
            .get("x_pub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("x_pub"))?
            .to_string();
        let k_pub = self_v
            .get("k_pub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("k_pub"))?
            .to_string();

        let bootstrap_id_hex = hex::encode(id_from_peer_pubs(&x_pub, &k_pub)?);

        // Remove any stale seq=0 bootstrap slot from the ratchet key map.
        if let Some(keys) = self_v["e2e_rx"].get_mut("keys").and_then(|v| v.as_object_mut()) {
            let remove_bootstrap = keys
                .get(&bootstrap_id_hex)
                .and_then(|v| v.get("seq"))
                .and_then(|v| v.as_u64())
                == Some(0);

            if remove_bootstrap {
                drop_removed_json_key(keys, &bootstrap_id_hex);
            }
        }

        if self_v["e2e_rx"]
            .get("active")
            .and_then(|v| v.as_str())
            == Some(bootstrap_id_hex.as_str())
        {
            self_v["e2e_rx"]["active"] = json!("");
        }

        if self_v.get("prekeys_local_public").is_none() {
            self_v["prekeys_local_public"] = json!([]);
        }
        if self_v.get("prekeys_advertised").is_none() {
            self_v["prekeys_advertised"] = json!(false);
        }

        Ok(())
    })
}

pub(crate) fn self_bootstrap_rx_privs(
    self_v: &SecretJson,
    to_id: &[u8; 32],
) -> Option<(Byte32, SecretBytes)> {
    self_v.with_exposed(|self_v| {
        let x_pub_hex = self_v.get("x_pub")?.as_str()?;
        let k_pub_hex = self_v.get("k_pub")?.as_str()?;
        let bootstrap_id = id_from_peer_pubs(x_pub_hex, k_pub_hex).ok()?;

        if &bootstrap_id != to_id {
            return None;
        }

        let x_priv_hex = self_v.get("x_priv")?.as_str()?;
        let k_priv_hex = self_v.get("k_priv")?.as_str()?;

        let x_priv = Byte32::from_hex(x_priv_hex.trim()).ok()?;
        let k_priv = SecretBytes::from_hex(k_priv_hex.trim()).ok()?;

        Some((x_priv, k_priv))
    })
}

pub(crate) fn self_next_seq(self_v: &mut SecretJson) -> u64 {
    self_v.with_exposed_mut(|self_v| {
        let n = self_v["e2e_rx"]["next_seq"].as_u64().unwrap_or(1);
        self_v["e2e_rx"]["next_seq"] = json!(n + 1);
        n
    })
}

pub(crate) fn self_find_seq(self_v: &SecretJson, to_id: &[u8; 32]) -> Option<u64> {
    self_v.with_exposed(|self_v| {
        let id_hex = hex::encode(to_id);
        let keys = self_v.get("e2e_rx")?.get("keys")?.as_object()?;
        let item = keys.get(&id_hex)?.as_object()?;
        item.get("seq")?.as_u64()
    })
}

pub(crate) fn self_get_rx_privs(self_v: &SecretJson, to_id: &[u8; 32]) -> Option<(Byte32, SecretBytes)> {
    self_v.with_exposed(|self_v| {
        let id_hex = hex::encode(to_id);
        let keys = self_v.get("e2e_rx")?.get("keys")?.as_object()?;
        let item = keys.get(&id_hex)?.as_object()?;

        let x_priv_hex = item.get("x_priv")?.as_str()?;
        let k_priv_hex = item.get("k_priv")?.as_str()?;

        Some((
            Byte32::from_hex(x_priv_hex.trim()).ok()?,
            SecretBytes::from_hex(k_priv_hex.trim()).ok()?,
        ))
    })
}

pub(crate) fn gc_after_ack(self_v: &mut SecretJson) {
    self_v.with_exposed_mut(|self_v| {
        let window = self_v["e2e_rx"]["window"].as_u64().unwrap_or(DEFAULT_WINDOW);
        let ack = self_v["e2e_rx"]["ack_seq"].as_u64().unwrap_or(0);
        let min_keep_seq = ack.saturating_sub(window);

        let mut remove: Vec<String> = Vec::new();

        if let Some(keys) = self_v["e2e_rx"]["keys"].as_object() {
            for (k, v) in keys.iter() {
                let seq = v.get("seq").and_then(|x| x.as_u64()).unwrap_or(0);
                if seq == 0 {
                    continue;
                }
                if seq < min_keep_seq {
                    remove.push(k.clone());
                }
            }
        }

        if let Some(keys) = self_v["e2e_rx"]["keys"].as_object_mut() {
            for k in remove {
                drop_removed_json_key(keys, &k);
            }
        }
    });
}

pub(crate) fn next_tx_step(self_v: &mut SecretJson) -> u64 {
    self_v.with_exposed_mut(|self_v| {
        let step = self_v["e2e_tx"]["step"].as_u64().unwrap_or(0) + 1;
        self_v["e2e_tx"]["step"] = json!(step);
        step
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::invite_codec::gen_self_state;

    #[test]
    fn ensure_self_keyring_initializes_e2e_fields() {
        let (_cid, mut sj) = gen_self_state().unwrap();
        ensure_self_keyring(&mut sj).unwrap();

        sj.with_exposed(|v| {
            assert!(v.get("e2e_tx").is_some(), "e2e_tx must be initialized");
            assert!(v.get("e2e_rx").is_some(), "e2e_rx must be initialized");
            assert!(v.get("bootstrap").is_some(), "bootstrap must be initialized");
            assert!(v["e2e_rx"]["active"].is_string());
            assert_eq!(v["e2e_rx"]["ack_seq"].as_u64(), Some(0));
            assert_eq!(v["e2e_rx"]["next_seq"].as_u64(), Some(1));
            assert_eq!(v["e2e_rx"]["window"].as_u64(), Some(DEFAULT_WINDOW));
        });
    }

    #[test]
    fn ensure_self_keyring_idempotent() {
        let (_cid, mut sj) = gen_self_state().unwrap();
        ensure_self_keyring(&mut sj).unwrap();
        let ack_before = sj.with_exposed(|v| v["e2e_rx"]["ack_seq"].as_u64());
        ensure_self_keyring(&mut sj).unwrap();
        let ack_after = sj.with_exposed(|v| v["e2e_rx"]["ack_seq"].as_u64());
        assert_eq!(ack_before, ack_after);
    }

    #[test]
    fn mark_bootstrap_retire_ready_sets_flag() {
        let (_cid, mut sj) = gen_self_state().unwrap();
        ensure_self_keyring(&mut sj).unwrap();
        mark_bootstrap_retire_ready(&mut sj);

        let flag = sj.with_exposed(|v| {
            v.get("bootstrap")
                .and_then(|b| b.get("retire_ok"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        });
        assert!(flag, "retire_ok must be true after mark");
    }
}