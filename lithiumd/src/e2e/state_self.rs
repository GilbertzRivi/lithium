use lithium_core::{
    error::{LithiumError, Result},
    secrets::{Byte32, SecretJson, bytes::SecretBytes},
};
use serde_json::json;

use crate::state_fields as sf;

use serde_json::Value;

use super::{
    crypto::id_from_peer_pubs,
    state::{BootstrapState, E2eRx, RxKey},
    wire::{drop_removed_json_key, now_ms},
};

fn load_bootstrap(self_v: &Value) -> BootstrapState {
    self_v
        .get(sf::BOOTSTRAP)
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default()
}

pub(crate) fn load_e2e_rx(self_v: &Value) -> E2eRx {
    self_v
        .get(sf::E2E_RX)
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default()
}

pub(crate) fn store_e2e_rx(self_v: &mut Value, rx: &E2eRx) {
    if let Ok(v) = serde_json::to_value(rx) {
        // Zeroize the prior receive keys instead of letting the old Value drop in clear.
        drop(SecretJson::from(std::mem::replace(&mut self_v[sf::E2E_RX], v)));
    }
}

pub(crate) fn set_active_reply_key(self_v: &mut Value, id_hex: &str, key: RxKey) {
    let mut rx = load_e2e_rx(self_v);
    rx.active = id_hex.to_owned();
    rx.keys.insert(id_hex.to_owned(), key);
    store_e2e_rx(self_v, &rx);
}

pub(crate) fn advance_ack(self_v: &mut Value, seq: u64) {
    let mut rx = load_e2e_rx(self_v);
    if seq > rx.ack_seq {
        rx.ack_seq = seq;
        store_e2e_rx(self_v, &rx);
    }
}

pub fn drop_bootstrap_private_if_established(self_v: &mut SecretJson, peer_v: &SecretJson) {
    let peer_established = peer_v.with_exposed(|peer_v| peer_v.get(sf::E2E_PEER).is_some());

    let retire_ok = self_v.with_exposed(|self_v| {
        load_e2e_rx(self_v).ack_seq > 0 || load_bootstrap(self_v).retire_ok
    });

    if !(peer_established && retire_ok) {
        return;
    }

    self_v.with_exposed_mut(|self_v| {
        if let Some(obj) = self_v.as_object_mut() {
            drop_removed_json_key(obj, sf::X_PRIV);
            drop_removed_json_key(obj, sf::K_PRIV);
        }

        let mut b = load_bootstrap(self_v);
        b.rx_used = true;
        b.retire_ok = true;
        b.retired_at_ms = now_ms();
        if let Ok(v) = serde_json::to_value(b) {
            self_v[sf::BOOTSTRAP] = v;
        }
    });
}

pub fn mark_bootstrap_retire_ready(self_v: &mut SecretJson) {
    self_v.with_exposed_mut(|self_v| {
        let mut b = load_bootstrap(self_v);
        b.retire_ok = true;
        if let Ok(v) = serde_json::to_value(b) {
            self_v[sf::BOOTSTRAP] = v;
        }
    });
}

pub fn ensure_self_keyring(self_v: &mut SecretJson) -> Result<()> {
    self_v.with_exposed_mut(|self_v| {
        if self_v.get(sf::E2E_TX).is_none() {
            self_v[sf::E2E_TX] = json!({ sf::STEP: 0u64 });
        }

        if let Ok(v) = serde_json::to_value(load_bootstrap(self_v)) {
            self_v[sf::BOOTSTRAP] = v;
        }

        let mut rx = load_e2e_rx(self_v);

        let x_pub = self_v
            .get(sf::X_PUB)
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("x_pub"))?
            .to_string();
        let k_pub = self_v
            .get(sf::K_PUB)
            .and_then(|v| v.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("k_pub"))?
            .to_string();

        let bootstrap_id_hex = hex::encode(id_from_peer_pubs(&x_pub, &k_pub)?);

        // Remove any stale seq=0 bootstrap slot from the ratchet key map.
        if rx.keys.get(&bootstrap_id_hex).map(|k| k.seq) == Some(0) {
            rx.keys.remove(&bootstrap_id_hex);
        }

        if rx.active == bootstrap_id_hex {
            rx.active = String::new();
        }

        store_e2e_rx(self_v, &rx);

        if self_v.get(sf::PREKEYS_LOCAL_PUBLIC).is_none() {
            self_v[sf::PREKEYS_LOCAL_PUBLIC] = json!([]);
        }
        if self_v.get(sf::PREKEYS_ADVERTISED).is_none() {
            self_v[sf::PREKEYS_ADVERTISED] = json!(false);
        }

        Ok(())
    })
}

pub(crate) fn self_bootstrap_rx_privs(
    self_v: &SecretJson,
    to_id: &[u8; 32],
) -> Option<(Byte32, SecretBytes)> {
    self_v.with_exposed(|self_v| {
        let x_pub_hex = self_v.get(sf::X_PUB)?.as_str()?;
        let k_pub_hex = self_v.get(sf::K_PUB)?.as_str()?;
        let bootstrap_id = id_from_peer_pubs(x_pub_hex, k_pub_hex).ok()?;

        if &bootstrap_id != to_id {
            return None;
        }

        let x_priv_hex = self_v.get(sf::X_PRIV)?.as_str()?;
        let k_priv_hex = self_v.get(sf::K_PRIV)?.as_str()?;

        let x_priv = Byte32::from_hex(x_priv_hex.trim()).ok()?;
        let k_priv = SecretBytes::from_hex(k_priv_hex.trim()).ok()?;

        Some((x_priv, k_priv))
    })
}

pub(crate) fn self_next_seq(self_v: &mut SecretJson) -> u64 {
    self_v.with_exposed_mut(|self_v| {
        let mut rx = load_e2e_rx(self_v);
        let n = rx.next_seq;
        rx.next_seq = n + 1;
        store_e2e_rx(self_v, &rx);
        n
    })
}

pub(crate) fn self_find_seq(self_v: &SecretJson, to_id: &[u8; 32]) -> Option<u64> {
    self_v.with_exposed(|self_v| load_e2e_rx(self_v).keys.get(&hex::encode(to_id)).map(|k| k.seq))
}

pub(crate) fn self_get_rx_privs(self_v: &SecretJson, to_id: &[u8; 32]) -> Option<(Byte32, SecretBytes)> {
    self_v.with_exposed(|self_v| {
        let rx = load_e2e_rx(self_v);
        let rk = rx.keys.get(&hex::encode(to_id))?;
        Some((
            Byte32::from_hex(rk.x_priv.trim()).ok()?,
            SecretBytes::from_hex(rk.k_priv.trim()).ok()?,
        ))
    })
}

pub(crate) fn gc_after_ack(self_v: &mut SecretJson) {
    self_v.with_exposed_mut(|self_v| {
        let mut rx = load_e2e_rx(self_v);
        let min_keep_seq = rx.ack_seq.saturating_sub(rx.window);
        rx.keys.retain(|_, k| k.seq == 0 || k.seq >= min_keep_seq);
        store_e2e_rx(self_v, &rx);
    });
}

pub(crate) fn next_tx_step(self_v: &mut SecretJson) -> u64 {
    self_v.with_exposed_mut(|self_v| {
        let step = self_v[sf::E2E_TX][sf::STEP].as_u64().unwrap_or(0) + 1;
        self_v[sf::E2E_TX][sf::STEP] = json!(step);
        step
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::invite_codec::gen_self_state;
    use crate::e2e::wire::DEFAULT_WINDOW;

    #[test]
    fn ensure_self_keyring_initializes_e2e_fields() {
        let (_cid, mut sj) = gen_self_state().unwrap();
        ensure_self_keyring(&mut sj).unwrap();

        sj.with_exposed(|v| {
            assert!(v.get(sf::E2E_TX).is_some(), "e2e_tx must be initialized");
            assert!(v.get(sf::E2E_RX).is_some(), "e2e_rx must be initialized");
            assert!(v.get(sf::BOOTSTRAP).is_some(), "bootstrap must be initialized");
            let rx = load_e2e_rx(v);
            assert!(rx.active.is_empty());
            assert_eq!(rx.ack_seq, 0);
            assert_eq!(rx.next_seq, 1);
            assert_eq!(rx.window, DEFAULT_WINDOW);
        });
    }

    #[test]
    fn ensure_self_keyring_idempotent() {
        let (_cid, mut sj) = gen_self_state().unwrap();
        ensure_self_keyring(&mut sj).unwrap();
        let ack_before = sj.with_exposed(|v| load_e2e_rx(v).ack_seq);
        ensure_self_keyring(&mut sj).unwrap();
        let ack_after = sj.with_exposed(|v| load_e2e_rx(v).ack_seq);
        assert_eq!(ack_before, ack_after);
    }

    #[test]
    fn mark_bootstrap_retire_ready_sets_flag() {
        let (_cid, mut sj) = gen_self_state().unwrap();
        ensure_self_keyring(&mut sj).unwrap();
        mark_bootstrap_retire_ready(&mut sj);

        let flag = sj.with_exposed(|v| load_bootstrap(v).retire_ok);
        assert!(flag, "retire_ok must be true after mark");
    }
}