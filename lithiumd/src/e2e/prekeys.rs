use lithium_core::{
    crypto::keys,
    error::{LithiumError, Result},
    secrets::{Byte32, SecretJson, bytes::SecretBytes},
};
use serde::Serialize;
use serde_json::{Value, json};

use super::wire::now_ms;

#[derive(Serialize)]
struct LocalPrekeyPriv<'a> {
    v: u8,
    id: &'a str,
    x_priv: &'a str,
    x_pub: &'a str,
    k_priv: &'a str,
    k_pub: &'a str,
    created_at_ms: u64,
}

// Returns (id_hex, priv_blob, public_item { id, x_pub, k_pub, created_at_ms }).
pub fn gen_local_prekey_material() -> Result<(String, SecretBytes, Value)> {
    let id = keys::random_32()?;
    let id_hex = id.to_hex();

    let (x_priv_fb, x_pub_fb) = keys::random_x25519_keypair()?;
    let x_priv_hex = x_priv_fb.to_hex();
    let x_pub_hex = x_pub_fb.to_hex();

    let (k_priv, k_pub) = keys::random_kyber_mlkem1024_keypair()?;
    let k_priv_hex = k_priv.to_hex();
    let k_pub_hex = k_pub.to_hex();

    let created_at_ms = now_ms();

    let priv_state = LocalPrekeyPriv {
        v: 1,
        id: id_hex.expose(),
        x_priv: x_priv_hex.expose(),
        x_pub: x_pub_hex.expose(),
        k_priv: k_priv_hex.expose(),
        k_pub: k_pub_hex.expose(),
        created_at_ms,
    };

    let priv_blob = {
        let mut out = SecretBytes::new(Vec::new());
        serde_json::to_writer(out.expose_as_mut_vec(), &priv_state)
            .map_err(LithiumError::json_parse)?;
        out
    };

    let public_item = json!({
        "id": id_hex.expose(),
        "x_pub": x_pub_hex.expose(),
        "k_pub": k_pub_hex.expose(),
        "created_at_ms": created_at_ms
    });

    Ok((id_hex.expose().to_owned(), priv_blob, public_item))
}

pub fn prekey_blob_to_privs(blob: &SecretBytes) -> Result<(Byte32, SecretBytes)> {
    let v = SecretJson::from_bytes(blob.expose_as_slice())?;

    v.with_exposed(|v| -> Result<(Byte32, SecretBytes)> {
        let x_priv_hex = v
            .get("x_priv")
            .and_then(|x| x.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("x_priv"))?;
        let k_priv_hex = v
            .get("k_priv")
            .and_then(|x| x.as_str())
            .ok_or_else(|| LithiumError::json_missing_field("k_priv"))?;

        Ok((
            Byte32::from_hex(x_priv_hex.trim())?,
            SecretBytes::from_hex(k_priv_hex.trim())?,
        ))
    })
}

pub fn prekeys_should_advertise(self_v: &SecretJson) -> bool {
    self_v.with_exposed(|self_v| {
        !self_v
            .get("prekeys_advertised")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    })
}

pub fn prekeys_mark_advertised(self_v: &mut SecretJson) {
    self_v.with_exposed_mut(|self_v| {
        self_v["prekeys_advertised"] = json!(true);
    });
}

pub fn local_public_prekeys(self_v: &SecretJson) -> Vec<Value> {
    self_v.with_exposed(|self_v| {
        self_v
            .get("prekeys_local_public")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
    })
}

pub fn local_remove_public_prekey(self_v: &mut SecretJson, id_hex: &str) {
    self_v.with_exposed_mut(|self_v| {
        let Some(arr) = self_v
            .get_mut("prekeys_local_public")
            .and_then(|v| v.as_array_mut())
        else {
            return;
        };
        arr.retain(|v| v.get("id").and_then(|x| x.as_str()) != Some(id_hex));
        self_v["prekeys_advertised"] = json!(false);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::invite_codec::gen_self_state;
    use crate::e2e::state_self::ensure_self_keyring;

    #[test]
    fn prekey_material_generated_successfully() {
        let (id_hex, blob, pub_item) = gen_local_prekey_material().unwrap();
        assert_eq!(id_hex.len(), 64, "id hex must be 64 chars (32 bytes)");
        assert!(!blob.expose_as_slice().is_empty());
        assert_eq!(pub_item.get("id").and_then(|v| v.as_str()), Some(id_hex.as_str()));
    }

    #[test]
    fn prekey_material_unique_each_time() {
        let (id1, _, _) = gen_local_prekey_material().unwrap();
        let (id2, _, _) = gen_local_prekey_material().unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn prekey_blob_to_privs_roundtrip() {
        let (_id, blob, _pub_item) = gen_local_prekey_material().unwrap();
        let (x_priv, k_priv) = prekey_blob_to_privs(&blob).unwrap();
        assert_eq!(x_priv.as_slice().len(), 32);
        assert!(!k_priv.expose_as_slice().is_empty());
    }

    #[test]
    fn prekey_blob_to_privs_garbage_fails() {
        let bad = SecretBytes::from_slice(b"not json");
        assert!(prekey_blob_to_privs(&bad).is_err());
    }

    #[test]
    fn prekeys_should_advertise_initially_true() {
        let (_cid, mut sj) = gen_self_state().unwrap();
        ensure_self_keyring(&mut sj).unwrap();
        assert!(prekeys_should_advertise(&sj));
    }

    #[test]
    fn prekeys_mark_advertised_clears_flag() {
        let (_cid, mut sj) = gen_self_state().unwrap();
        ensure_self_keyring(&mut sj).unwrap();
        prekeys_mark_advertised(&mut sj);
        assert!(!prekeys_should_advertise(&sj));
    }

    #[test]
    fn local_public_prekeys_empty_initially() {
        let (_cid, mut sj) = gen_self_state().unwrap();
        ensure_self_keyring(&mut sj).unwrap();
        assert!(local_public_prekeys(&sj).is_empty());
    }
}