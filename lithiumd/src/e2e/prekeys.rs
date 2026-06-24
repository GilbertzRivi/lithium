use lithium_core::{
    crypto::keys,
    error::{LithiumError, Result},
    secrets::{Byte32, ZeroizingWriter, bytes::SecretBytes},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::state::{LocalPrekeyPublic, SelfState};
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

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct LocalPrekeyPrivOwned {
    x_priv: String,
    k_priv: String,
}

pub fn gen_local_prekey_material() -> Result<(String, SecretBytes, LocalPrekeyPublic)> {
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
        let mut w = ZeroizingWriter::new();
        serde_json::to_writer(&mut w, &priv_state).map_err(LithiumError::json_parse)?;
        w.into_secret()
    };

    let public_item = LocalPrekeyPublic {
        id: id_hex.expose().to_owned(),
        x_pub: x_pub_hex.expose().to_owned(),
        k_pub: k_pub_hex.expose().to_owned(),
        created_at_ms,
    };

    Ok((id_hex.expose().to_owned(), priv_blob, public_item))
}

pub fn prekey_blob_to_privs(blob: &SecretBytes) -> Result<(Byte32, SecretBytes)> {
    let parsed: LocalPrekeyPrivOwned =
        serde_json::from_slice(blob.expose_as_slice()).map_err(LithiumError::json_parse)?;

    Ok((
        Byte32::from_hex(parsed.x_priv.trim())?,
        SecretBytes::from_hex(parsed.k_priv.trim())?,
    ))
}

pub fn prekeys_should_advertise(self_st: &SelfState) -> bool {
    !self_st.prekeys_advertised
}

pub fn prekeys_mark_advertised(self_st: &mut SelfState) {
    self_st.prekeys_advertised = true;
}

pub fn local_public_prekeys(self_st: &SelfState) -> Vec<Value> {
    self_st
        .prekeys_local_public
        .iter()
        .filter_map(|p| serde_json::to_value(p).ok())
        .collect()
}

pub fn local_remove_public_prekey(self_st: &mut SelfState, id_hex: &str) {
    self_st.prekeys_local_public.retain(|p| p.id != id_hex);
    self_st.prekeys_advertised = false;
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
        assert_eq!(pub_item.id, id_hex);
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
        let (_cid, mut st) = gen_self_state().unwrap();
        ensure_self_keyring(&mut st).unwrap();
        assert!(prekeys_should_advertise(&st));
    }

    #[test]
    fn prekeys_mark_advertised_clears_flag() {
        let (_cid, mut st) = gen_self_state().unwrap();
        ensure_self_keyring(&mut st).unwrap();
        prekeys_mark_advertised(&mut st);
        assert!(!prekeys_should_advertise(&st));
    }

    #[test]
    fn local_public_prekeys_empty_initially() {
        let (_cid, mut st) = gen_self_state().unwrap();
        ensure_self_keyring(&mut st).unwrap();
        assert!(local_public_prekeys(&st).is_empty());
    }
}
