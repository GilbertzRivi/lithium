// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use pqcrypto::kem::mlkem1024::{
    Ciphertext as KyberCiphertext, PublicKey as KyberPublicKey, SecretKey as KyberSecretKey,
    SharedSecret as KyberSharedSecret, decapsulate as kyber_decapsulate,
    encapsulate as kyber_encapsulate,
};
use pqcrypto::traits::kem::{
    Ciphertext as TraitKyberCiphertext, PublicKey as TraitKyberPublicKey,
    SecretKey as TraitKyberSecretKey, SharedSecret as TraitKyberSharedSecret,
};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

use crate::{
    crypto::{aead, kdf, keys},
    error::{LithiumError, Result},
    secrets::{Byte32, bytes::SecretBytes},
};

const KYBER_BOX_VERSION: u8 = 1;
const KYBER_KEM_ID: u8 = 1;

#[derive(Clone, Debug)]
pub struct WirePayload {
    pub enc_body: SecretBytes,
    pub enc_headers: SecretBytes,
    pub kem_ct: SecretBytes,
}

#[inline]
fn label(ctx: &str, part: &str) -> SecretBytes {
    SecretBytes::new(format!("{ctx}/{part}/v1").into_bytes())
}

#[inline]
fn derive_ecdh_key(priv_x: &Byte32, peer_pub_x: &Byte32, ctx: &str) -> Result<Byte32> {
    let my_secret = XStaticSecret::from(*priv_x.as_array());
    let peer_pub = XPublicKey::from(*peer_pub_x.as_array());
    let shared = my_secret.diffie_hellman(&peer_pub);

    if !shared.was_contributory() {
        return Err(LithiumError::invalid_credentials("x25519_low_order"));
    }

    let shared_secret = Byte32::new(shared.to_bytes());

    kdf::derive32(
        &SecretBytes::from_slice(shared_secret.as_slice()),
        None,
        &label(ctx, "ecdh-key"),
    )
}

// UniversalCombiner (draft-irtf-cfrg-hybrid-kems): HKDF-Extract dual-PRF over ss_kem (salt) and
// ecdh_key (IKM). ct_t/ek_t are bound explicitly because X25519 has no binding of its own; ek_PQ
// is already bound inside ss_kem by ML-KEM's H(ek), so only ct_PQ is added.
#[inline]
fn derive_base_key(
    ss_kem: &Byte32,
    ecdh_key: &Byte32,
    ct_t: &[u8; 32],
    ek_t: &[u8; 32],
    ct_pq_hash: &[u8; 32],
    ctx: &str,
) -> Result<Byte32> {
    let ecdh_input = SecretBytes::from_slice(ecdh_key.as_slice());
    let ss_salt = SecretBytes::from_slice(ss_kem.as_slice());

    let mut info = label(ctx, "base-key").expose_as_slice().to_vec();
    info.extend_from_slice(ct_t);
    info.extend_from_slice(ek_t);
    info.extend_from_slice(ct_pq_hash);

    kdf::derive32(&ecdh_input, Some(&ss_salt), &SecretBytes::new(info))
}

#[inline]
fn derive_body_key(base_key: &Byte32, ctx: &str) -> Result<Byte32> {
    kdf::derive32(
        &SecretBytes::from_slice(base_key.as_slice()),
        None,
        &label(ctx, "body-key"),
    )
}

#[inline]
fn derive_headers_key(base_key: &Byte32, ctx: &str) -> Result<Byte32> {
    kdf::derive32(
        &SecretBytes::from_slice(base_key.as_slice()),
        None,
        &label(ctx, "headers-key"),
    )
}

fn encapsulate_kem(peer_kyber_pub: &[u8]) -> Result<(Byte32, [u8; 32], SecretBytes)> {
    let pk = KyberPublicKey::from_bytes(peer_kyber_pub).map_err(|_| LithiumError::internal())?;

    let (ss, ct_kem): (KyberSharedSecret, KyberCiphertext) = kyber_encapsulate(&pk);
    let ss_bytes = Byte32::from_slice(ss.as_bytes()).map_err(|_| LithiumError::internal())?;

    let ct_bytes = ct_kem.as_bytes();
    let mut ct_hash = [0u8; 32];
    ct_hash.copy_from_slice(Sha256::digest(ct_bytes).as_slice());

    let mut blob = Vec::with_capacity(2 + ct_bytes.len());
    blob.push(KYBER_BOX_VERSION);
    blob.push(KYBER_KEM_ID);
    blob.extend_from_slice(ct_bytes);

    Ok((ss_bytes, ct_hash, SecretBytes::new(blob)))
}

fn decapsulate_kem(kyber_priv_bytes: &[u8], blob: &[u8]) -> Result<(Byte32, [u8; 32])> {
    if blob.len() < 2 {
        return Err(LithiumError::internal());
    }
    if blob[0] != KYBER_BOX_VERSION || blob[1] != KYBER_KEM_ID {
        return Err(LithiumError::internal());
    }
    let ct_slice = &blob[2..];

    let mut ct_hash = [0u8; 32];
    ct_hash.copy_from_slice(Sha256::digest(ct_slice).as_slice());

    let sk = KyberSecretKey::from_bytes(kyber_priv_bytes).map_err(|_| LithiumError::internal())?;
    let ct = KyberCiphertext::from_bytes(ct_slice).map_err(|_| LithiumError::internal())?;
    let ss: KyberSharedSecret = kyber_decapsulate(&ct, &sk);
    let ss_bytes = Byte32::from_slice(ss.as_bytes()).map_err(|_| LithiumError::internal())?;

    Ok((ss_bytes, ct_hash))
}

pub fn encrypt(
    ctx: &str,
    priv_x: &Byte32,
    peer_pub_x: &Byte32,
    peer_k_pub: &SecretBytes,
    body: &SecretBytes,
    headers: &SecretBytes,
) -> Result<WirePayload> {
    let ecdh_key = derive_ecdh_key(priv_x, peer_pub_x, ctx)?;

    let ct_t = *XPublicKey::from(&XStaticSecret::from(*priv_x.as_array())).as_bytes();
    let ek_t = *peer_pub_x.as_array();

    let (ss_kem, ct_hash, kem_ct) = encapsulate_kem(peer_k_pub.expose_as_slice())?;

    let base_key = derive_base_key(&ss_kem, &ecdh_key, &ct_t, &ek_t, &ct_hash, ctx)?;
    let body_key = derive_body_key(&base_key, ctx)?;
    let headers_key = derive_headers_key(&base_key, ctx)?;

    let body_nonce = keys::random_12()?;
    let headers_nonce = keys::random_12()?;

    let enc_body = aead::encrypt(body, &body_key, &body_nonce, &label(ctx, "body"))?;

    let enc_headers = aead::encrypt(
        headers,
        &headers_key,
        &headers_nonce,
        &label(ctx, "headers"),
    )?;

    Ok(WirePayload {
        enc_body,
        enc_headers,
        kem_ct,
    })
}

pub fn decrypt(
    ctx: &str,
    priv_x: &Byte32,
    peer_pub_x: &Byte32,
    kyber_priv: &SecretBytes,
    wire: &WirePayload,
) -> Result<(SecretBytes, SecretBytes)> {
    let ecdh_key = derive_ecdh_key(priv_x, peer_pub_x, ctx)?;

    let ct_t = *peer_pub_x.as_array();
    let ek_t = *XPublicKey::from(&XStaticSecret::from(*priv_x.as_array())).as_bytes();

    let (ss_kem, ct_hash) =
        decapsulate_kem(kyber_priv.expose_as_slice(), wire.kem_ct.expose_as_slice())?;

    let base_key = derive_base_key(&ss_kem, &ecdh_key, &ct_t, &ek_t, &ct_hash, ctx)?;
    let body_key = derive_body_key(&base_key, ctx)?;
    let headers_key = derive_headers_key(&base_key, ctx)?;

    let dec_body = aead::decrypt(&wire.enc_body, &body_key, &label(ctx, "body"))?;

    let dec_headers = aead::decrypt(&wire.enc_headers, &headers_key, &label(ctx, "headers"))?;

    Ok((dec_body, dec_headers))
}
