use hkdf::Hkdf;
use pqcrypto::kem::mlkem1024::{
    Ciphertext as KyberCiphertext,
    PublicKey as KyberPublicKey,
    SecretKey as KyberSecretKey,
    SharedSecret as KyberSharedSecret,
    decapsulate as kyber_decapsulate,
    encapsulate as kyber_encapsulate,
};
use pqcrypto::traits::kem::{
    Ciphertext as TraitKyberCiphertext,
    PublicKey as TraitKyberPublicKey,
    SecretKey as TraitKyberSecretKey,
    SharedSecret as TraitKyberSharedSecret,
};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

use crate::{
    crypto::{aead, kdf, keys},
    error::{LithiumError, Result},
    secrets::{Byte32, bytes::SecretBytes},
};

const AEAD_VERSION: u8 = 1;
const KYBER_BOX_VERSION: u8 = 1;
const KYBER_KEM_ID: u8 = 1;
const KYBER_AEAD_ID: u8 = 1;
const KYBER_SALT_LEN: u8 = 32;
const KYBERBOX_AAD_PREFIX: &[u8] = b"kyberbox/v1|kem=mlkem1024|aead=aes256-gcm-siv|";
const KYBER_KEMDEM_INFO: &[u8] = b"kemdem/kyber-mlkem1024/v1";

#[derive(Clone, Debug)]
pub struct WirePayload {
    pub enc_body: SecretBytes,
    pub enc_headers: SecretBytes,
    pub seed_enc: SecretBytes,
}

#[inline]
fn label(ctx: &str, part: &str) -> SecretBytes {
    SecretBytes::from_vec(format!("{ctx}/{part}/v1").into_bytes())
}

#[inline]
fn derive_ecdh_key(priv_x: &Byte32, peer_pub_x: &Byte32, ctx: &str) -> Result<Byte32> {
    let my_secret = XStaticSecret::from(*priv_x.as_array());
    let peer_pub = XPublicKey::from(*peer_pub_x.as_array());
    let shared = my_secret.diffie_hellman(&peer_pub);

    kdf::derive32(
        &SecretBytes::from_slice(shared.as_bytes()),
        None,
        &label(ctx, "ecdh-key"),
    )
}

#[inline]
fn derive_base_key(ecdh_key: &Byte32, seed_plain: &SecretBytes, ctx: &str) -> Result<Byte32> {
    kdf::derive32(
        &SecretBytes::from_slice(ecdh_key.as_slice()),
        Some(seed_plain),
        &label(ctx, "base-key"),
    )
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

fn encrypt_kyber_seed(peer_kyber_pub: &[u8], plaintext: &[u8], user_aad: &[u8]) -> Result<SecretBytes> {
    let pk = KyberPublicKey::from_bytes(peer_kyber_pub).map_err(|_| LithiumError::internal())?;

    let (ss_bytes, ct_kem) = {
        let (ss, ct_kem): (KyberSharedSecret, KyberCiphertext) = kyber_encapsulate(&pk);
        let ss_bytes = SecretBytes::from_slice(ss.as_bytes());
        (ss_bytes, ct_kem)
    };

    let ct_bytes = ct_kem.as_bytes();
    let salt_arr = Sha256::digest(ct_bytes);

    let mut aead_key = Byte32::new_zeroed();
    let hk = Hkdf::<Sha256>::new(Some(salt_arr.as_slice()), ss_bytes.as_slice());
    hk.expand(KYBER_KEMDEM_INFO, aead_key.as_mut_slice())
        .map_err(|_| LithiumError::kdf_failed())?;

    let mut header = Vec::with_capacity(1 + 1 + 1 + 1 + 32);
    header.push(KYBER_BOX_VERSION);
    header.push(KYBER_KEM_ID);
    header.push(KYBER_AEAD_ID);
    header.push(KYBER_SALT_LEN);
    header.extend_from_slice(salt_arr.as_slice());

    let mut aad_full = Vec::with_capacity(1 + KYBERBOX_AAD_PREFIX.len() + header.len() + user_aad.len());
    aad_full.push(AEAD_VERSION);
    aad_full.extend_from_slice(KYBERBOX_AAD_PREFIX);
    aad_full.extend_from_slice(&header);
    aad_full.extend_from_slice(user_aad);

    let nonce = keys::random_12()?;
    let aead_blob = aead::encrypt(
        &SecretBytes::from_slice(plaintext),
        &aead_key,
        &nonce,
        &SecretBytes::from_vec(aad_full),
    )?;

    if ct_bytes.len() > u16::MAX as usize {
        return Err(LithiumError::internal());
    }

    let mut out = Vec::with_capacity(header.len() + 2 + ct_bytes.len() + aead_blob.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&(ct_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(ct_bytes);
    out.extend_from_slice(aead_blob.as_slice());

    Ok(SecretBytes::from_vec(out))
}

fn decrypt_kyber_seed(kyber_priv_bytes: &[u8], blob: &[u8], user_aad: &[u8]) -> Result<SecretBytes> {
    if blob.len() < 1 + 1 + 1 + 1 + 32 + 2 {
        return Err(LithiumError::internal());
    }

    let ver = blob[0];
    let kem_id = blob[1];
    let aead_id = blob[2];
    let salt_len = blob[3] as usize;

    if ver != KYBER_BOX_VERSION
        || kem_id != KYBER_KEM_ID
        || aead_id != KYBER_AEAD_ID
        || salt_len != 32
    {
        return Err(LithiumError::internal());
    }

    let salt = &blob[4..4 + 32];
    let mut idx = 4 + 32;

    if blob.len() < idx + 2 {
        return Err(LithiumError::internal());
    }
    let ct_len = u16::from_be_bytes([blob[idx], blob[idx + 1]]) as usize;
    idx += 2;

    if blob.len() < idx + ct_len {
        return Err(LithiumError::internal());
    }
    let ct_slice = &blob[idx..idx + ct_len];
    idx += ct_len;
    let aead_blob = &blob[idx..];

    let salt_ref = Sha256::digest(ct_slice);
    if salt_ref.as_slice() != salt {
        return Err(LithiumError::internal());
    }

    let ss_bytes = {
        let sk = KyberSecretKey::from_bytes(kyber_priv_bytes).map_err(|_| LithiumError::internal())?;
        let ct = KyberCiphertext::from_bytes(ct_slice).map_err(|_| LithiumError::internal())?;
        let ss: KyberSharedSecret = kyber_decapsulate(&ct, &sk);
        SecretBytes::from_slice(ss.as_bytes())
    };

    let mut aead_key = Byte32::new_zeroed();
    let hk = Hkdf::<Sha256>::new(Some(salt), ss_bytes.as_slice());
    hk.expand(KYBER_KEMDEM_INFO, aead_key.as_mut_slice())
        .map_err(|_| LithiumError::kdf_failed())?;

    let mut header = Vec::with_capacity(1 + 1 + 1 + 1 + 32);
    header.push(ver);
    header.push(kem_id);
    header.push(aead_id);
    header.push(KYBER_SALT_LEN);
    header.extend_from_slice(salt);

    let mut aad_full = Vec::with_capacity(1 + KYBERBOX_AAD_PREFIX.len() + header.len() + user_aad.len());
    aad_full.push(AEAD_VERSION);
    aad_full.extend_from_slice(KYBERBOX_AAD_PREFIX);
    aad_full.extend_from_slice(&header);
    aad_full.extend_from_slice(user_aad);

    aead::decrypt(
        &SecretBytes::from_slice(aead_blob),
        &aead_key,
        &SecretBytes::from_vec(aad_full),
    )
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

    let seed_plain = keys::random_32()?;
    let seed_enc = encrypt_kyber_seed(
        peer_k_pub.as_slice(),
        seed_plain.as_slice(),
        label(ctx, "seed").as_slice(),
    )?;

    let base_key = derive_base_key(&ecdh_key, &SecretBytes::from_slice(seed_plain.as_slice()), ctx)?;
    let body_key = derive_body_key(&base_key, ctx)?;
    let headers_key = derive_headers_key(&base_key, ctx)?;

    let body_nonce = keys::random_12()?;
    let headers_nonce = keys::random_12()?;

    let enc_body = aead::encrypt(
        body,
        &body_key,
        &body_nonce,
        &label(ctx, "body"),
    )?;

    let enc_headers = aead::encrypt(
        headers,
        &headers_key,
        &headers_nonce,
        &label(ctx, "headers"),
    )?;

    Ok(WirePayload {
        enc_body,
        enc_headers,
        seed_enc,
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

    let seed_plain = decrypt_kyber_seed(
        kyber_priv.as_slice(),
        wire.seed_enc.as_slice(),
        label(ctx, "seed").as_slice(),
    )?;

    let base_key = derive_base_key(&ecdh_key, &seed_plain, ctx)?;
    let body_key = derive_body_key(&base_key, ctx)?;
    let headers_key = derive_headers_key(&base_key, ctx)?;

    let dec_body = aead::decrypt(
        &wire.enc_body,
        &body_key,
        &label(ctx, "body"),
    )?;

    let dec_headers = aead::decrypt(
        &wire.enc_headers,
        &headers_key,
        &label(ctx, "headers"),
    )?;

    Ok((dec_body, dec_headers))
}