// CONCATENATED *.rs FILES — 2026-03-13T02:17:20+01:00


// ===== FILE: ./src/crypto/aead.rs =====
// ----------------------------------------

use aes_gcm_siv::{aead::{Aead, KeyInit, Payload}, Aes256GcmSiv, Key, Nonce};

use crate::{error::{LithiumError, Result}, secrets::{Byte12, Byte32}, secrets::bytes::SecretBytes};

const AEAD_BLOB_VERSION: u8 = 1;

pub fn encrypt_raw(
    plaintext: &SecretBytes,
    key: &Byte32,
    nonce: &Byte12,
    aad: &SecretBytes,
) -> Result<SecretBytes> {
    let key: &Key<Aes256GcmSiv> = key
        .as_slice()
        .try_into()
        .map_err(|_| LithiumError::aead_failed())?;

    let nonce: &Nonce = nonce
        .as_slice()
        .try_into()
        .map_err(|_| LithiumError::aead_failed())?;

    let cipher = Aes256GcmSiv::new(key);
    let ct = cipher.encrypt(
        nonce,
        Payload {
            msg: plaintext.expose_as_slice(),
            aad: aad.expose_as_slice(),
        },
    )?;

    Ok(SecretBytes::from_vec(ct))
}

pub fn decrypt_raw(
    ciphertext: &SecretBytes,
    key: &Byte32,
    nonce: &Byte12,
    aad: &SecretBytes,
) -> Result<SecretBytes> {
    let key: &Key<Aes256GcmSiv> = key
        .as_slice()
        .try_into()
        .map_err(|_| LithiumError::aead_failed())?;

    let nonce: &Nonce = nonce
        .as_slice()
        .try_into()
        .map_err(|_| LithiumError::aead_failed())?;

    let cipher = Aes256GcmSiv::new(key);
    let pt = cipher.decrypt(
        nonce,
        Payload {
            msg: ciphertext.expose_as_slice(),
            aad: aad.expose_as_slice(),
        },
    )?;

    Ok(SecretBytes::from_vec(pt))
}

pub fn encrypt(plaintext: &SecretBytes, key: &Byte32, nonce: &Byte12, aad: &SecretBytes) -> Result<SecretBytes> {
    let ct = encrypt_raw(plaintext, key, nonce, aad)?;
    let mut out = Vec::with_capacity(1 + 12 + ct.len());
    out.push(AEAD_BLOB_VERSION);
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(ct.expose_as_slice());
    Ok(SecretBytes::from_vec(out))
}

pub fn decrypt(blob: &SecretBytes, key: &Byte32, aad: &SecretBytes) -> Result<SecretBytes> {
    if blob.len() < 1 + 12 + 16 { return Err(LithiumError::aead_failed()); }
    if blob.expose_as_slice()[0] != AEAD_BLOB_VERSION { return Err(LithiumError::aead_failed()); }
    let nonce = Byte12::from_slice(&blob.expose_as_slice()[1..13])?;
    let ct = SecretBytes::from_slice(&blob.expose_as_slice()[13..]);
    decrypt_raw(&ct, key, &nonce, aad)
}


// ===== FILE: ./src/crypto/kdf.rs =====
// ----------------------------------------

use hkdf::Hkdf;
use sha2::Sha256;

use crate::{error::Result, secrets::Byte32, secrets::bytes::SecretBytes};

pub fn derive32(input: &SecretBytes, salt: Option<&SecretBytes>, info: &SecretBytes) -> Result<Byte32> {
    let hk = Hkdf::<Sha256>::new(salt.map(|s| s.expose_as_slice()), input.expose_as_slice());
    let mut out = Byte32::new_zeroed();
    hk.expand(info.expose_as_slice(), out.as_mut_slice())?;
    Ok(out)
}

// ===== FILE: ./src/crypto/keys.rs =====
// ----------------------------------------

use ed25519_dalek::SigningKey;
use pqcrypto::kem::mlkem1024;
use pqcrypto::sign::mldsa87;
use pqcrypto::traits::kem::{PublicKey as _, SecretKey as _};
use pqcrypto::traits::sign::{PublicKey as SignPub, SecretKey as SignSk};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};
use rand::rngs::SysRng;
use rand::TryRng;
use crate::error::Result;
use crate::secrets::bytes::{FixedBytes, SecretBytes};
use crate::secrets::types::{MasterKey32, Nonce12, SessionId32};

#[inline]
pub fn random_fixed<const N: usize>() -> Result<FixedBytes<N>> {
    let mut out = FixedBytes::<N>::new_zeroed();
    let mut rng = SysRng;
    rng.try_fill_bytes(out.as_mut_slice())?;
    Ok(out)
}
#[inline]
pub fn random_12() -> Result<Nonce12> { Ok(random_fixed::<12>()?) }
#[inline]
pub fn random_32() -> Result<SessionId32> { Ok(random_fixed::<32>()?) }
#[inline]
pub fn random_master_key32() -> Result<MasterKey32> { Ok(random_fixed::<32>()?) }

#[inline]
pub fn random_x25519_keypair() -> Result<(FixedBytes<32>, FixedBytes<32>)> {
    let sk_seed = random_fixed::<32>()?;
    let secret = XStaticSecret::from(*sk_seed.as_array());
    let pk = XPublicKey::from(&secret);
    Ok((sk_seed, FixedBytes::new(*pk.as_bytes())))
}

#[inline]
pub fn random_ed25519_keypair() -> Result<(FixedBytes<32>, FixedBytes<32>)> {
    let seed = random_fixed::<32>()?;
    let signing = SigningKey::from_bytes(seed.as_array());
    let vk = signing.verifying_key().to_bytes();
    Ok((seed, FixedBytes::new(vk)))
}

#[inline]
pub fn random_kyber_mlkem1024_keypair() -> Result<(SecretBytes, SecretBytes)> {
    let (pk, sk) = mlkem1024::keypair();
    Ok((SecretBytes::from_slice(sk.as_bytes()), SecretBytes::from_slice(pk.as_bytes())))
}

#[inline]
pub fn random_dilithium_mldsa87_keypair() -> Result<(SecretBytes, SecretBytes)> {
    let (pk, sk) = mldsa87::keypair();
    Ok((SecretBytes::from_slice(SignSk::as_bytes(&sk)), SecretBytes::from_slice(SignPub::as_bytes(&pk))))
}


// ===== FILE: ./src/crypto/kyberbox.rs =====
// ----------------------------------------

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

    let shared_secret = Byte32::new(shared.to_bytes());

    kdf::derive32(
        &SecretBytes::from_slice(shared_secret.as_slice()),
        None,
        &label(ctx, "ecdh-key"),
    )
}

#[inline]
fn derive_base_key(ecdh_key: &Byte32, seed_plain: &Byte32, ctx: &str) -> Result<Byte32> {
    let ecdh_input = SecretBytes::from_slice(ecdh_key.as_slice());
    let seed_salt = SecretBytes::from_slice(seed_plain.as_slice());

    kdf::derive32(
        &ecdh_input,
        Some(&seed_salt),
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
        let ss_bytes = Byte32::from_slice(ss.as_bytes()).map_err(|_| LithiumError::internal())?;
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
    out.extend_from_slice(aead_blob.expose_as_slice());

    Ok(SecretBytes::from_vec(out))
}

fn decrypt_kyber_seed(kyber_priv_bytes: &[u8], blob: &[u8], user_aad: &[u8]) -> Result<Byte32> {
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
        Byte32::from_slice(ss.as_bytes()).map_err(|_| LithiumError::internal())?
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

    let seed_plain = aead::decrypt(
        &SecretBytes::from_slice(aead_blob),
        &aead_key,
        &SecretBytes::from_vec(aad_full),
    )?;

    Byte32::from_slice(seed_plain.expose_as_slice()).map_err(|_| LithiumError::internal())
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
        peer_k_pub.expose_as_slice(),
        seed_plain.as_slice(),
        label(ctx, "seed").expose_as_slice(),
    )?;

    let base_key = derive_base_key(&ecdh_key, &seed_plain, ctx)?;
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
        kyber_priv.expose_as_slice(),
        wire.seed_enc.expose_as_slice(),
        label(ctx, "seed").expose_as_slice(),
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

// ===== FILE: ./src/crypto/mod.rs =====
// ----------------------------------------

pub mod aead;
pub mod kdf;
pub mod keys;
pub mod kyberbox;
pub mod sign;


// ===== FILE: ./src/crypto/sign.rs =====
// ----------------------------------------

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use pqcrypto::sign::mldsa87::{DetachedSignature, PublicKey, SecretKey, detached_sign, verify_detached_signature};
use pqcrypto::traits::sign::{DetachedSignature as DStrait, PublicKey as PKtrait, SecretKey as SKtrait};
use crate::{error::{LithiumError, Result}, secrets::Byte32, secrets::bytes::SecretBytes};

pub fn sign_message<S: AsRef<[u8]>>(message: &[u8], priv_ed_seed: S) -> Result<SecretBytes> {
    let seed = Byte32::from_slice(priv_ed_seed.as_ref())?;
    let signing = SigningKey::from_bytes(seed.as_array());
    let sig: Signature = signing.sign(message);
    Ok(SecretBytes::from_slice(&sig.to_bytes()))
}

pub fn verify_signature(message: &[u8], signature: &[u8], pub_key: &Byte32) -> bool {
    if signature.len() != 64 { return false; }
    let sig = match Signature::from_slice(signature) { Ok(v) => v, Err(_) => return false };
    let pk = match VerifyingKey::from_bytes(pub_key.as_array()) { Ok(v) => v, Err(_) => return false };
    pk.verify(message, &sig).is_ok()
}

pub fn sign_message_dili<S: AsRef<[u8]>>(message: &[u8], dili_sk_bytes: S) -> Result<SecretBytes> {
    let sig_bytes = {
        let sk = SecretKey::from_bytes(dili_sk_bytes.as_ref()).map_err(|_| LithiumError::internal())?;
        let sig: DetachedSignature = detached_sign(message, &sk);
        SecretBytes::from_slice(sig.as_bytes())
    };
    Ok(sig_bytes)
}

pub fn verify_signature_dili(message: &[u8], signature: &[u8], dili_pk_bytes: &SecretBytes) -> bool {
    let Ok(pk) = PublicKey::from_bytes(dili_pk_bytes.expose_as_slice()) else { return false; };
    let Ok(sig) = DetachedSignature::from_bytes(signature) else { return false; };
    verify_detached_signature(&sig, message, &pk).is_ok()
}


// ===== FILE: ./src/db/manager.rs =====
// ----------------------------------------

use std::sync::Arc;

use sea_orm::DatabaseConnection;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{crypto::{aead, keys}, error::Result, keys::{KeyManager, MkProvider}, secrets::Byte32, secrets::bytes::SecretBytes};

pub struct DataManager<P: MkProvider> {
    db: DatabaseConnection,
    key_manager: Arc<Mutex<KeyManager<P>>>,
}

impl<P: MkProvider + Send + Sync + 'static> DataManager<P> {
    pub fn new(db: DatabaseConnection, key_manager: Arc<Mutex<KeyManager<P>>>) -> Self {
        Self { db, key_manager }
    }

    pub fn db(&self) -> &DatabaseConnection { &self.db }

    pub async fn init(&self) -> Result<()> { Ok(()) }

    pub async fn load_db_dek(&self) -> Result<Byte32> {
        self.key_manager.lock().await.derive_secret32(b"lithium/db-dek/v1")
    }

    pub async fn users_uuid_namespace(&self) -> Result<Uuid> {
        let d = self.key_manager.lock().await.derive_secret32(b"lithium/users-uuid-namespace/v1")?;
        let mut b = [0u8; 16];
        b.copy_from_slice(&d.as_slice()[..16]);
        b[6] = (b[6] & 0x0f) | 0x50;
        b[8] = (b[8] & 0x3f) | 0x80;
        Ok(Uuid::from_bytes(b))
    }

    pub async fn encrypt_db_blob(&self, plaintext: &SecretBytes, aad: &SecretBytes) -> Result<SecretBytes> {
        let dek = self.load_db_dek().await?;
        let nonce = keys::random_12()?;
        aead::encrypt(plaintext, &dek, &nonce, aad)
    }

    pub async fn decrypt_db_blob(&self, blob: &SecretBytes, aad: &SecretBytes) -> Result<SecretBytes> {
        let dek = self.load_db_dek().await?;
        aead::decrypt(blob, &dek, aad)
    }
}


// ===== FILE: ./src/db/mod.rs =====
// ----------------------------------------

pub mod manager;


// ===== FILE: ./src/error.rs =====
// ----------------------------------------

use core::fmt;

pub type Result<T> = core::result::Result<T, LithiumError>;

#[derive(Debug)]
pub struct LithiumError {
    pub kind: CryptoErrorKind,
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl LithiumError {
    #[inline]
    pub fn new(kind: CryptoErrorKind) -> Self {
        Self { kind, source: None }
    }

    #[inline]
    pub fn with_source<E>(mut self, err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        self.source = Some(Box::new(err));
        self
    }

    #[inline]
    pub fn is_verbose() -> bool {
        cfg!(debug_assertions)
    }

    #[inline]
    pub fn invalid_len(expected: usize, got: usize) -> Self {
        Self::new(CryptoErrorKind::InvalidLength { expected, got })
    }

    #[inline]
    pub fn invalid_hex_len(expected: usize, got: usize) -> Self {
        Self::new(CryptoErrorKind::InvalidHexLength { expected, got })
    }

    #[inline]
    pub fn invalid_hex<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::new(CryptoErrorKind::InvalidHex).with_source(err)
    }

    #[inline]
    pub fn hex_prefix_disallowed() -> Self {
        Self::new(CryptoErrorKind::HexDisallowedPrefix)
    }

    #[inline]
    pub fn hex_must_be_lowercase() -> Self {
        Self::new(CryptoErrorKind::HexMustBeLowercase)
    }

    #[inline]
    pub fn string_policy() -> Self {
        Self::new(CryptoErrorKind::StringPolicy)
    }

    #[inline]
    pub fn missing_header(name: &'static str) -> Self {
        Self::new(CryptoErrorKind::MissingHeader { name })
    }

    #[inline]
    pub fn invalid_utf8_header<E>(name: &'static str, err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::new(CryptoErrorKind::InvalidUtf8Header { name }).with_source(err)
    }

    #[inline]
    pub fn json_parse<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::new(CryptoErrorKind::JsonParse).with_source(err)
    }

    #[inline]
    pub fn json_not_object() -> Self {
        Self::new(CryptoErrorKind::JsonNotObject)
    }

    #[inline]
    pub fn json_missing_field(key: &'static str) -> Self {
        Self::new(CryptoErrorKind::JsonMissingField { key })
    }

    #[inline]
    pub fn json_type_mismatch(key: &'static str, expected: &'static str) -> Self {
        Self::new(CryptoErrorKind::JsonTypeMismatch { key, expected })
    }

    #[inline]
    pub fn aead_failed() -> Self {
        Self::new(CryptoErrorKind::AeadFailed)
    }

    #[inline]
    pub fn kdf_failed() -> Self {
        Self::new(CryptoErrorKind::KdfFailed)
    }

    #[inline]
    pub fn io<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::new(CryptoErrorKind::Io).with_source(err)
    }

    #[inline]
    pub fn internal() -> Self {
        Self::new(CryptoErrorKind::Internal)
    }

    #[inline]
    pub fn invalid_credentials(msg: &'static str) -> Self {
        Self::new(CryptoErrorKind::InvalidCredentials { msg })
    }

    #[inline]
    pub fn invalid_perms(msg: &'static str) -> Self {
        Self::new(CryptoErrorKind::InvalidPermissions { msg })
    }

    #[inline]
    pub fn invalid_utf(msg: &'static str) -> Self {
        Self::new(CryptoErrorKind::InvalidUtf { msg })
    }

    #[inline]
    pub fn env_missing(name: &'static str) -> Self {
        Self::new(CryptoErrorKind::EnvMissing { name })
    }

    #[inline]
    pub fn env_invalid(name: &'static str) -> Self {
        Self::new(CryptoErrorKind::EnvInvalid { name })
    }

    #[inline]
    pub fn state_missing(name: &'static str) -> Self {
        Self::new(CryptoErrorKind::StateMissing { name })
    }

    #[inline]
    pub fn timeout<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::new(CryptoErrorKind::Timeout).with_source(err)
    }

    #[inline]
    pub fn transport<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::new(CryptoErrorKind::Transport).with_source(err)
    }

    #[inline]
    pub fn http_status(code: u16) -> Self {
        Self::new(CryptoErrorKind::HttpStatus { code })
    }

    #[inline]
    pub fn is_not_found(&self) -> bool {
        if self.kind != CryptoErrorKind::Io {
            return false;
        }
        let Some(src) = self.source.as_deref() else { return false; };
        if let Some(ioe) = src.downcast_ref::<std::io::Error>() {
            return ioe.kind() == std::io::ErrorKind::NotFound;
        }
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoErrorKind {
    InvalidLength { expected: usize, got: usize },
    InvalidHexLength { expected: usize, got: usize },
    InvalidHex,
    HexDisallowedPrefix,
    HexMustBeLowercase,
    StringPolicy,
    MissingHeader { name: &'static str },
    InvalidUtf8Header { name: &'static str },
    JsonParse,
    JsonNotObject,
    JsonMissingField { key: &'static str },
    JsonTypeMismatch { key: &'static str, expected: &'static str },
    InvalidCredentials { msg: &'static str },
    InvalidPermissions { msg: &'static str },
    InvalidUtf { msg: &'static str },
    EnvMissing { name: &'static str },
    EnvInvalid { name: &'static str },
    StateMissing { name: &'static str },
    HttpStatus { code: u16 },
    Timeout,
    Transport,
    KdfFailed,
    AeadFailed,
    Io,
    Internal,
}

impl fmt::Display for CryptoErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoErrorKind::InvalidLength { .. } => write!(f, "invalid length"),
            CryptoErrorKind::InvalidHexLength { .. } => write!(f, "invalid hex length"),
            CryptoErrorKind::InvalidHex => write!(f, "invalid hex"),
            CryptoErrorKind::HexDisallowedPrefix => write!(f, "hex prefix disallowed"),
            CryptoErrorKind::HexMustBeLowercase => write!(f, "hex must be lowercase"),
            CryptoErrorKind::StringPolicy => write!(f, "invalid input"),
            CryptoErrorKind::MissingHeader { .. } => write!(f, "missing header"),
            CryptoErrorKind::InvalidUtf8Header { .. } => write!(f, "invalid header encoding"),
            CryptoErrorKind::JsonParse => write!(f, "invalid json"),
            CryptoErrorKind::JsonNotObject => write!(f, "invalid json"),
            CryptoErrorKind::JsonMissingField { .. } => write!(f, "invalid json"),
            CryptoErrorKind::JsonTypeMismatch { .. } => write!(f, "invalid json"),
            CryptoErrorKind::InvalidCredentials { .. } => write!(f, "invalid credentials"),
            CryptoErrorKind::InvalidPermissions { .. } => write!(f, "permission denied"),
            CryptoErrorKind::InvalidUtf { .. } => write!(f, "invalid utf-8"),
            CryptoErrorKind::EnvMissing { .. } => write!(f, "missing environment variable"),
            CryptoErrorKind::EnvInvalid { .. } => write!(f, "invalid environment variable"),
            CryptoErrorKind::StateMissing { .. } => write!(f, "missing state"),
            CryptoErrorKind::HttpStatus { .. } => write!(f, "http status error"),
            CryptoErrorKind::Timeout => write!(f, "timeout"),
            CryptoErrorKind::Transport => write!(f, "transport error"),
            CryptoErrorKind::KdfFailed => write!(f, "cryptographic operation failed"),
            CryptoErrorKind::AeadFailed => write!(f, "cryptographic operation failed"),
            CryptoErrorKind::Io => write!(f, "i/o error"),
            CryptoErrorKind::Internal => write!(f, "internal error"),
        }
    }
}

impl fmt::Display for LithiumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if Self::is_verbose() {
            match self.kind {
                CryptoErrorKind::InvalidLength { expected, got } => write!(f, "invalid length: expected {expected}, got {got}")?,
                CryptoErrorKind::InvalidHexLength { expected, got } => write!(f, "invalid hex length: expected {expected}, got {got}")?,
                CryptoErrorKind::MissingHeader { name } => write!(f, "missing header: {name}")?,
                CryptoErrorKind::InvalidUtf8Header { name } => write!(f, "invalid utf-8 in header: {name}")?,
                CryptoErrorKind::JsonMissingField { key } => write!(f, "json missing field: {key}")?,
                CryptoErrorKind::JsonTypeMismatch { key, expected } => write!(f, "json type mismatch at {key}: expected {expected}")?,
                CryptoErrorKind::InvalidCredentials { msg } => write!(f, "invalid credentials: {msg}")?,
                CryptoErrorKind::InvalidPermissions { msg } => write!(f, "invalid permissions: {msg}")?,
                CryptoErrorKind::InvalidUtf { msg } => write!(f, "invalid utf-8: {msg}")?,
                CryptoErrorKind::EnvMissing { name } => write!(f, "missing env var: {name}")?,
                CryptoErrorKind::EnvInvalid { name } => write!(f, "invalid env var: {name}")?,
                CryptoErrorKind::StateMissing { name } => write!(f, "missing state: {name}")?,
                CryptoErrorKind::HttpStatus { code } => write!(f, "http status error: {code}")?,
                _ => write!(f, "{}", self.kind)?,
            }
            if let Some(src) = &self.source {
                write!(f, " | source: {src}")?;
            }
            Ok(())
        } else {
            write!(f, "{}", self.kind)
        }
    }
}

impl std::error::Error for LithiumError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|e| e as _)
    }
}

impl From<std::io::Error> for LithiumError {
    fn from(value: std::io::Error) -> Self {
        LithiumError::io(value)
    }
}
impl From<hex::FromHexError> for LithiumError {
    fn from(value: hex::FromHexError) -> Self {
        LithiumError::invalid_hex(value)
    }
}
impl From<serde_json::Error> for LithiumError {
    fn from(value: serde_json::Error) -> Self {
        LithiumError::json_parse(value)
    }
}
impl From<hkdf::InvalidLength> for LithiumError {
    fn from(_: hkdf::InvalidLength) -> Self {
        LithiumError::kdf_failed()
    }
}
impl From<aes_gcm_siv::aead::Error> for LithiumError {
    fn from(_: aes_gcm_siv::aead::Error) -> Self {
        LithiumError::aead_failed()
    }
}
impl From<rand::rngs::SysError> for LithiumError {
    fn from(err: rand::rngs::SysError) -> Self {
        LithiumError::internal().with_source(err)
    }
}

// ===== FILE: ./src/keys/keyfile.rs =====
// ----------------------------------------

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::crypto::{aead, keys};
use crate::error::{CryptoErrorKind, LithiumError, Result};
use crate::secrets::bytes::{FixedBytes, SecretBytes};
use crate::secrets::types::{Byte12, Byte32, MasterKey32};

pub const KEYFILE_MAGIC: &[u8; 4] = b"KEYF";
pub const KEYFILE_VERSION: u8 = 1;
pub const ALG_ID_AES256_GCM_SIV: u8 = 1;
pub const DEK_LEN: u16 = 32;

#[inline]
pub fn read_keyfile_bytes(path: &Path) -> Result<SecretBytes> {
    Ok(SecretBytes::from_vec(fs::read(path).map_err(LithiumError::io)?))
}

pub fn write_secure(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(LithiumError::io)?;
    }

    let tmp = path.with_extension("tmp");

    let write_res = (|| -> Result<()> {
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)
            .map_err(LithiumError::io)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(LithiumError::io)?;
        }

        let mut f = f;
        f.write_all(data).map_err(LithiumError::io)?;
        f.sync_all().map_err(LithiumError::io)?;
        Ok(())
    })();

    if let Err(e) = write_res {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    fs::rename(&tmp, path).map_err(LithiumError::io)?;
    Ok(())
}

#[inline]
fn aad_for(version: u8, key_type: &str) -> SecretBytes {
    SecretBytes::from_vec(format!("keyfile:v{}|{}", version, key_type).into_bytes())
}

#[inline]
fn derive_kek(mk: &MasterKey32, salt: &[u8; 32]) -> Result<Byte32> {
    let hk = Hkdf::<Sha256>::new(Some(salt), mk.as_slice());
    let mut out = Byte32::new_zeroed();
    hk.expand(b"kek/v1", out.as_mut_slice())?;
    Ok(out)
}

#[inline]
fn wrap_dek(
    kek: &Byte32,
    dek: &Byte32,
    aad: &SecretBytes,
) -> Result<(Vec<u8>, [u8; 12])> {
    let nonce = keys::random_fixed::<12>()?;
    let ct = aead::encrypt_raw(
        &SecretBytes::from_slice(dek.as_slice()),
        kek,
        &nonce,
        aad,
    )?;

    Ok((ct.expose_as_slice().to_vec(), *nonce.as_array()))
}

#[inline]
fn encrypt_payload(
    dek: &Byte32,
    payload: &[u8],
    aad: &SecretBytes,
) -> Result<(Vec<u8>, [u8; 12])> {
    let nonce = keys::random_fixed::<12>()?;
    let ct = aead::encrypt_raw(
        &SecretBytes::from_slice(payload),
        dek,
        &nonce,
        aad,
    )?;

    Ok((ct.expose_as_slice().to_vec(), *nonce.as_array()))
}

fn build_record(
    version: u8,
    alg_id: u8,
    dek_len: u16,
    salt: &[u8; 32],
    nonce_wrap: &[u8; 12],
    ct_wrap: &[u8],
    nonce_payload: &[u8; 12],
    ct_payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(KEYFILE_MAGIC);
    out.push(version);
    out.push(alg_id);
    out.extend_from_slice(&dek_len.to_be_bytes());

    out.extend_from_slice(&(salt.len() as u16).to_be_bytes());
    out.extend_from_slice(salt);

    out.extend_from_slice(&(nonce_wrap.len() as u16).to_be_bytes());
    out.extend_from_slice(nonce_wrap);

    out.extend_from_slice(&(ct_wrap.len() as u16).to_be_bytes());
    out.extend_from_slice(ct_wrap);

    out.extend_from_slice(&(nonce_payload.len() as u16).to_be_bytes());
    out.extend_from_slice(nonce_payload);

    out.extend_from_slice(&(ct_payload.len() as u32).to_be_bytes());
    out.extend_from_slice(ct_payload);

    out
}

fn read_u16(buf: &[u8], idx: &mut usize) -> Result<u16> {
    if *idx + 2 > buf.len() {
        return Err(LithiumError::new(CryptoErrorKind::InvalidLength {
            expected: *idx + 2,
            got: buf.len(),
        }));
    }
    let v = u16::from_be_bytes([buf[*idx], buf[*idx + 1]]);
    *idx += 2;
    Ok(v)
}

fn read_u32(buf: &[u8], idx: &mut usize) -> Result<u32> {
    if *idx + 4 > buf.len() {
        return Err(LithiumError::new(CryptoErrorKind::InvalidLength {
            expected: *idx + 4,
            got: buf.len(),
        }));
    }
    let v = u32::from_be_bytes([buf[*idx], buf[*idx + 1], buf[*idx + 2], buf[*idx + 3]]);
    *idx += 4;
    Ok(v)
}

fn parse_keyfile(
    buf: &SecretBytes,
) -> Result<(u8, u8, u16, [u8; 32], [u8; 12], Vec<u8>, [u8; 12], Vec<u8>)> {
    let buf = buf.expose_as_slice();
    let mut idx = 0;

    if buf.len() < 8 {
        return Err(LithiumError::invalid_len(8, buf.len()));
    }
    if &buf[0..4] != KEYFILE_MAGIC {
        return Err(LithiumError::internal());
    }

    idx += 4;
    let version = buf[idx];
    idx += 1;
    let alg_id = buf[idx];
    idx += 1;
    let dek_len = u16::from_be_bytes([buf[idx], buf[idx + 1]]);
    idx += 2;

    let len_salt = read_u16(buf, &mut idx)? as usize;
    if len_salt != 32 || idx + 32 > buf.len() {
        return Err(LithiumError::internal());
    }
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&buf[idx..idx + 32]);
    idx += 32;

    let len_nonce_wrap = read_u16(buf, &mut idx)? as usize;
    if len_nonce_wrap != 12 || idx + 12 > buf.len() {
        return Err(LithiumError::internal());
    }
    let mut nonce_wrap = [0u8; 12];
    nonce_wrap.copy_from_slice(&buf[idx..idx + 12]);
    idx += 12;

    let len_ct_wrap = read_u16(buf, &mut idx)? as usize;
    if idx + len_ct_wrap > buf.len() {
        return Err(LithiumError::internal());
    }
    let ct_wrap = buf[idx..idx + len_ct_wrap].to_vec();
    idx += len_ct_wrap;

    let len_nonce_payload = read_u16(buf, &mut idx)? as usize;
    if len_nonce_payload != 12 || idx + 12 > buf.len() {
        return Err(LithiumError::internal());
    }
    let mut nonce_payload = [0u8; 12];
    nonce_payload.copy_from_slice(&buf[idx..idx + 12]);
    idx += 12;

    let len_ct_payload = read_u32(buf, &mut idx)? as usize;
    if idx + len_ct_payload > buf.len() {
        return Err(LithiumError::internal());
    }
    let ct_payload = buf[idx..idx + len_ct_payload].to_vec();

    Ok((
        version,
        alg_id,
        dek_len,
        salt,
        nonce_wrap,
        ct_wrap,
        nonce_payload,
        ct_payload,
    ))
}

fn unwrap_dek(
    mk: &MasterKey32,
    salt: &[u8; 32],
    nonce_wrap: &[u8; 12],
    ct_wrap: &[u8],
    aad: &SecretBytes,
) -> Result<Byte32> {
    let kek = derive_kek(mk, salt)?;
    let nonce = Byte12::from_slice(nonce_wrap)?;
    let dek_bytes = aead::decrypt_raw(
        &SecretBytes::from_slice(ct_wrap),
        &kek,
        &nonce,
        aad,
    )?;
    Byte32::from_slice(dek_bytes.expose_as_slice())
}

fn decrypt_payload_bytes(
    dek: &Byte32,
    nonce_payload: &[u8; 12],
    ct_payload: &[u8],
    aad: &SecretBytes,
) -> Result<SecretBytes> {
    let nonce = Byte12::from_slice(nonce_payload)?;
    aead::decrypt_raw(
        &SecretBytes::from_slice(ct_payload),
        dek,
        &nonce,
        aad,
    )
}

fn decrypt_payload_32(
    dek: &Byte32,
    nonce_payload: &[u8; 12],
    ct_payload: &[u8],
    aad: &SecretBytes,
) -> Result<FixedBytes<32>> {
    let pt = decrypt_payload_bytes(dek, nonce_payload, ct_payload, aad)?;
    FixedBytes::<32>::from_slice(pt.expose_as_slice())
}

pub fn save_secret32_encrypted(
    path: &Path,
    mk: &MasterKey32,
    payload: &FixedBytes<32>,
    key_type: &str,
) -> Result<()> {
    let dek = keys::random_fixed::<32>()?;
    let salt = keys::random_fixed::<32>()?;
    let kek = derive_kek(mk, salt.as_array())?;
    let aad = aad_for(KEYFILE_VERSION, key_type);

    let (ct_wrap, nonce_wrap) = wrap_dek(&kek, &dek, &aad)?;
    let (ct_payload, nonce_payload) = encrypt_payload(&dek, payload.as_slice(), &aad)?;

    let out = build_record(
        KEYFILE_VERSION,
        ALG_ID_AES256_GCM_SIV,
        DEK_LEN,
        salt.as_array(),
        &nonce_wrap,
        &ct_wrap,
        &nonce_payload,
        &ct_payload,
    );

    write_secure(path, &out)?;
    Ok(())
}

pub fn save_bytes_encrypted(
    path: &Path,
    mk: &MasterKey32,
    payload: &[u8],
    key_type: &str,
) -> Result<()> {
    let dek = keys::random_fixed::<32>()?;
    let salt = keys::random_fixed::<32>()?;
    let kek = derive_kek(mk, salt.as_array())?;
    let aad = aad_for(KEYFILE_VERSION, key_type);

    let (ct_wrap, nonce_wrap) = wrap_dek(&kek, &dek, &aad)?;
    let (ct_payload, nonce_payload) = encrypt_payload(&dek, payload, &aad)?;

    let out = build_record(
        KEYFILE_VERSION,
        ALG_ID_AES256_GCM_SIV,
        DEK_LEN,
        salt.as_array(),
        &nonce_wrap,
        &ct_wrap,
        &nonce_payload,
        &ct_payload,
    );

    write_secure(path, &out)?;
    Ok(())
}

pub fn load_secret32_decrypted(
    path: &Path,
    mk: &MasterKey32,
    key_type: &str,
) -> Result<FixedBytes<32>> {
    let buf = read_keyfile_bytes(path)?;
    let (version, alg_id, dek_len, salt, nonce_wrap, ct_wrap, nonce_payload, ct_payload) =
        parse_keyfile(&buf)?;

    if version != KEYFILE_VERSION || alg_id != ALG_ID_AES256_GCM_SIV || dek_len != DEK_LEN {
        return Err(LithiumError::internal());
    }

    let aad = aad_for(version, key_type);
    let dek = unwrap_dek(mk, &salt, &nonce_wrap, &ct_wrap, &aad)?;
    decrypt_payload_32(&dek, &nonce_payload, &ct_payload, &aad)
}

pub fn load_bytes_decrypted(
    path: &Path,
    mk: &MasterKey32,
    key_type: &str,
) -> Result<SecretBytes> {
    let buf = read_keyfile_bytes(path)?;
    let (version, alg_id, dek_len, salt, nonce_wrap, ct_wrap, nonce_payload, ct_payload) =
        parse_keyfile(&buf)?;

    if version != KEYFILE_VERSION || alg_id != ALG_ID_AES256_GCM_SIV || dek_len != DEK_LEN {
        return Err(LithiumError::internal());
    }

    let aad = aad_for(version, key_type);
    let dek = unwrap_dek(mk, &salt, &nonce_wrap, &ct_wrap, &aad)?;
    decrypt_payload_bytes(&dek, &nonce_payload, &ct_payload, &aad)
}

pub fn rewrap_keyfile_dek_to_bytes(
    path: &Path,
    old_mk: &MasterKey32,
    new_mk: &MasterKey32,
    key_type: &str,
) -> Result<SecretBytes> {
    let buf = read_keyfile_bytes(path)?;
    let (
        version,
        alg_id,
        dek_len,
        mut salt_old,
        mut nonce_wrap_old,
        mut ct_wrap_old,
        nonce_payload,
        ct_payload,
    ) = parse_keyfile(&buf)?;

    if version != KEYFILE_VERSION || alg_id != ALG_ID_AES256_GCM_SIV || dek_len != DEK_LEN {
        return Err(LithiumError::internal());
    }

    let aad = aad_for(version, key_type);
    let dek = unwrap_dek(old_mk, &salt_old, &nonce_wrap_old, &ct_wrap_old, &aad)?;

    let salt_new = keys::random_fixed::<32>()?;
    let kek_new = derive_kek(new_mk, salt_new.as_array())?;
    let (ct_wrap_new, nonce_wrap_new) = wrap_dek(&kek_new, &dek, &aad)?;

    let out = build_record(
        version,
        alg_id,
        dek_len,
        salt_new.as_array(),
        &nonce_wrap_new,
        &ct_wrap_new,
        &nonce_payload,
        &ct_payload,
    );

    salt_old.zeroize();
    nonce_wrap_old.zeroize();
    ct_wrap_old.zeroize();

    Ok(SecretBytes::from_vec(out))
}

pub fn rewrap_keyfile_dek(
    path: &Path,
    old_mk: &MasterKey32,
    new_mk: &MasterKey32,
    key_type: &str,
) -> Result<()> {
    let out = rewrap_keyfile_dek_to_bytes(path, old_mk, new_mk, key_type)?;
    write_secure(path, out.expose_as_slice())
}

// ===== FILE: ./src/keys/manager.rs =====
// ----------------------------------------

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use pqcrypto::kem::mlkem1024;
use pqcrypto::sign::mldsa87;
use pqcrypto::traits::kem::{PublicKey as _, SecretKey as _};
use pqcrypto::traits::sign::{PublicKey as SignPub, SecretKey as SignSk};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

use crate::crypto::keys;
use crate::error::{LithiumError, Result};
use crate::secrets::{Byte32, MasterKey32, SecretBytes};

use super::keyfile;

const DEFAULT_ROTATE_EVERY: Duration = Duration::from_secs(3600);

const PUB_DIR: &str = "pub";
const PRIV_DIR: &str = "priv";
const SECRETS_DIR: &str = "secrets";
const ROTATE_DIR: &str = ".rotate";
const ROTATE_STAGE_DIR: &str = "staged";
const ROTATE_READY_FILE: &str = "ready";
const ROTATE_NEXT_OLD_FILE: &str = "next-mk-old.keyf";
const ROTATE_NEXT_NEW_FILE: &str = "next-mk-new.keyf";

const ED_PUB: &str = "ed25519.pub";
const X_PUB: &str = "x25519.pub";
const KYBER_PUB: &str = "kyber-mlkem1024.pub";
const DILI_PUB: &str = "dilithium-mldsa87.pub";

const ED_PRIV: &str = "ed25519.keyf";
const X_PRIV: &str = "x25519.keyf";
const KYBER_PRIV: &str = "kyber-mlkem1024.keyf";
const DILI_PRIV: &str = "dilithium-mldsa87.keyf";

const LEGACY_STATE_FILE: &str = "state.keyf";

const KT_ED_SEED: &str = "ed25519-seed-v2";
const KT_X_SEED: &str = "x25519-seed-v2";
const KT_KYBER_SK: &str = "kyber-mlkem1024-sk-v2";
const KT_DILI_SK: &str = "dilithium-mldsa87-sk-v2";
const KT_ROTATE_NEXT_OLD: &str = "rotate-next-mk-old-v1";
const KT_ROTATE_NEXT_NEW: &str = "rotate-next-mk-new-v1";

const JWT_LABEL: &[u8] = b"lithium/jwt-secret/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStoreKind {
    Server,
    User,
}

impl KeyStoreKind {
    fn dir_name(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::User => "user",
        }
    }
}

pub trait MkProvider {
    fn load_mk(&self) -> Result<Byte32>;
    fn store_mk(&self, mk: &Byte32) -> Result<()>;

    fn derive_secret32(&self, _mk: &Byte32, _label: &[u8]) -> Result<Byte32> {
        Err(LithiumError::invalid_credentials("mk_provider_derive_secret32_unused"))
    }
}

pub struct PlainFileMkProvider {
    path: PathBuf,
}

impl PlainFileMkProvider {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl MkProvider for PlainFileMkProvider {
    fn load_mk(&self) -> Result<Byte32> {
        let bytes = keyfile::read_keyfile_bytes(&self.path)?;
        Byte32::from_slice(bytes.expose_as_slice())
    }

    fn store_mk(&self, mk: &Byte32) -> Result<()> {
        keyfile::write_secure(&self.path, mk.as_slice())
    }
}

#[derive(Clone)]
pub struct PublicKeys {
    pub ed25519: Byte32,
    pub x25519: Byte32,
    pub kyber: SecretBytes,
    pub dilithium: SecretBytes,
}

pub struct KeyManager<P: MkProvider> {
    root_dir: PathBuf,
    pub_dir: PathBuf,
    priv_dir: PathBuf,
    secrets_dir: PathBuf,
    rotate_dir: PathBuf,
    mk_provider: P,
    public_keys: PublicKeys,
    jwt_secret: Byte32,
    rotate_every: Duration,
    next_rotation_at: Instant,
}

#[derive(Clone)]
struct RewrapTarget {
    live_path: PathBuf,
    relative_path: PathBuf,
    key_type: String,
}

#[inline]
fn sync_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let dir = fs::File::open(path).map_err(LithiumError::io)?;
    dir.sync_all().map_err(LithiumError::io)
}

#[inline]
fn write_marker(path: &Path, data: &[u8]) -> Result<()> {
    keyfile::write_secure(path, data)?;
    if let Some(parent) = path.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

#[inline]
fn read_pub32(path: &Path) -> Result<Byte32> {
    let bytes = keyfile::read_keyfile_bytes(path)?;
    Byte32::from_slice(bytes.expose_as_slice())
}

#[inline]
fn read_pub_bytes(path: &Path) -> Result<SecretBytes> {
    keyfile::read_keyfile_bytes(path)
}

fn sync_public_cache(pub_dir: &Path, pks: &PublicKeys) -> Result<()> {
    fs::create_dir_all(pub_dir).map_err(LithiumError::io)?;
    keyfile::write_secure(&pub_dir.join(ED_PUB), pks.ed25519.as_slice())?;
    keyfile::write_secure(&pub_dir.join(X_PUB), pks.x25519.as_slice())?;
    keyfile::write_secure(&pub_dir.join(KYBER_PUB), pks.kyber.expose_as_slice())?;
    keyfile::write_secure(&pub_dir.join(DILI_PUB), pks.dilithium.expose_as_slice())?;
    sync_dir(pub_dir)?;
    Ok(())
}

fn load_public_cache(pub_dir: &Path) -> Result<PublicKeys> {
    Ok(PublicKeys {
        ed25519: read_pub32(&pub_dir.join(ED_PUB))?,
        x25519: read_pub32(&pub_dir.join(X_PUB))?,
        kyber: read_pub_bytes(&pub_dir.join(KYBER_PUB))?,
        dilithium: read_pub_bytes(&pub_dir.join(DILI_PUB))?,
    })
}

fn ensure_secret32_keyfile(
    path: &Path,
    mk: &MasterKey32,
    key_type: &str,
    generator: impl FnOnce() -> Result<Byte32>,
) -> Result<Byte32> {
    if path.exists() {
        return keyfile::load_secret32_decrypted(path, mk, key_type);
    }

    let v = generator()?;
    keyfile::save_secret32_encrypted(path, mk, &v, key_type)?;
    Ok(v)
}

fn label_hex(label: &[u8]) -> String {
    hex::encode(label)
}

fn label_key_type(label: &[u8]) -> String {
    format!("secret32:{}", label_hex(label))
}

fn label_key_type_from_hex(hex_label: &str) -> String {
    format!("secret32:{}", hex_label)
}

fn label_secret_path(secrets_dir: &Path, label: &[u8]) -> PathBuf {
    secrets_dir.join(format!("{}.keyf", label_hex(label)))
}

fn load_or_create_label_secret32(
    secrets_dir: &Path,
    mk: &MasterKey32,
    label: &[u8],
) -> Result<Byte32> {
    let path = label_secret_path(secrets_dir, label);
    let key_type = label_key_type(label);

    if path.exists() {
        return keyfile::load_secret32_decrypted(&path, mk, &key_type);
    }

    let v = keys::random_32()?;
    keyfile::save_secret32_encrypted(&path, mk, &v, &key_type)?;
    Ok(v)
}

fn derive_ed25519_pub(seed: &Byte32) -> Byte32 {
    let sk = SigningKey::from_bytes(seed.as_array());
    Byte32::new(sk.verifying_key().to_bytes())
}

fn derive_x25519_pub(seed: &Byte32) -> Byte32 {
    let sk = XStaticSecret::from(*seed.as_array());
    let pk = XPublicKey::from(&sk);
    Byte32::new(pk.to_bytes())
}

fn ensure_asymmetric_material(
    pub_dir: &Path,
    priv_dir: &Path,
    mk: &MasterKey32,
) -> Result<PublicKeys> {
    fs::create_dir_all(pub_dir).map_err(LithiumError::io)?;
    fs::create_dir_all(priv_dir).map_err(LithiumError::io)?;

    let ed_seed = ensure_secret32_keyfile(
        &priv_dir.join(ED_PRIV),
        mk,
        KT_ED_SEED,
        || keys::random_fixed::<32>(),
    )?;

    let x_seed = ensure_secret32_keyfile(
        &priv_dir.join(X_PRIV),
        mk,
        KT_X_SEED,
        || keys::random_fixed::<32>(),
    )?;

    let kyber_pub = {
        let priv_path = priv_dir.join(KYBER_PRIV);
        let pub_path = pub_dir.join(KYBER_PUB);
        if priv_path.exists() && pub_path.exists() {
            let _ = keyfile::load_bytes_decrypted(&priv_path, mk, KT_KYBER_SK)?;
            read_pub_bytes(&pub_path)?
        } else if priv_path.exists() || pub_path.exists() {
            return Err(LithiumError::invalid_credentials("keystore_layout_inconsistent"));
        } else {
            let (pk, sk) = mlkem1024::keypair();
            let sk_bytes = SecretBytes::from_slice(sk.as_bytes());
            let pk_bytes = SecretBytes::from_slice(pk.as_bytes());
            keyfile::save_bytes_encrypted(&priv_path, mk, sk_bytes.expose_as_slice(), KT_KYBER_SK)?;
            keyfile::write_secure(&pub_path, pk_bytes.expose_as_slice())?;
            pk_bytes
        }
    };

    let dili_pub = {
        let priv_path = priv_dir.join(DILI_PRIV);
        let pub_path = pub_dir.join(DILI_PUB);
        if priv_path.exists() && pub_path.exists() {
            let _ = keyfile::load_bytes_decrypted(&priv_path, mk, KT_DILI_SK)?;
            read_pub_bytes(&pub_path)?
        } else if priv_path.exists() || pub_path.exists() {
            return Err(LithiumError::invalid_credentials("keystore_layout_inconsistent"));
        } else {
            let (pk, sk) = mldsa87::keypair();
            let sk_bytes = SecretBytes::from_slice(SignSk::as_bytes(&sk));
            let pk_bytes = SecretBytes::from_slice(SignPub::as_bytes(&pk));
            keyfile::save_bytes_encrypted(&priv_path, mk, sk_bytes.expose_as_slice(), KT_DILI_SK)?;
            keyfile::write_secure(&pub_path, pk_bytes.expose_as_slice())?;
            pk_bytes
        }
    };

    let pks = PublicKeys {
        ed25519: derive_ed25519_pub(&ed_seed),
        x25519: derive_x25519_pub(&x_seed),
        kyber: kyber_pub,
        dilithium: dili_pub,
    };

    sync_public_cache(pub_dir, &pks)?;
    Ok(pks)
}

fn has_legacy_or_inconsistent_layout(root_dir: &Path) -> bool {
    root_dir.join(LEGACY_STATE_FILE).exists()
}

fn list_dir_keyfiles(dir: &Path) -> Result<Vec<PathBuf>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    for ent in fs::read_dir(dir).map_err(LithiumError::io)? {
        let ent = ent.map_err(LithiumError::io)?;
        let path = ent.path();
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("keyf") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

fn collect_rewrap_targets(root_dir: &Path, priv_dir: &Path, secrets_dir: &Path) -> Result<Vec<RewrapTarget>> {
    let mut out = Vec::new();

    let fixed = [
        (priv_dir.join(ED_PRIV), KT_ED_SEED.to_owned()),
        (priv_dir.join(X_PRIV), KT_X_SEED.to_owned()),
        (priv_dir.join(KYBER_PRIV), KT_KYBER_SK.to_owned()),
        (priv_dir.join(DILI_PRIV), KT_DILI_SK.to_owned()),
    ];

    for (path, key_type) in fixed {
        if path.exists() {
            let relative_path = path
                .strip_prefix(root_dir)
                .map_err(|_| LithiumError::internal())?
                .to_path_buf();
            out.push(RewrapTarget {
                live_path: path,
                relative_path,
                key_type,
            });
        }
    }

    for path in list_dir_keyfiles(secrets_dir)? {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(LithiumError::internal)?
            .to_owned();

        let relative_path = path
            .strip_prefix(root_dir)
            .map_err(|_| LithiumError::internal())?
            .to_path_buf();

        out.push(RewrapTarget {
            live_path: path,
            relative_path,
            key_type: label_key_type_from_hex(&stem),
        });
    }

    out.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    Ok(out)
}

fn stage_target_path(rotate_dir: &Path, relative_path: &Path) -> PathBuf {
    rotate_dir.join(ROTATE_STAGE_DIR).join(relative_path)
}

fn cleanup_rotation_dir(rotate_dir: &Path) -> Result<()> {
    if rotate_dir.exists() {
        fs::remove_dir_all(rotate_dir).map_err(LithiumError::io)?;
        if let Some(parent) = rotate_dir.parent() {
            sync_dir(parent)?;
        }
    }
    Ok(())
}

fn apply_staged_files(rotate_dir: &Path, targets: &[RewrapTarget]) -> Result<()> {
    for target in targets {
        let staged_path = stage_target_path(rotate_dir, &target.relative_path);
        let staged = keyfile::read_keyfile_bytes(&staged_path)?;
        keyfile::write_secure(&target.live_path, staged.expose_as_slice())?;
        if let Some(parent) = target.live_path.parent() {
            sync_dir(parent)?;
        }
    }
    Ok(())
}

fn prepare_staged_files(
    rotate_dir: &Path,
    old_mk: &MasterKey32,
    new_mk: &MasterKey32,
    targets: &[RewrapTarget],
) -> Result<()> {
    let staged_root = rotate_dir.join(ROTATE_STAGE_DIR);
    fs::create_dir_all(&staged_root).map_err(LithiumError::io)?;

    for target in targets {
        let out = keyfile::rewrap_keyfile_dek_to_bytes(
            &target.live_path,
            old_mk,
            new_mk,
            &target.key_type,
        )?;
        let staged_path = stage_target_path(rotate_dir, &target.relative_path);
        if let Some(parent) = staged_path.parent() {
            fs::create_dir_all(parent).map_err(LithiumError::io)?;
        }
        keyfile::write_secure(&staged_path, out.expose_as_slice())?;
        if let Some(parent) = staged_path.parent() {
            sync_dir(parent)?;
        }
    }

    sync_dir(&staged_root)?;
    Ok(())
}

fn recover_pending_rotation_if_any<P: MkProvider>(
    root_dir: &Path,
    priv_dir: &Path,
    secrets_dir: &Path,
    rotate_dir: &Path,
    mk_provider: &P,
) -> Result<()> {
    if !rotate_dir.exists() {
        return Ok(());
    }

    let ready_path = rotate_dir.join(ROTATE_READY_FILE);
    if !ready_path.exists() {
        cleanup_rotation_dir(rotate_dir)?;
        return Ok(());
    }

    let targets = collect_rewrap_targets(root_dir, priv_dir, secrets_dir)?;
    let current_mk = mk_provider.load_mk()?;
    let next_old_path = rotate_dir.join(ROTATE_NEXT_OLD_FILE);
    let next_new_path = rotate_dir.join(ROTATE_NEXT_NEW_FILE);

    let (new_mk, provider_already_switched) = if next_new_path.exists() {
        match keyfile::load_secret32_decrypted(&next_new_path, &current_mk, KT_ROTATE_NEXT_NEW) {
            Ok(candidate) => (candidate, true),
            Err(_) => {
                let candidate = keyfile::load_secret32_decrypted(
                    &next_old_path,
                    &current_mk,
                    KT_ROTATE_NEXT_OLD,
                )?;
                (candidate, false)
            }
        }
    } else {
        let candidate = keyfile::load_secret32_decrypted(
            &next_old_path,
            &current_mk,
            KT_ROTATE_NEXT_OLD,
        )?;
        (candidate, false)
    };

    apply_staged_files(rotate_dir, &targets)?;

    if !provider_already_switched {
        mk_provider.store_mk(&new_mk)?;
    }

    cleanup_rotation_dir(rotate_dir)?;
    Ok(())
}

impl<P: MkProvider> KeyManager<P> {
    pub fn start(base_dir: &Path, kind: KeyStoreKind, name: &str, mk_provider: P) -> Result<Self> {
        let root_dir = base_dir.join(kind.dir_name()).join(name);
        let pub_dir = root_dir.join(PUB_DIR);
        let priv_dir = root_dir.join(PRIV_DIR);
        let secrets_dir = root_dir.join(SECRETS_DIR);
        let rotate_dir = root_dir.join(ROTATE_DIR);

        fs::create_dir_all(&root_dir).map_err(LithiumError::io)?;
        fs::create_dir_all(&pub_dir).map_err(LithiumError::io)?;
        fs::create_dir_all(&priv_dir).map_err(LithiumError::io)?;
        fs::create_dir_all(&secrets_dir).map_err(LithiumError::io)?;

        match mk_provider.load_mk() {
            Ok(_) => {}
            Err(e) if e.is_not_found() => {
                let new_mk = keys::random_master_key32()?;
                mk_provider.store_mk(&new_mk)?;
            }
            Err(e) => return Err(e),
        }

        if has_legacy_or_inconsistent_layout(&root_dir) {
            return Err(LithiumError::invalid_credentials(
                "legacy_keystore_layout_unsupported",
            ));
        }

        recover_pending_rotation_if_any(
            &root_dir,
            &priv_dir,
            &secrets_dir,
            &rotate_dir,
            &mk_provider,
        )?;

        let root_mk = mk_provider.load_mk()?;

        let public_keys = ensure_asymmetric_material(&pub_dir, &priv_dir, &root_mk)?;
        let jwt_secret = keys::random_32()?;

        Ok(Self {
            root_dir,
            pub_dir,
            priv_dir,
            secrets_dir,
            rotate_dir,
            mk_provider,
            public_keys,
            jwt_secret,
            rotate_every: DEFAULT_ROTATE_EVERY,
            next_rotation_at: Instant::now() + DEFAULT_ROTATE_EVERY,
        })
    }

    pub fn start_plain(
        base_dir: &Path,
        kind: KeyStoreKind,
        name: &str,
    ) -> Result<KeyManager<PlainFileMkProvider>> {
        let mk_path = base_dir.join(kind.dir_name()).join(name).join("mk");
        let provider = PlainFileMkProvider::new(mk_path);
        KeyManager::start(base_dir, kind, name, provider)
    }

    pub fn public_keys(&self) -> &PublicKeys {
        &self.public_keys
    }

    pub fn jwt_secret(&self) -> &Byte32 {
        &self.jwt_secret
    }

    pub fn set_rotate_interval(&mut self, interval: Duration) {
        self.rotate_every = interval;
        self.next_rotation_at = Instant::now() + interval;
    }

    pub fn reload_public_keys(&mut self) -> Result<()> {
        self.public_keys = load_public_cache(&self.pub_dir)?;
        Ok(())
    }

    pub fn derive_secret32(&self, label: &[u8]) -> Result<Byte32> {
        if label == JWT_LABEL {
            return Ok(self.jwt_secret.clone());
        }

        let root_mk = self.mk_provider.load_mk()?;
        load_or_create_label_secret32(&self.secrets_dir, &root_mk, label)
    }

    pub fn mk_provider_mut(&mut self) -> &mut P {
        &mut self.mk_provider
    }

    pub fn with_ed_sk<R>(&self, f: impl FnOnce(Byte32) -> Result<R>) -> Result<R> {
        let mk = self.mk_provider.load_mk()?;
        let seed = keyfile::load_secret32_decrypted(&self.priv_dir.join(ED_PRIV), &mk, KT_ED_SEED)?;
        f(seed)
    }

    pub fn with_x25519_sk<R>(&self, f: impl FnOnce(Byte32) -> Result<R>) -> Result<R> {
        let mk = self.mk_provider.load_mk()?;
        let seed = keyfile::load_secret32_decrypted(&self.priv_dir.join(X_PRIV), &mk, KT_X_SEED)?;
        f(seed)
    }

    pub fn with_kyber_sk<R>(&self, f: impl FnOnce(SecretBytes) -> Result<R>) -> Result<R> {
        let mk = self.mk_provider.load_mk()?;
        let sk = keyfile::load_bytes_decrypted(&self.priv_dir.join(KYBER_PRIV), &mk, KT_KYBER_SK)?;
        f(sk)
    }

    pub fn with_dilithium_sk<R>(&self, f: impl FnOnce(SecretBytes) -> Result<R>) -> Result<R> {
        let mk = self.mk_provider.load_mk()?;
        let sk = keyfile::load_bytes_decrypted(&self.priv_dir.join(DILI_PRIV), &mk, KT_DILI_SK)?;
        f(sk)
    }

    pub fn with_x25519_and_kyber_sk<R>(
        &self,
        f: impl FnOnce(Byte32, SecretBytes) -> Result<R>,
    ) -> Result<R> {
        let mk = self.mk_provider.load_mk()?;
        let x_seed = keyfile::load_secret32_decrypted(&self.priv_dir.join(X_PRIV), &mk, KT_X_SEED)?;
        let kyber_sk = keyfile::load_bytes_decrypted(&self.priv_dir.join(KYBER_PRIV), &mk, KT_KYBER_SK)?;
        f(x_seed, kyber_sk)
    }

    pub fn maybe_rotate_mk(&mut self) -> Result<()> {
        recover_pending_rotation_if_any(
            &self.root_dir,
            &self.priv_dir,
            &self.secrets_dir,
            &self.rotate_dir,
            &self.mk_provider,
        )?;

        if Instant::now() < self.next_rotation_at {
            return Ok(());
        }

        cleanup_rotation_dir(&self.rotate_dir)?;
        fs::create_dir_all(&self.rotate_dir).map_err(LithiumError::io)?;
        sync_dir(&self.rotate_dir)?;

        let old_mk = self.mk_provider.load_mk()?;
        let new_mk = keys::random_master_key32()?;
        let targets = collect_rewrap_targets(&self.root_dir, &self.priv_dir, &self.secrets_dir)?;

        let next_old_path = self.rotate_dir.join(ROTATE_NEXT_OLD_FILE);
        let next_new_path = self.rotate_dir.join(ROTATE_NEXT_NEW_FILE);
        keyfile::save_secret32_encrypted(&next_old_path, &old_mk, &new_mk, KT_ROTATE_NEXT_OLD)?;
        keyfile::save_secret32_encrypted(&next_new_path, &new_mk, &new_mk, KT_ROTATE_NEXT_NEW)?;
        sync_dir(&self.rotate_dir)?;

        prepare_staged_files(&self.rotate_dir, &old_mk, &new_mk, &targets)?;
        write_marker(&self.rotate_dir.join(ROTATE_READY_FILE), b"ready")?;

        apply_staged_files(&self.rotate_dir, &targets)?;
        self.mk_provider.store_mk(&new_mk)?;
        self.jwt_secret = keys::random_32()?;
        self.next_rotation_at = Instant::now() + self.rotate_every;

        cleanup_rotation_dir(&self.rotate_dir)?;
        Ok(())
    }
}

// ===== FILE: ./src/keys/mod.rs =====
// ----------------------------------------

pub mod keyfile;
pub mod manager;

pub use manager::{KeyManager, KeyStoreKind, MkProvider, PlainFileMkProvider, PublicKeys};


// ===== FILE: ./src/lib.rs =====
// ----------------------------------------

#![forbid(unsafe_code)]

pub mod crypto;
pub mod db;
pub mod error;
pub mod keys;
pub mod passwords;
pub mod secrets;
pub mod utils;

pub use error::{CryptoErrorKind, LithiumError, Result};


// ===== FILE: ./src/passwords/mod.rs =====
// ----------------------------------------

pub mod passwords;


// ===== FILE: ./src/passwords/passwords.rs =====
// ----------------------------------------

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};

use crate::{
    crypto::{aead, keys},
    error::{LithiumError, Result},
    secrets::{Byte32, SecretString},
    secrets::bytes::SecretBytes,
};

const DEK_WRAP_VER: u8 = 1;
const DEK_WRAP_AAD: &[u8] = b"lithium/dek-wrap/v1";
const DEK_WRAP_SALT_LEN: usize = 32;

#[derive(Debug, Clone, Copy)]
pub struct PasswordPolicy {
    pub min_len: usize,
    pub max_len: usize,
    pub require_lowercase: bool,
    pub require_uppercase: bool,
    pub require_digit: bool,
    pub require_special: bool,
    pub allow_whitespace: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_len: 8,
            max_len: 1024,
            require_lowercase: true,
            require_uppercase: true,
            require_digit: true,
            require_special: true,
            allow_whitespace: false,
        }
    }
}

fn argon2_std() -> Result<Argon2<'static>> {
    let params = Params::new(64 * 1024, 3, 1, Some(32))
        .map_err(|_| LithiumError::internal())?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

pub fn validate_password(password: &SecretString, pol: PasswordPolicy) -> Result<()> {
    let s = password.expose();
    let len = s.chars().count();

    if len < pol.min_len || len > pol.max_len {
        return Err(LithiumError::string_policy());
    }

    if s.as_bytes().iter().any(|&b| b == 0) {
        return Err(LithiumError::string_policy());
    }

    if !pol.allow_whitespace && s.chars().any(|c| c.is_whitespace()) {
        return Err(LithiumError::string_policy());
    }

    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_special = false;

    for ch in s.chars() {
        if ch.is_ascii_lowercase() {
            has_lower = true;
        } else if ch.is_ascii_uppercase() {
            has_upper = true;
        } else if ch.is_ascii_digit() {
            has_digit = true;
        } else if !ch.is_whitespace() {
            has_special = true;
        }
    }

    if pol.require_lowercase && !has_lower {
        return Err(LithiumError::string_policy());
    }
    if pol.require_uppercase && !has_upper {
        return Err(LithiumError::string_policy());
    }
    if pol.require_digit && !has_digit {
        return Err(LithiumError::string_policy());
    }
    if pol.require_special && !has_special {
        return Err(LithiumError::string_policy());
    }

    Ok(())
}

pub fn validate_passwords_distinct(a: &SecretString, b: &SecretString) -> Result<()> {
    if a.expose() == b.expose() {
        return Err(LithiumError::invalid_credentials("passwords_not_distinct"));
    }
    Ok(())
}

pub fn hash_password_phc(password: &SecretString) -> Result<String> {
    let argon2 = argon2_std()?;
    let salt = SaltString::generate(&mut OsRng);

    let phc = argon2
        .hash_password(password.expose().as_bytes(), &salt)
        .map_err(|_| LithiumError::internal())?;

    Ok(phc.to_string())
}

pub fn verify_password_phc(phc: &str, password: &SecretString) -> Result<bool> {
    let parsed = PasswordHash::new(phc)
        .map_err(|_| LithiumError::invalid_credentials("bad_password_hash"))?;

    let argon2 = argon2_std()?;
    Ok(argon2
        .verify_password(password.expose().as_bytes(), &parsed)
        .is_ok())
}

pub fn generate_dek() -> Result<Byte32> {
    keys::random_32()
}

fn derive_wrap_key(data_password: &SecretString, salt: &[u8]) -> Result<Byte32> {
    let params = Params::new(64 * 1024, 3, 1, Some(32))
        .map_err(|_| LithiumError::internal())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = Byte32::new_zeroed();
    argon2
        .hash_password_into(data_password.expose().as_bytes(), salt, out.as_mut_slice())
        .map_err(|_| LithiumError::internal())?;

    Ok(out)
}

pub fn wrap_dek_for_server_hex(
    dek: &Byte32,
    data_password: &SecretString,
) -> Result<SecretString> {
    let salt = keys::random_fixed::<DEK_WRAP_SALT_LEN>()?;
    let key = derive_wrap_key(data_password, salt.as_slice())?;
    let nonce = keys::random_12()?;

    let blob = aead::encrypt(
        &SecretBytes::from_slice(dek.as_slice()),
        &key,
        &nonce,
        &SecretBytes::from_slice(DEK_WRAP_AAD),
    )?;

    let mut out = Vec::with_capacity(1 + DEK_WRAP_SALT_LEN + blob.len());
    out.push(DEK_WRAP_VER);
    out.extend_from_slice(salt.as_slice());
    out.extend_from_slice(blob.expose_as_slice());

    Ok(SecretString::new(hex::encode(out)))
}

pub fn unwrap_dek_from_server_hex(
    blob_hex: &SecretString,
    data_password: &SecretString,
) -> Result<Byte32> {
    let blob = SecretBytes::from_hex(blob_hex.expose().trim())?;

    if blob.len() < 1 + DEK_WRAP_SALT_LEN + 1 + 12 + 16 {
        return Err(LithiumError::invalid_credentials("bad_dek_blob"));
    }

    if blob.expose_as_slice()[0] != DEK_WRAP_VER {
        return Err(LithiumError::invalid_credentials("bad_dek_blob"));
    }

    let salt = &blob.expose_as_slice()[1..1 + DEK_WRAP_SALT_LEN];
    let wrapped = SecretBytes::from_slice(&blob.expose_as_slice()[1 + DEK_WRAP_SALT_LEN..]);

    let key = derive_wrap_key(data_password, salt)?;
    let pt = aead::decrypt(
        &wrapped,
        &key,
        &SecretBytes::from_slice(DEK_WRAP_AAD),
    )?;

    Byte32::from_slice(pt.expose_as_slice())
}

// ===== FILE: ./src/secrets/bytes.rs =====
// ----------------------------------------

use core::fmt;
use core::hash::{Hash, Hasher};
use subtle::ConstantTimeEq;

use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};

use crate::error::{CryptoErrorKind, LithiumError, Result};
use crate::secrets::SecretString;

pub struct FixedBytes<const N: usize>(SecretBox<[u8; N]>);

impl<const N: usize> FixedBytes<N> {
    pub const LEN: usize = N;

    #[inline]
    pub fn new(bytes: [u8; N]) -> Self {
        Self(SecretBox::new(Box::new(bytes)))
    }

    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != N {
            return Err(LithiumError::invalid_len(N, slice.len()));
        }
        let mut out = Self::new_zeroed();
        out.as_mut_slice().copy_from_slice(slice);
        Ok(out)
    }

    #[inline]
    pub fn as_array(&self) -> &[u8; N] {
        self.0.expose_secret()
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        self.0.expose_secret().as_slice()
    }

    #[inline]
    pub fn to_hex(&self) -> SecretString {
        SecretString::new(hex::encode(self.as_slice()))
    }

    #[inline]
    pub fn from_hex(s: &str) -> Result<Self> {
        if s.len() >= 2 && (&s[..2] == "0x" || &s[..2] == "0X") {
            return Err(LithiumError::hex_prefix_disallowed());
        }
        let expected = 2 * N;
        if s.len() != expected {
            return Err(LithiumError::new(CryptoErrorKind::InvalidHexLength {
                expected,
                got: s.len(),
            }));
        }
        for &b in s.as_bytes() {
            match b {
                b'0'..=b'9' | b'a'..=b'f' => {}
                b'A'..=b'F' => return Err(LithiumError::hex_must_be_lowercase()),
                _ => return Err(LithiumError::new(CryptoErrorKind::InvalidHex)),
            }
        }

        let mut out = SecretBox::new(Box::new([0u8; N]));
        hex::decode_to_slice(s, out.expose_secret_mut().as_mut_slice()).map_err(LithiumError::from)?;
        Ok(Self(out))
    }

    #[inline]
    pub fn new_zeroed() -> Self {
        Self(SecretBox::new(Box::new([0u8; N])))
    }

    #[inline]
    pub fn as_mut_array(&mut self) -> &mut [u8; N] {
        self.0.expose_secret_mut()
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.expose_secret_mut().as_mut_slice()
    }
}

impl<const N: usize> Clone for FixedBytes<N> {
    fn clone(&self) -> Self {
        let mut out = Self::new_zeroed();
        out.as_mut_slice().copy_from_slice(self.as_slice());
        out
    }
}

impl<const N: usize> PartialEq for FixedBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice().ct_eq(other.as_slice()).into()
    }
}
impl<const N: usize> Eq for FixedBytes<N> {}
impl<const N: usize> Hash for FixedBytes<N> {
    fn hash<H: Hasher>(&self, state: &mut H) { self.as_slice().hash(state); }
}
impl<const N: usize> fmt::Debug for FixedBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "FixedBytes<{}>(..)", N) }
}
impl<const N: usize> AsRef<[u8]> for FixedBytes<N> {
    fn as_ref(&self) -> &[u8] { self.as_slice() }
}
impl<const N: usize> TryFrom<&[u8]> for FixedBytes<N> {
    type Error = LithiumError;
    fn try_from(value: &[u8]) -> Result<Self> { Self::from_slice(value) }
}
impl<const N: usize> From<[u8; N]> for FixedBytes<N> {
    fn from(value: [u8; N]) -> Self { Self::new(value) }
}

pub type Byte12 = FixedBytes<12>;
pub type Byte32 = FixedBytes<32>;
pub type Byte64 = FixedBytes<64>;
pub type Byte2048 = FixedBytes<2048>;

pub struct SecretBytes(SecretBox<Vec<u8>>);

impl SecretBytes {
    #[inline]
    pub fn new(v: Vec<u8>) -> Self { Self(SecretBox::new(Box::new(v))) }
    #[inline]
    pub fn from_vec(v: Vec<u8>) -> Self { Self::new(v) }
    #[inline]
    pub fn from_slice(v: &[u8]) -> Self { Self::new(v.to_vec()) }
    #[inline]
    pub fn expose_as_slice(&self) -> &[u8] { self.0.expose_secret().as_slice() }
    #[inline]
    pub fn expose_as_mut_vec(&mut self) -> &mut Vec<u8> { self.0.expose_secret_mut() }
    #[inline]
    pub fn expose_into_vec(self) -> Vec<u8> { self.0.expose_secret().clone() }
    #[inline]
    pub fn to_hex(&self) -> SecretString { SecretString::new(hex::encode(self.expose_as_slice())) }
    #[inline]
    pub fn len(&self) -> usize { self.expose_as_slice().len() }
    #[inline]
    pub fn is_empty(&self) -> bool { self.expose_as_slice().is_empty() }

    #[inline]
    pub fn from_hex(s: &str) -> Result<Self> {
        if s.len() >= 2 && (&s[..2] == "0x" || &s[..2] == "0X") {
            return Err(LithiumError::hex_prefix_disallowed());
        }
        if (s.len() % 2) != 0 {
            return Err(LithiumError::new(CryptoErrorKind::InvalidHexLength {
                expected: s.len() + 1,
                got: s.len(),
            }));
        }
        for &b in s.as_bytes() {
            match b {
                b'0'..=b'9' | b'a'..=b'f' => {}
                b'A'..=b'F' => return Err(LithiumError::hex_must_be_lowercase()),
                _ => return Err(LithiumError::new(CryptoErrorKind::InvalidHex)),
            }
        }

        let mut out = Self::new(vec![0u8; s.len() / 2]);
        hex::decode_to_slice(s, out.expose_as_mut_vec()).map_err(LithiumError::from)?;
        Ok(out)
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self { Self::from_slice(self.expose_as_slice()) }
}
impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("SecretBytes(..)") }
}
impl ExposeSecret<Vec<u8>> for SecretBytes {
    fn expose_secret(&self) -> &Vec<u8> { self.0.expose_secret() }
}
impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        self.expose_as_slice()
    }
}

// ===== FILE: ./src/secrets/json.rs =====
// ----------------------------------------

use core::fmt;

use secrecy::{ExposeSecret, SecretBox};
use serde_json::{map::Map, Value};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{LithiumError, Result};
use crate::secrets::string::SecretString;

pub struct SecretJson {
    value: Value,
    raw: Option<SecretString>,
}

#[inline]
fn ty_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

impl SecretJson {
    #[inline]
    pub fn from_str(s: &str) -> Result<Self> {
        let v: Value = serde_json::from_str(s)?;
        Ok(Self { value: v, raw: Some(SecretString::new(s.to_owned())) })
    }
    #[inline]
    pub fn from_string(s: String) -> Result<Self> {
        let v: Value = serde_json::from_str(&s)?;
        Ok(Self { value: v, raw: Some(SecretString::new(s)) })
    }
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let s = core::str::from_utf8(bytes).map_err(|e| LithiumError::string_policy().with_source(e))?;
        Self::from_str(s)
    }
    #[inline]
    pub fn from_vec(bytes: Vec<u8>) -> Result<Self> {
        let s = String::from_utf8(bytes).map_err(|e| LithiumError::string_policy().with_source(e))?;
        Self::from_string(s)
    }
    #[inline]
    pub fn from_zeroizing_vec(bytes: Zeroizing<Vec<u8>>) -> Result<Self> {
        let s = core::str::from_utf8(bytes.as_slice())
            .map_err(|e| LithiumError::string_policy().with_source(e))?;
        Self::from_str(s)
    }
    #[inline]
    pub fn from_zeroizing_vec_no_raw(bytes: Zeroizing<Vec<u8>>) -> Result<Self> {
        let v: Value = serde_json::from_slice(bytes.as_slice())?;
        Ok(Self { value: v, raw: None })
    }

    fn zeroize_value(v: &mut Value) {
        match v {
            Value::String(s) => {
                s.zeroize();
                s.clear();
                s.shrink_to_fit();
            }
            Value::Array(arr) => {
                for elem in arr.iter_mut() { Self::zeroize_value(elem); }
                arr.clear();
                arr.shrink_to_fit();
            }
            Value::Object(map) => {
                let owned: Map<String, Value> = core::mem::take(map);
                for (mut k, mut mut_v) in owned.into_iter() {
                    Self::zeroize_value(&mut mut_v);
                    drop(mut_v);
                    k.zeroize();
                    k.clear();
                    k.shrink_to_fit();
                }
            }
            Value::Number(_) => *v = Value::Null,
            Value::Bool(_) | Value::Null => {}
        }
    }

    #[inline]
    pub fn with_exposed<R>(&self, f: impl FnOnce(&Value) -> R) -> R { f(&self.value) }
    #[inline]
    pub fn with_exposed_mut<R>(&mut self, f: impl FnOnce(&mut Value) -> R) -> R { f(&mut self.value) }
    #[inline]
    fn obj(&self) -> Result<&Map<String, Value>> { self.value.as_object().ok_or_else(LithiumError::json_not_object) }
    #[inline]
    fn obj_mut(&mut self) -> Result<&mut Map<String, Value>> { self.value.as_object_mut().ok_or_else(LithiumError::json_not_object) }

    #[inline]
    pub fn get_string(&self, key: &'static str) -> Result<SecretString> {
        let obj = self.obj()?;
        let v = obj.get(key).ok_or_else(|| LithiumError::json_missing_field(key))?;
        match v { Value::String(s) => Ok(SecretString::new(s.clone())), other => Err(LithiumError::json_type_mismatch(key, ty_name(other))) }
    }
    #[inline]
    pub fn get_integer(&self, key: &'static str) -> Result<SecretBox<i64>> {
        let obj = self.obj()?;
        let v = obj.get(key).ok_or_else(|| LithiumError::json_missing_field(key))?;
        match v.as_i64() { Some(i) => Ok(SecretBox::new(Box::new(i))), None => Err(LithiumError::json_type_mismatch(key, ty_name(v))) }
    }
    #[inline]
    pub fn get_bool(&self, key: &'static str) -> Result<bool> {
        let obj = self.obj()?;
        let v = obj.get(key).ok_or_else(|| LithiumError::json_missing_field(key))?;
        v.as_bool().ok_or_else(|| LithiumError::json_type_mismatch(key, ty_name(v)))
    }
    #[inline]
    pub fn get_array(&self, key: &'static str) -> Result<Vec<SecretJson>> {
        let obj = self.obj()?;
        let v = obj.get(key).ok_or_else(|| LithiumError::json_missing_field(key))?;
        match v.as_array() { Some(a) => Ok(a.iter().cloned().map(SecretJson::from).collect()), None => Err(LithiumError::json_type_mismatch(key, ty_name(v))) }
    }
    #[inline]
    pub fn get_object(&self, key: &'static str) -> Result<SecretJson> {
        let obj = self.obj()?;
        let v = obj.get(key).ok_or_else(|| LithiumError::json_missing_field(key))?;
        match v.as_object() { Some(o) => Ok(SecretJson::from(Value::Object(o.clone()))), None => Err(LithiumError::json_type_mismatch(key, ty_name(v))) }
    }
    #[inline]
    pub fn take_string(&mut self, key: &'static str) -> Result<SecretString> {
        let obj = self.obj_mut()?;
        match obj.remove(key) { Some(Value::String(s)) => Ok(SecretString::new(s)), Some(other) => Err(LithiumError::json_type_mismatch(key, ty_name(&other))), None => Err(LithiumError::json_missing_field(key)) }
    }
    #[inline]
    pub fn take_bool(&mut self, key: &'static str) -> Result<bool> {
        let obj = self.obj_mut()?;
        match obj.remove(key) { Some(Value::Bool(b)) => Ok(b), Some(other) => Err(LithiumError::json_type_mismatch(key, ty_name(&other))), None => Err(LithiumError::json_missing_field(key)) }
    }
    #[inline]
    pub fn take_i64(&mut self, key: &'static str) -> Result<SecretBox<i64>> {
        let obj = self.obj_mut()?;
        match obj.remove(key) { Some(Value::Number(n)) => n.as_i64().map(|i| SecretBox::new(Box::new(i))).ok_or_else(|| LithiumError::json_type_mismatch(key, "number")), Some(other) => Err(LithiumError::json_type_mismatch(key, ty_name(&other))), None => Err(LithiumError::json_missing_field(key)) }
    }
    #[inline]
    pub fn take_u64(&mut self, key: &'static str) -> Result<SecretBox<u64>> {
        let obj = self.obj_mut()?;
        match obj.remove(key) { Some(Value::Number(n)) => n.as_u64().map(|u| SecretBox::new(Box::new(u))).ok_or_else(|| LithiumError::json_type_mismatch(key, "number")), Some(other) => Err(LithiumError::json_type_mismatch(key, ty_name(&other))), None => Err(LithiumError::json_missing_field(key)) }
    }
    #[inline]
    pub fn take_f64(&mut self, key: &'static str) -> Result<SecretBox<f64>> {
        let obj = self.obj_mut()?;
        match obj.remove(key) { Some(Value::Number(n)) => n.as_f64().map(|u| SecretBox::new(Box::new(u))).ok_or_else(|| LithiumError::json_type_mismatch(key, "number")), Some(other) => Err(LithiumError::json_type_mismatch(key, ty_name(&other))), None => Err(LithiumError::json_missing_field(key)) }
    }
    #[inline]
    pub fn take_array(&mut self, key: &'static str) -> Result<Vec<SecretJson>> {
        let obj = self.obj_mut()?;
        match obj.remove(key) { Some(Value::Array(a)) => Ok(a.into_iter().map(SecretJson::from).collect()), Some(other) => Err(LithiumError::json_type_mismatch(key, ty_name(&other))), None => Err(LithiumError::json_missing_field(key)) }
    }
    #[inline]
    pub fn take_object(&mut self, key: &'static str) -> Result<SecretJson> {
        let obj = self.obj_mut()?;
        match obj.remove(key) { Some(Value::Object(o)) => Ok(SecretJson::from(Value::Object(o))), Some(other) => Err(LithiumError::json_type_mismatch(key, ty_name(&other))), None => Err(LithiumError::json_missing_field(key)) }
    }
    #[inline]
    pub fn take_raw_json(&mut self) -> Option<SecretString> { self.raw.take() }
    #[inline]
    pub fn get_raw_json(&self) -> Option<SecretString> { self.raw.as_ref().cloned() }
    #[inline]
    pub fn raw_json(&self) -> Option<SecretString> { self.get_raw_json() }
}

impl From<Value> for SecretJson {
    fn from(value: Value) -> Self { SecretJson { value, raw: None } }
}
impl Drop for SecretJson {
    fn drop(&mut self) { Self::zeroize_value(&mut self.value); }
}
impl fmt::Debug for SecretJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("SecretJson(<redacted>)") }
}
impl fmt::Display for SecretJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("<redacted>") }
}
impl ExposeSecret<Value> for SecretJson {
    fn expose_secret(&self) -> &Value { &self.value }
}


// ===== FILE: ./src/secrets/mod.rs =====
// ----------------------------------------

pub mod bytes;
pub mod json;
pub mod string;
pub mod types;

pub use bytes::{Byte12, Byte32, Byte64, Byte2048, FixedBytes, SecretBytes};
pub use json::SecretJson;
pub use string::SecretString;
pub use types::{MasterKey32, Nonce12, SessionId32};


// ===== FILE: ./src/secrets/string.rs =====
// ----------------------------------------

use core::fmt;

use secrecy::{ExposeSecret, SecretString as SecrecySecretString};
use zeroize::Zeroizing;

use crate::error::{LithiumError, Result};
use crate::secrets::bytes::FixedBytes;

#[derive(Clone)]
pub struct SecretString(SecrecySecretString);

impl SecretString {
    #[inline]
    pub fn new(s: String) -> Self {
        Self(SecrecySecretString::new(Box::from(s)))
    }

    #[inline]
    pub fn new_checked(s: String) -> Result<Self> {
        if s.as_bytes().iter().any(|&b| b == 0) {
            return Err(LithiumError::string_policy());
        }
        Ok(Self::new(s))
    }

    #[inline]
    pub fn expose(&self) -> &str { self.0.expose_secret() }
    #[inline]
    pub fn to_zeroizing(&self) -> Zeroizing<String> { Zeroizing::new(self.expose().to_owned()) }

    #[inline]
    pub fn from_utf8_bytes(bytes: &[u8]) -> Result<Self> {
        let s = core::str::from_utf8(bytes)
            .map_err(|e| LithiumError::string_policy().with_source(e))?
            .to_owned();
        Self::new_checked(s)
    }

    #[inline]
    pub fn from_utf8_vec(bytes: Vec<u8>) -> Result<Self> {
        let s = String::from_utf8(bytes).map_err(|e| LithiumError::string_policy().with_source(e))?;
        Self::new_checked(s)
    }

    #[inline]
    pub fn decode_hex(&self) -> Result<Zeroizing<Vec<u8>>> {
        let v = hex::decode(self.expose()).map_err(LithiumError::from)?;
        Ok(Zeroizing::new(v))
    }

    #[inline]
    pub fn decode_hex_fixed<const N: usize>(&self) -> Result<FixedBytes<N>> {
        FixedBytes::<N>::from_hex(self.expose())
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("SecretString(<redacted>)") }
}
impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("<redacted>") }
}
impl TryFrom<&[u8]> for SecretString {
    type Error = LithiumError;
    fn try_from(value: &[u8]) -> Result<Self> { Self::from_utf8_bytes(value) }
}
impl TryFrom<Vec<u8>> for SecretString {
    type Error = LithiumError;
    fn try_from(value: Vec<u8>) -> Result<Self> { Self::from_utf8_vec(value) }
}
impl TryFrom<&Vec<u8>> for SecretString {
    type Error = LithiumError;
    fn try_from(value: &Vec<u8>) -> Result<Self> { Self::from_utf8_bytes(value.as_slice()) }
}
impl ExposeSecret<str> for SecretString {
    fn expose_secret(&self) -> &str { self.expose() }
}


// ===== FILE: ./src/secrets/types.rs =====
// ----------------------------------------

pub(crate) use crate::secrets::bytes::{Byte12, Byte32};

pub type MasterKey32 = Byte32;
pub type Nonce12 = Byte12;
pub type SessionId32 = Byte32;


// ===== FILE: ./src/utils/headers.rs =====
// ----------------------------------------

use std::collections::HashMap;

use crate::{error::{LithiumError, Result}, secrets::{FixedBytes, SecretString}, secrets::bytes::SecretBytes};

pub fn header_str(headers: &HashMap<String, Vec<u8>>, name: &'static str) -> Result<SecretString> {
    let v = headers.get(&name.to_ascii_lowercase()).ok_or_else(|| LithiumError::missing_header(name))?;
    SecretString::from_utf8_bytes(v)
}

pub fn header_hex<const N: usize>(headers: &HashMap<String, Vec<u8>>, name: &'static str) -> Result<FixedBytes<N>> {
    let s = header_str(headers, name)?;
    FixedBytes::<N>::from_hex(s.expose())
}

pub fn header_hex_bytes(headers: &HashMap<String, Vec<u8>>, name: &'static str) -> Result<SecretBytes> {
    let s = header_str(headers, name)?;
    SecretBytes::from_hex(s.expose())
}


// ===== FILE: ./src/utils/mod.rs =====
// ----------------------------------------

pub mod headers;
pub mod store;


// ===== FILE: ./src/utils/store.rs =====
// ----------------------------------------

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use zeroize::Zeroize;

use crate::error::Result;
use crate::secrets::bytes::SecretBytes;

#[derive(Clone)]
pub struct EphemeralStoreManager {
    inner: Arc<Mutex<StoreInner>>,
}

#[derive(Default)]
struct StoreInner {
    map: HashMap<String, StoreEntry>,
    heap: BinaryHeap<HeapEntry>,
    next_version: u64,
}

struct StoreEntry {
    ciphertext: SecretBytes,
    expires_at: Instant,
    version: u64,
}

#[derive(Clone)]
struct HeapEntry {
    expires_at: Instant,
    version: u64,
    key: String,
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other.expires_at.cmp(&self.expires_at)
            .then_with(|| other.version.cmp(&self.version))
            .then_with(|| other.key.cmp(&self.key))
    }
}
impl PartialOrd for HeapEntry { fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) } }
impl PartialEq for HeapEntry { fn eq(&self, other: &Self) -> bool { self.expires_at == other.expires_at && self.version == other.version && self.key == other.key } }
impl Eq for HeapEntry {}

impl EphemeralStoreManager {
    pub fn new() -> Result<Self> {
        let inner = Arc::new(Mutex::new(StoreInner::default()));
        let mgr = Self { inner: inner.clone() };
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                let _ = EphemeralStoreManager::cleanup_once(&inner).await;
            }
        });
        Ok(mgr)
    }

    async fn cleanup_once(inner: &Arc<Mutex<StoreInner>>) -> Result<()> {
        let now = Instant::now();
        let mut guard = inner.lock().await;
        loop {
            let Some(top) = guard.heap.peek().cloned() else { break; };
            if top.expires_at > now { break; }
            guard.heap.pop();
            let should_remove = match guard.map.get(&top.key) {
                Some(cur) => cur.version == top.version && cur.expires_at <= now,
                None => false,
            };
            if should_remove {
                if let Some(mut removed) = guard.map.remove(&top.key) {
                    removed.ciphertext.expose_as_mut_vec().zeroize();
                }
            }
        }
        Ok(())
    }

    fn next_version(guard: &mut StoreInner) -> u64 {
        let v = guard.next_version;
        guard.next_version = guard.next_version.wrapping_add(1);
        v
    }

    pub async fn set(&self, key: &str, value: &SecretBytes, ttl: Duration) -> Result<()> {
        if ttl.is_zero() { return Ok(()); }
        let expires_at = Instant::now() + ttl;
        let mut guard = self.inner.lock().await;
        let ver = Self::next_version(&mut guard);
        let entry = StoreEntry { ciphertext: value.clone(), expires_at, version: ver };
        guard.map.insert(key.to_owned(), entry);
        guard.heap.push(HeapEntry { expires_at, version: ver, key: key.to_owned() });
        Ok(())
    }

    pub async fn set_if_absent(&self, key: &str, value: &SecretBytes, ttl: Duration) -> Result<bool> {
        let now = Instant::now();
        let expires_at = now + ttl;
        let mut guard = self.inner.lock().await;
        if let Some(e) = guard.map.get(key) {
            if e.expires_at > now { return Ok(false); }
        }
        let ver = Self::next_version(&mut guard);
        guard.map.insert(key.to_owned(), StoreEntry { ciphertext: value.clone(), expires_at, version: ver });
        guard.heap.push(HeapEntry { expires_at, version: ver, key: key.to_owned() });
        Ok(true)
    }

    pub async fn peek(&self, key: &str) -> Result<Option<SecretBytes>> {
        let now = Instant::now();
        let mut guard = self.inner.lock().await;
        if let Some(entry) = guard.map.get(key) {
            if entry.expires_at <= now {
                let _ = guard.map.remove(key);
                return Ok(None);
            }
            return Ok(Some(entry.ciphertext.clone()));
        }
        Ok(None)
    }

    pub async fn take(&self, key: &str) -> Result<Option<SecretBytes>> {
        let now = Instant::now();
        let mut guard = self.inner.lock().await;
        let Some(mut entry) = guard.map.remove(key) else { return Ok(None); };
        if entry.expires_at <= now {
            entry.ciphertext.expose_as_mut_vec().zeroize();
            return Ok(None);
        }
        Ok(Some(entry.ciphertext))
    }

    pub async fn del(&self, key: &str) -> Result<()> {
        let mut guard = self.inner.lock().await;
        if let Some(mut entry) = guard.map.remove(key) { entry.ciphertext.expose_as_mut_vec().zeroize(); }
        Ok(())
    }
}

pub fn hash_sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

