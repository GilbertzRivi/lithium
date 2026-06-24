use aes_gcm_siv::{
    Aes256GcmSiv, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};

use crate::{
    error::{LithiumError, Result},
    secrets::bytes::SecretBytes,
    secrets::{Byte12, Byte32},
};

const AEAD_BLOB_VERSION: u8 = 1;

pub fn encrypt_raw(
    plaintext: &SecretBytes,
    key: &Byte32,
    nonce: &Byte12,
    aad: &SecretBytes,
) -> Result<SecretBytes> {
    let key: &Key<Aes256GcmSiv> = key.as_slice().into();

    let nonce: &Nonce = nonce.as_slice().into();

    let cipher = Aes256GcmSiv::new(key);
    let ct = cipher.encrypt(
        nonce,
        Payload {
            msg: plaintext.expose_as_slice(),
            aad: aad.expose_as_slice(),
        },
    )?;

    Ok(SecretBytes::new(ct))
}

pub fn decrypt_raw(
    ciphertext: &SecretBytes,
    key: &Byte32,
    nonce: &Byte12,
    aad: &SecretBytes,
) -> Result<SecretBytes> {
    let key: &Key<Aes256GcmSiv> = key.as_slice().into();

    let nonce: &Nonce = nonce.as_slice().into();

    let cipher = Aes256GcmSiv::new(key);
    let pt = cipher.decrypt(
        nonce,
        Payload {
            msg: ciphertext.expose_as_slice(),
            aad: aad.expose_as_slice(),
        },
    )?;

    Ok(SecretBytes::new(pt))
}

pub fn encrypt(
    plaintext: &SecretBytes,
    key: &Byte32,
    nonce: &Byte12,
    aad: &SecretBytes,
) -> Result<SecretBytes> {
    let ct = encrypt_raw(plaintext, key, nonce, aad)?;
    let mut out = Vec::with_capacity(1 + 12 + ct.len());
    out.push(AEAD_BLOB_VERSION);
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(ct.expose_as_slice());
    Ok(SecretBytes::new(out))
}

pub fn decrypt(blob: &SecretBytes, key: &Byte32, aad: &SecretBytes) -> Result<SecretBytes> {
    if blob.len() < 1 + 12 + 16 {
        return Err(LithiumError::aead_failed());
    }
    if blob.expose_as_slice()[0] != AEAD_BLOB_VERSION {
        return Err(LithiumError::aead_failed());
    }
    let nonce = Byte12::from_slice(&blob.expose_as_slice()[1..13])?;
    let ct = SecretBytes::from_slice(&blob.expose_as_slice()[13..]);
    decrypt_raw(&ct, key, &nonce, aad)
}
