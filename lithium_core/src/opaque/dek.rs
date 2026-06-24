use crate::crypto::{aead, kdf, keys};
use crate::error::{LithiumError, Result};
use crate::secrets::bytes::SecretBytes;
use crate::secrets::{Byte32, Byte64, SecretString};

const DEK_WRAP_VER: u8 = 1;

fn wrap_key(export_key: &Byte64, aad: &[u8]) -> Result<Byte32> {
    kdf::derive32(
        &SecretBytes::from_slice(export_key.as_slice()),
        None,
        &SecretBytes::from_slice(aad),
    )
}

pub fn wrap_dek_under_export_key(
    dek: &Byte32,
    export_key: &Byte64,
    aad: &[u8],
) -> Result<SecretString> {
    let key = wrap_key(export_key, aad)?;
    let nonce = keys::random_12()?;
    let blob = aead::encrypt(
        &SecretBytes::from_slice(dek.as_slice()),
        &key,
        &nonce,
        &SecretBytes::from_slice(aad),
    )?;

    let mut out = Vec::with_capacity(1 + blob.len());
    out.push(DEK_WRAP_VER);
    out.extend_from_slice(blob.expose_as_slice());

    Ok(SecretString::new(hex::encode(out)))
}

pub fn unwrap_dek_under_export_key(
    blob_hex: &SecretString,
    export_key: &Byte64,
    aad: &[u8],
) -> Result<Byte32> {
    let blob = SecretBytes::from_hex(blob_hex.expose().trim())?;

    if blob.len() < 1 + 1 + 12 + 16 {
        return Err(LithiumError::invalid_credentials("bad_dek_blob"));
    }
    if blob.expose_as_slice()[0] != DEK_WRAP_VER {
        return Err(LithiumError::invalid_credentials("bad_dek_blob"));
    }

    let key = wrap_key(export_key, aad)?;
    let wrapped = SecretBytes::from_slice(&blob.expose_as_slice()[1..]);
    let pt = aead::decrypt(&wrapped, &key, &SecretBytes::from_slice(aad))?;

    Byte32::from_slice(pt.expose_as_slice())
}
