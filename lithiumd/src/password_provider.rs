use std::path::PathBuf;

use lithium_core::{
    crypto::{aead, keys},
    error::{LithiumError, Result},
    keys::MkProvider,
    secrets::{Byte32, SecretString},
    keys::keyfile,
};

use argon2::{Argon2, Algorithm, Version, Params};
use lithium_core::secrets::bytes::SecretBytes;

const MAGIC: &[u8; 4] = b"LMK1";
const SALT_LEN: usize = 32;
const AAD: &[u8] = b"lithium/mkfile/v1";

pub struct PasswordFileMkProvider {
    path: PathBuf,
    pass: SecretString,
}

impl PasswordFileMkProvider {
    pub fn new(path: PathBuf, pass: SecretString) -> Self {
        Self { path, pass }
    }

    fn derive_user_key(&self, salt: &Byte32) -> Result<Byte32> {
        let params = Params::new(
            64 * 1024, 
            3, 
            1, 
            Some(32),
        ).map_err(|_| LithiumError::internal())?;

        let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut out = [0u8; 32];
        a2.hash_password_into(self.pass.expose().as_bytes(), salt.as_slice(), &mut out)
            .map_err(|_| LithiumError::internal())?;

        Ok(Byte32::new(out))
    }

    fn encode_file(salt: &Byte32, blob: &SecretBytes) -> SecretBytes {
        let mut out = Vec::with_capacity(4 + 1 + SALT_LEN + 4 + blob.as_slice().len());
        out.extend_from_slice(MAGIC);
        out.push(SALT_LEN as u8);
        out.extend_from_slice(salt.as_slice());
        out.extend_from_slice(&(blob.as_slice().len() as u32).to_le_bytes());
        out.extend_from_slice(blob.as_slice());
        SecretBytes::from_vec(out)
    }

    fn decode_file(buf: &SecretBytes) -> Result<(Byte32, SecretBytes)> {
        let b = buf.as_slice();

        if b.len() < 4 + 1 + SALT_LEN + 4 {
            return Err(LithiumError::internal());
        }
        if &b[0..4] != MAGIC {
            return Err(LithiumError::internal());
        }

        let salt_len = b[4] as usize;
        if salt_len != SALT_LEN {
            return Err(LithiumError::internal());
        }

        let salt_off = 5;
        let salt = Byte32::from_slice(&b[salt_off..salt_off + SALT_LEN])?;

        let len_off = salt_off + SALT_LEN;
        let blob_len = u32::from_le_bytes(
            b[len_off..len_off + 4]
                .try_into()
                .map_err(|_| LithiumError::internal())?,
        ) as usize;

        let blob_off = len_off + 4;
        if b.len() != blob_off + blob_len {
            return Err(LithiumError::internal());
        }

        Ok((salt, SecretBytes::from_slice(&b[blob_off..])))
    }
}

impl MkProvider for PasswordFileMkProvider {
    fn load_mk(&self) -> Result<Byte32> {
        let buf = keyfile::read_keyfile_bytes(&self.path)?;

        let (salt, blob) = Self::decode_file(&SecretBytes::new(buf))?;
        let user_key = self.derive_user_key(&salt)?;

        let pt = aead::decrypt(&blob, &user_key, &SecretBytes::from_slice(AAD))
            .map_err(|e| {
                if e.kind == lithium_core::error::CryptoErrorKind::AeadFailed {
                    LithiumError::invalid_credentials("bad_data_password")
                } else {
                    e
                }
            })?;
        Byte32::from_slice(pt.as_slice())
    }

    fn store_mk(&self, mk: &Byte32) -> Result<()> {
        let salt = keys::random_32()?;

        let user_key = self.derive_user_key(&salt)?;

        let nonce = keys::random_12()?;
        let blob = aead::encrypt(&SecretBytes::from_slice(mk.as_slice()), &user_key, &nonce, &SecretBytes::from_slice(AAD))?;

        let bytes = Self::encode_file(&salt, &blob);
        keyfile::write_secure(&self.path, &bytes.as_slice())
    }
}
