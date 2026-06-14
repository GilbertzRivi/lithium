use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};

use lithium_core::{
    crypto::{aead, kdf, keys},
    error::{LithiumError, Result},
    keys::{keyfile, MkProvider},
    secrets::{Byte32, SecretString},
};
use lithium_core::secrets::bytes::SecretBytes;

const MAGIC: &[u8; 4] = b"LMK1";
const SALT_LEN: usize = 32;
const AAD: &[u8] = b"lithium/mkfile/v1";

const USER_ROOT_SALT_FILE: &str = "root.salt";
const USER_COMBINED_LABEL: &[u8] = b"lithium/user-provider/combined/v1";

pub struct PasswordFileMkProvider {
    path: PathBuf,
    pass: SecretString,
    server_dek: Option<Byte32>,
}

impl PasswordFileMkProvider {
    pub fn new(path: PathBuf, pass: SecretString) -> Self {
        Self {
            path,
            pass,
            server_dek: None,
        }
    }

    pub fn set_server_dek(&mut self, dek: Byte32) {
        self.server_dek = Some(dek);
    }

    fn root_salt_path(&self) -> PathBuf {
        match self.path.parent() {
            Some(parent) => parent.join(USER_ROOT_SALT_FILE),
            None => PathBuf::from(USER_ROOT_SALT_FILE),
        }
    }

    fn load_root_salt(&self) -> Result<Option<Byte32>> {
        let path = self.root_salt_path();
        if !path.exists() {
            return Ok(None);
        }

        let buf = keyfile::read_keyfile_bytes(&path)?;
        let salt = Byte32::from_slice(buf.expose_as_slice())?;
        Ok(Some(salt))
    }

    fn ensure_root_salt(&self) -> Result<Byte32> {
        if let Some(existing) = self.load_root_salt()? {
            return Ok(existing);
        }

        let salt = keys::random_32()?;
        keyfile::write_secure(&self.root_salt_path(), salt.as_slice())?;
        Ok(salt)
    }

    fn argon2_32(&self, salt: &[u8]) -> Result<Byte32> {
        let params = Params::new(64 * 1024, 3, 1, Some(32))
            .map_err(|_| LithiumError::internal())?;

        let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut out = Byte32::new_zeroed();
        a2.hash_password_into(self.pass.expose().as_bytes(), salt, out.as_mut_slice())
            .map_err(|_| LithiumError::internal())?;

        Ok(out)
    }

    fn derive_user_key(&self, salt: &Byte32) -> Result<Byte32> {
        self.argon2_32(salt.as_slice())
    }

    fn derive_password_root(&self) -> Result<Byte32> {
        let root_salt = self.ensure_root_salt()?;
        self.argon2_32(root_salt.as_slice())
    }

    fn derive_combined_root(&self) -> Result<Byte32> {
        let server_dek = self
            .server_dek
            .as_ref()
            .ok_or_else(|| LithiumError::invalid_credentials("missing_server_dek"))?;

        let pass_root = self.derive_password_root()?;

        kdf::derive32(
            &SecretBytes::from_slice(server_dek.as_slice()),
            Some(&SecretBytes::from_slice(pass_root.as_slice())),
            &SecretBytes::from_slice(USER_COMBINED_LABEL),
        )
    }

    fn encode_file(salt: &Byte32, blob: &SecretBytes) -> SecretBytes {
        let mut out = Vec::with_capacity(4 + 1 + SALT_LEN + 4 + blob.expose_as_slice().len());
        out.extend_from_slice(MAGIC);
        out.push(SALT_LEN as u8);
        out.extend_from_slice(salt.as_slice());
        out.extend_from_slice(&(blob.expose_as_slice().len() as u32).to_le_bytes());
        out.extend_from_slice(blob.expose_as_slice());
        SecretBytes::new(out)
    }

    fn decode_file(buf: &SecretBytes) -> Result<(Byte32, SecretBytes)> {
        let b = buf.expose_as_slice();

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

        let (salt, blob) = Self::decode_file(&buf)?;
        let user_key = self.derive_user_key(&salt)?;

        let pt = aead::decrypt(&blob, &user_key, &SecretBytes::from_slice(AAD))
            .map_err(|e| {
                if e.kind == lithium_core::error::CryptoErrorKind::AeadFailed {
                    LithiumError::invalid_credentials("bad_data_password")
                } else {
                    e
                }
            })?;
        Byte32::from_slice(pt.expose_as_slice())
    }

    fn store_mk(&self, mk: &Byte32) -> Result<()> {
        let _root_salt = self.ensure_root_salt()?;

        let salt = keys::random_32()?;
        let user_key = self.derive_user_key(&salt)?;

        let nonce = keys::random_12()?;
        let blob = aead::encrypt(
            &SecretBytes::from_slice(mk.as_slice()),
            &user_key,
            &nonce,
            &SecretBytes::from_slice(AAD),
        )?;

        let bytes = Self::encode_file(&salt, &blob);
        keyfile::write_secure(&self.path, bytes.expose_as_slice())
    }

    fn derive_secret32(&self, _mk: &Byte32, label: &[u8], _secrets_dir: &Path) -> Result<Byte32> {
        let root = self.derive_combined_root()?;
        kdf::derive32(
            &SecretBytes::from_slice(root.as_slice()),
            None,
            &SecretBytes::from_slice(label),
        )
    }
}