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

    if s.as_bytes().contains(&0) {
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