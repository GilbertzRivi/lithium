use crate::{
    crypto::keys,
    error::{LithiumError, Result},
    secrets::{Byte32, SecretString},
};

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
            min_len: 12,
            max_len: 1024,
            require_lowercase: true,
            require_uppercase: true,
            require_digit: true,
            require_special: true,
            allow_whitespace: false,
        }
    }
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

pub fn generate_dek() -> Result<Byte32> {
    keys::random_32()
}
