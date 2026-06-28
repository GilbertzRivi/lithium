// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

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
        let Some(src) = self.source.as_deref() else {
            return false;
        };
        if let Some(ioe) = src.downcast_ref::<std::io::Error>() {
            return ioe.kind() == std::io::ErrorKind::NotFound;
        }
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoErrorKind {
    InvalidLength {
        expected: usize,
        got: usize,
    },
    InvalidHexLength {
        expected: usize,
        got: usize,
    },
    InvalidHex,
    HexDisallowedPrefix,
    HexMustBeLowercase,
    StringPolicy,
    MissingHeader {
        name: &'static str,
    },
    InvalidUtf8Header {
        name: &'static str,
    },
    JsonParse,
    JsonNotObject,
    JsonMissingField {
        key: &'static str,
    },
    JsonTypeMismatch {
        key: &'static str,
        expected: &'static str,
    },
    InvalidCredentials {
        msg: &'static str,
    },
    InvalidPermissions {
        msg: &'static str,
    },
    InvalidUtf {
        msg: &'static str,
    },
    EnvMissing {
        name: &'static str,
    },
    EnvInvalid {
        name: &'static str,
    },
    StateMissing {
        name: &'static str,
    },
    HttpStatus {
        code: u16,
    },
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
                CryptoErrorKind::InvalidLength { expected, got } => {
                    write!(f, "invalid length: expected {expected}, got {got}")?
                }
                CryptoErrorKind::InvalidHexLength { expected, got } => {
                    write!(f, "invalid hex length: expected {expected}, got {got}")?
                }
                CryptoErrorKind::MissingHeader { name } => write!(f, "missing header: {name}")?,
                CryptoErrorKind::InvalidUtf8Header { name } => {
                    write!(f, "invalid utf-8 in header: {name}")?
                }
                CryptoErrorKind::JsonMissingField { key } => {
                    write!(f, "json missing field: {key}")?
                }
                CryptoErrorKind::JsonTypeMismatch { key, expected } => {
                    write!(f, "json type mismatch at {key}: expected {expected}")?
                }
                CryptoErrorKind::InvalidCredentials { msg } => {
                    write!(f, "invalid credentials: {msg}")?
                }
                CryptoErrorKind::InvalidPermissions { msg } => {
                    write!(f, "invalid permissions: {msg}")?
                }
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
