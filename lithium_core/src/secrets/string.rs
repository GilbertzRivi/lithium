use core::fmt;

use secrecy::{ExposeSecret, SecretString as SecrecySecretString};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer};
use zeroize::{Zeroize, Zeroizing};

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
        if s.as_bytes().contains(&0) {
            return Err(LithiumError::string_policy());
        }
        Ok(Self::new(s))
    }

    #[inline]
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }

    #[inline]
    pub fn to_zeroizing(&self) -> Zeroizing<String> {
        Zeroizing::new(self.expose().to_owned())
    }

    #[inline]
    pub fn from_utf8_bytes(bytes: &[u8]) -> Result<Self> {
        let s = core::str::from_utf8(bytes)
            .map_err(|e| LithiumError::string_policy().with_source(e))?
            .to_owned();
        Self::new_checked(s)
    }

    #[inline]
    pub fn from_utf8_vec(bytes: Vec<u8>) -> Result<Self> {
        let s =
            String::from_utf8(bytes).map_err(|e| LithiumError::string_policy().with_source(e))?;
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

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut s = String::deserialize(deserializer)?;

        if s.as_bytes().contains(&0) {
            s.zeroize();
            return Err(D::Error::custom("invalid secret string"));
        }

        Ok(Self::new(s))
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl TryFrom<&[u8]> for SecretString {
    type Error = LithiumError;
    fn try_from(value: &[u8]) -> Result<Self> {
        Self::from_utf8_bytes(value)
    }
}

impl TryFrom<Vec<u8>> for SecretString {
    type Error = LithiumError;
    fn try_from(value: Vec<u8>) -> Result<Self> {
        Self::from_utf8_vec(value)
    }
}

impl TryFrom<&Vec<u8>> for SecretString {
    type Error = LithiumError;
    fn try_from(value: &Vec<u8>) -> Result<Self> {
        Self::from_utf8_bytes(value.as_slice())
    }
}

impl ExposeSecret<str> for SecretString {
    fn expose_secret(&self) -> &str {
        self.expose()
    }
}
