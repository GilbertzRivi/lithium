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

pub type MasterKey32 = Byte32;
pub type Nonce12 = Byte12;
pub type SessionId32 = Byte32;

pub struct SecretBytes(SecretBox<Vec<u8>>);

impl SecretBytes {
    #[inline]
    pub fn new(v: Vec<u8>) -> Self { Self(SecretBox::new(Box::new(v))) }
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
        if !s.len().is_multiple_of(2) {
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