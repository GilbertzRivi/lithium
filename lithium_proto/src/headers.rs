use std::collections::HashMap;

use lithium_core::{
    error::{LithiumError, Result},
    secrets::bytes::SecretBytes,
    secrets::{FixedBytes, SecretString},
};

pub fn header_str(headers: &HashMap<String, Vec<u8>>, name: &'static str) -> Result<SecretString> {
    let v = headers
        .get(&name.to_ascii_lowercase())
        .ok_or_else(|| LithiumError::missing_header(name))?;
    SecretString::from_utf8_bytes(v)
}

pub fn header_hex<const N: usize>(
    headers: &HashMap<String, Vec<u8>>,
    name: &'static str,
) -> Result<FixedBytes<N>> {
    let s = header_str(headers, name)?;
    FixedBytes::<N>::from_hex(s.expose())
}

pub fn header_hex_bytes(
    headers: &HashMap<String, Vec<u8>>,
    name: &'static str,
) -> Result<SecretBytes> {
    let s = header_str(headers, name)?;
    SecretBytes::from_hex(s.expose())
}
