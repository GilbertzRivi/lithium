use std::path::Path;

use lithium_core::{
    error::{LithiumError, Result},
    secrets::{Byte32, bytes::SecretBytes},
};

use crate::protocol_manager::ServerBootstrap;

const MAGIC: &[u8; 8] = b"LITHIUPK";

/// Parse a `server.identity` file produced by lithiums and return the
/// [`ServerBootstrap`] needed for the encrypted transport layer.
///
/// The file is intentionally not read at daemon startup — call this function
/// only when a server connection is first attempted.
pub fn load(path: &Path) -> Result<ServerBootstrap> {
    parse(&std::fs::read(path).map_err(LithiumError::io)?)
}

pub(crate) fn parse(data: &[u8]) -> Result<ServerBootstrap> {
    if data.len() < 10 || &data[0..8] != MAGIC {
        return Err(LithiumError::invalid_credentials("server_identity_bad_magic"));
    }
    if data[8] != 0x01 {
        return Err(LithiumError::invalid_credentials("server_identity_unknown_version"));
    }

    let entry_count = data[9] as usize;
    let mut pos = 10;

    let mut x25519:   Option<Vec<u8>> = None;
    let mut ed25519:  Option<Vec<u8>> = None;
    let mut mlkem:    Option<Vec<u8>> = None;
    let mut mldsa:    Option<Vec<u8>> = None;

    for _ in 0..entry_count {
        if pos + 3 > data.len() {
            return Err(LithiumError::invalid_credentials("server_identity_truncated"));
        }
        let tag_len = data[pos] as usize;
        pos += 1;

        if pos + tag_len + 2 > data.len() {
            return Err(LithiumError::invalid_credentials("server_identity_truncated"));
        }
        let tag = std::str::from_utf8(&data[pos..pos + tag_len])
            .map_err(|_| LithiumError::invalid_credentials("server_identity_bad_tag"))?;
        pos += tag_len;

        let data_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        if pos + data_len > data.len() {
            return Err(LithiumError::invalid_credentials("server_identity_truncated"));
        }
        let key = data[pos..pos + data_len].to_vec();
        pos += data_len;

        match tag {
            "x25519"    => x25519  = Some(key),
            "ed25519"   => ed25519 = Some(key),
            "mlkem1024" => mlkem   = Some(key),
            "mldsa87"   => mldsa   = Some(key),
            _           => {}   // forward-compatible: ignore unknown tags
        }
    }

    let x25519  = x25519 .ok_or_else(|| LithiumError::invalid_credentials("server_identity_missing_x25519"))?;
    let ed25519 = ed25519.ok_or_else(|| LithiumError::invalid_credentials("server_identity_missing_ed25519"))?;
    let mlkem   = mlkem  .ok_or_else(|| LithiumError::invalid_credentials("server_identity_missing_mlkem1024"))?;
    let mldsa   = mldsa  .ok_or_else(|| LithiumError::invalid_credentials("server_identity_missing_mldsa87"))?;

    Ok(ServerBootstrap {
        shake_pub_x:    Byte32::from_slice(&x25519) .map_err(|_| LithiumError::invalid_credentials("server_identity_bad_x25519"))?,
        shake_pub_k:    SecretBytes::new(mlkem),
        server_sig_ed:  Byte32::from_slice(&ed25519).map_err(|_| LithiumError::invalid_credentials("server_identity_bad_ed25519"))?,
        server_sig_dili: SecretBytes::new(mldsa),
    })
}