use std::path::Path;

use lithium_core::{
    contract::identity_file::decode,
    error::{LithiumError, Result},
    secrets::{bytes::SecretBytes, Byte32},
};

use crate::protocol_manager::ServerBootstrap;

/// The file is intentionally not read at daemon startup; call this only when a
/// server connection is first attempted.
pub fn load(path: &Path) -> Result<ServerBootstrap> {
    parse(&std::fs::read(path).map_err(LithiumError::io)?)
}

pub(crate) fn parse(data: &[u8]) -> Result<ServerBootstrap> {
    let keys = decode(data)?;
    Ok(ServerBootstrap {
        shake_pub_x: Byte32::from_slice(&keys.x25519)
            .map_err(|_| LithiumError::invalid_credentials("server_identity_bad_x25519"))?,
        shake_pub_k: SecretBytes::new(keys.mlkem1024),
        server_sig_ed: Byte32::from_slice(&keys.ed25519)
            .map_err(|_| LithiumError::invalid_credentials("server_identity_bad_ed25519"))?,
        server_sig_dili: SecretBytes::new(keys.mldsa87),
    })
}
