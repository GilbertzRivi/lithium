// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::crypto::kyberbox::WirePayload;
use lithium_core::secrets::bytes::SecretBytes;
use lithium_core::secrets::{Byte32, SecretJson};

use crate::error::AppError;

pub fn decode_inbound(
    req_label: &str,
    x_priv: &Byte32,
    peer_key_x: &Byte32,
    k_priv: &SecretBytes,
    wire: WirePayload,
) -> Result<(SecretJson, SecretJson), AppError> {
    crate::transport::decode_inbound(req_label, x_priv, peer_key_x, k_priv, wire)
}

pub fn parse_u32_ascii(raw: &[u8]) -> u32 {
    crate::transport::parse_u32_ascii(raw)
}

pub fn pad_block(input: &[u8], block_size: usize) -> SecretBytes {
    crate::transport::pad_block(input, block_size)
}
