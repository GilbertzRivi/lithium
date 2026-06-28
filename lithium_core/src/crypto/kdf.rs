// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::{
    error::{LithiumError, Result},
    secrets::Byte32,
    secrets::bytes::SecretBytes,
};

pub(crate) const ARGON2_M_COST: u32 = 64 * 1024;
pub(crate) const ARGON2_T_COST: u32 = 3;
pub(crate) const ARGON2_P_COST: u32 = 1;
pub(crate) const ARGON2_OUT_LEN: usize = 32;

pub fn derive32(
    input: &SecretBytes,
    salt: Option<&SecretBytes>,
    info: &SecretBytes,
) -> Result<Byte32> {
    let hk = Hkdf::<Sha256>::new(salt.map(|s| s.expose_as_slice()), input.expose_as_slice());
    let mut out = Byte32::new_zeroed();
    hk.expand(info.expose_as_slice(), out.as_mut_slice())?;
    Ok(out)
}

// Same params on both sides of a wrap, or it never decrypts.
pub fn argon2id() -> Result<Argon2<'static>> {
    let params = Params::new(
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(ARGON2_OUT_LEN),
    )
    .map_err(|_| LithiumError::internal())?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}
