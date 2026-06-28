// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use argon2::{Algorithm, Argon2, Params, Version};
use opaque_ke::{CipherSuite, Ristretto255, TripleDh};
use sha2::Sha512;

use crate::crypto::kdf::{ARGON2_M_COST, ARGON2_P_COST, ARGON2_T_COST};
use crate::error::{LithiumError, Result};

pub struct LithiumCipherSuite;

impl CipherSuite for LithiumCipherSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, Sha512>;
    type Ksf = Argon2<'static>;
}

pub type ClientRegistrationState = opaque_ke::ClientRegistration<LithiumCipherSuite>;
pub type ClientLoginState = opaque_ke::ClientLogin<LithiumCipherSuite>;

// OPAQUE stretches the OPRF output to the envelope hash length (64), so output_len
// must stay unset; the cost profile matches kdf::argon2id().
pub(crate) fn opaque_ksf() -> Result<Argon2<'static>> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, None)
        .map_err(|_| LithiumError::internal())?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}
