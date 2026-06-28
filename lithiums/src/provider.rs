// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::{
    error::Result,
    keys::{MkProvider, PlainFileMkProvider},
    secrets::Byte32,
};

#[cfg(feature = "tpm")]
use crate::tpm_provider::TpmMkProvider;

pub enum ServerMkProvider {
    #[cfg(feature = "tpm")]
    Tpm(TpmMkProvider),
    Plain(PlainFileMkProvider),
}

impl MkProvider for ServerMkProvider {
    fn load_mk(&self) -> Result<Byte32> {
        match self {
            #[cfg(feature = "tpm")]
            Self::Tpm(p) => p.load_mk(),
            Self::Plain(p) => p.load_mk(),
        }
    }

    fn store_mk(&self, mk: &Byte32) -> Result<()> {
        match self {
            #[cfg(feature = "tpm")]
            Self::Tpm(p) => p.store_mk(mk),
            Self::Plain(p) => p.store_mk(mk),
        }
    }
}
