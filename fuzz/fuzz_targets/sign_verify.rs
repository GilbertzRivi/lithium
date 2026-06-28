// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;
use lithium_core::crypto::sign;
use lithium_core::secrets::{bytes::SecretBytes, Byte32};

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    let ed_pub = Byte32::from_slice(&data[..32]).unwrap_or_else(|_| Byte32::new_zeroed());
    let (sig, msg) = if data.len() > 96 {
        (&data[32..96], &data[96..])
    } else {
        (&data[32..], &[][..])
    };

    let _ = sign::verify_signature(msg, sig, &ed_pub);
    let _ = sign::verify_signature_dili(msg, sig, &SecretBytes::from_slice(data));
});
