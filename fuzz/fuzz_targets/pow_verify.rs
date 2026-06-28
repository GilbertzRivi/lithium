// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;
use lithium_core::pow;

fuzz_target!(|data: &[u8]| {
    if data.len() < 9 {
        return;
    }
    let nonce = u64::from_le_bytes(data[..8].try_into().unwrap());
    let bits = data[8] as u32;
    let _ = pow::verify(&data[9..], nonce, bits);
});
