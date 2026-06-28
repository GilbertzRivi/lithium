// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = lithiums::fuzz_api::parse_u32_ascii(data);
    if !data.is_empty() {
        let block_size = (data[0] as usize % 64) + 1;
        let _ = lithiums::fuzz_api::pad_block(data, block_size);
    }
});
