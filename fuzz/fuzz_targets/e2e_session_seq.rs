// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;
use lithiumd::fuzz_api::{drive, FuzzOp};

fuzz_target!(|ops: Vec<FuzzOp>| {
    drive(&ops);
});
