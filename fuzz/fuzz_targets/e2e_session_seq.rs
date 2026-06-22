#![no_main]

use libfuzzer_sys::fuzz_target;
use lithiumd::fuzz_api::{drive, FuzzOp};

fuzz_target!(|ops: Vec<FuzzOp>| {
    drive(&ops);
});
