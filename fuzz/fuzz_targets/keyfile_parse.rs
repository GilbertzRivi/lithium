#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = lithium_core::keys::keyfile::parse_keyfile_fuzz(data);
});
