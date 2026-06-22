#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    lithium_core::opaque::server::opaque_parse_fuzz(data);
});
