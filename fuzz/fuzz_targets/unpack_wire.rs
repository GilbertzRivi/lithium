#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = lithiumd::fuzz_api::unpack_wire(data);
});
