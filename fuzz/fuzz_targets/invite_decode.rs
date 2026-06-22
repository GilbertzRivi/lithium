#![no_main]

use libfuzzer_sys::fuzz_target;
use lithium_core::secrets::SecretString;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let code = SecretString::new(s.to_owned());
        let _ = lithiumd::fuzz_api::decode_invite_code(&code);
        let _ = lithiumd::fuzz_api::invite_commitment(&code);
    }
});
