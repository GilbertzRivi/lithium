#![no_main]

use libfuzzer_sys::fuzz_target;
use lithium_core::crypto::aead;
use lithium_core::secrets::{bytes::SecretBytes, Byte32};

fuzz_target!(|data: &[u8]| {
    let key = Byte32::new_zeroed();
    let aad = SecretBytes::new(b"fuzz-aad".to_vec());
    let blob = SecretBytes::from_slice(data);
    let _ = aead::decrypt(&blob, &key, &aad);
});
