#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use lithium_core::crypto::keys;
use lithium_core::crypto::kyberbox::WirePayload;
use lithium_core::secrets::{bytes::SecretBytes, Byte32};

static KP: OnceLock<(Byte32, Byte32, SecretBytes)> = OnceLock::new();

fn kp() -> &'static (Byte32, Byte32, SecretBytes) {
    KP.get_or_init(|| {
        let (x_priv, x_pub) = keys::random_x25519_keypair().unwrap();
        let (k_priv, _) = keys::random_kyber_mlkem1024_keypair().unwrap();
        (x_priv, x_pub, k_priv)
    })
}

fuzz_target!(|data: &[u8]| {
    let (x_priv, peer_key_x, k_priv) = kp();
    let n = data.len();
    let (a, b) = (n / 3, 2 * n / 3);
    let wire = WirePayload {
        seed_enc: SecretBytes::from_slice(&data[..a]),
        enc_headers: SecretBytes::from_slice(&data[a..b]),
        enc_body: SecretBytes::from_slice(&data[b..]),
    };
    let _ = lithiums::fuzz_api::decode_inbound("fuzz", x_priv, peer_key_x, k_priv, wire);
});
