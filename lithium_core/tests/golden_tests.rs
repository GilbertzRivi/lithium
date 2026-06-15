use std::collections::HashMap;

use lithium_core::crypto::kyberbox::WirePayload;
use lithium_core::crypto::{aead, kyberbox, sign};
use lithium_core::secrets::{Byte32, SecretBytes};

#[test]
fn aead_blob_decrypts_to_pinned_plaintext() {
    let key = Byte32::from_hex("9f2c1b8a4d6e0f3a57c9e1d2b40a8f6e7c5d3b1a09f8e7d6c5b4a39281706152").unwrap();
    let aad = SecretBytes::from_slice(b"golden-aad-v1");
    let blob = SecretBytes::from_hex(
        "01a14b7e02c9d3f5081623ab9cf124d1138aab1944639ca1eae2f7c84bb0709ee5c22d2d4ccfba979e3e91a7eb2507a6604e1a5da8",
    )
    .unwrap();

    let pt = aead::decrypt(&blob, &key, &aad).unwrap();
    assert_eq!(pt.expose_as_slice(), b"golden-aead-plaintext-v1");

    let mut tampered = blob.expose_as_slice().to_vec();
    *tampered.last_mut().unwrap() ^= 0x01;
    assert!(aead::decrypt(&SecretBytes::new(tampered), &key, &aad).is_err());
}

#[test]
fn kyberbox_wire_decrypts_to_pinned_plaintext() {
    let vectors: HashMap<&str, &str> = include_str!("testdata/kyberbox_golden_v1.txt")
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();

    let rx_x_priv = Byte32::from_hex(vectors["RX_X_PRIV"]).unwrap();
    let msg_x_pub = Byte32::from_hex(vectors["MSG_X_PUB"]).unwrap();
    let kyber_priv = SecretBytes::from_hex(vectors["KYBER_PRIV"]).unwrap();
    let wire = WirePayload {
        enc_body: SecretBytes::from_hex(vectors["ENC_BODY"]).unwrap(),
        enc_headers: SecretBytes::from_hex(vectors["ENC_HEADERS"]).unwrap(),
        seed_enc: SecretBytes::from_hex(vectors["SEED_ENC"]).unwrap(),
    };

    let (body, headers) =
        kyberbox::decrypt("golden/kyberbox/v1", &rx_x_priv, &msg_x_pub, &kyber_priv, &wire).unwrap();

    assert_eq!(body.expose_as_slice(), b"golden-body-v1");
    assert_eq!(headers.expose_as_slice(), b"golden-headers-v1");
}

#[test]
fn mldsa87_signature_verifies_pinned_vector() {
    let vectors: HashMap<&str, &str> = include_str!("testdata/mldsa87_verify_golden_v1.txt")
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();

    let dili_pub = SecretBytes::from_hex(vectors["DILI_PUB"]).unwrap();
    let dili_sig = SecretBytes::from_hex(vectors["DILI_SIG"]).unwrap();
    let msg = b"golden-mldsa87-v1";

    assert_eq!(dili_pub.expose_as_slice().len(), 2592);
    assert_eq!(dili_sig.expose_as_slice().len(), 4627);

    assert!(sign::verify_signature_dili(msg, dili_sig.expose_as_slice(), &dili_pub));
    assert!(!sign::verify_signature_dili(b"tampered", dili_sig.expose_as_slice(), &dili_pub));
}
