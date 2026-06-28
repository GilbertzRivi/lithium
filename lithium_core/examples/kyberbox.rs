// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

//! Hybrid X25519 + ML-KEM-1024 authenticated encryption round-trip (Pillar 2).
//!
//! Run with: `cargo run -p lithium_core --example kyberbox`

use lithium_core::crypto::{keys, kyberbox};
use lithium_core::secrets::bytes::SecretBytes;

fn main() -> lithium_core::Result<()> {
    // Caller-chosen domain separation; binds the ciphertext to one usage.
    let ctx = "myapp/message/v1";

    // Recipient advertises both a classical and a post-quantum public key.
    let (recipient_priv_x, recipient_pub_x) = keys::random_x25519_keypair()?;
    let (recipient_kyber_priv, recipient_kyber_pub) = keys::random_kyber_mlkem1024_keypair()?;

    // Sender draws a fresh ephemeral X25519 keypair per message.
    let (sender_priv_x, sender_pub_x) = keys::random_x25519_keypair()?;

    let body = SecretBytes::from_slice(b"attack at dawn");
    let headers = SecretBytes::from_slice(b"to: alice");

    let wire = kyberbox::encrypt(
        ctx,
        &sender_priv_x,
        &recipient_pub_x,
        &recipient_kyber_pub,
        &body,
        &headers,
    )?;

    let (plain_body, plain_headers) = kyberbox::decrypt(
        ctx,
        &recipient_priv_x,
        &sender_pub_x,
        &recipient_kyber_priv,
        &wire,
    )?;

    assert_eq!(plain_body.expose_as_slice(), body.expose_as_slice());
    assert_eq!(plain_headers.expose_as_slice(), headers.expose_as_slice());

    println!(
        "kyberbox round-trip ok ({} sealed body bytes)",
        wire.enc_body.expose_as_slice().len()
    );
    Ok(())
}
