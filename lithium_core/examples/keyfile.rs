// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

//! At-rest key management lifecycle (Pillar 1): `KeyManager` generates and persists the hybrid
//! identity, then reloads it unchanged across a restart.
//!
//! Run with: `cargo run -p lithium_core --example keyfile`

use lithium_core::keys::{KeyManager, KeyStoreKind, PlainFileMkProvider};

fn main() -> lithium_core::Result<()> {
    let dir = std::env::temp_dir().join(format!("lithium_keyfile_example_{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok();

    // First run generates the X25519/Ed25519/ML-KEM/ML-DSA identity and seals each private key
    // under the master key held by the provider.
    let km = KeyManager::start(
        &dir,
        KeyStoreKind::User,
        PlainFileMkProvider::new(dir.join("mk")),
    )?;
    let first = km.public_keys().clone();

    // A fresh KeyManager over the same directory loads the identity back unchanged.
    let reopened = KeyManager::start(
        &dir,
        KeyStoreKind::User,
        PlainFileMkProvider::new(dir.join("mk")),
    )?;
    let again = reopened.public_keys();

    assert_eq!(first.ed25519.as_slice(), again.ed25519.as_slice());
    assert_eq!(first.x25519.as_slice(), again.x25519.as_slice());

    println!("identity persisted and stable across restart");

    std::fs::remove_dir_all(&dir).ok();
    Ok(())
}
