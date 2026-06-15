use std::{fs, io, path::Path};

use lithium_core::contract::identity_file::{encode, ServerIdentityKeys};
use lithium_core::keys::PublicKeys;

pub fn write_server_identity(path: &Path, keys: &PublicKeys) -> io::Result<()> {
    let bytes = encode(&ServerIdentityKeys {
        x25519: keys.x25519.as_slice().to_vec(),
        ed25519: keys.ed25519.as_slice().to_vec(),
        mlkem1024: keys.kyber.expose_as_slice().to_vec(),
        mldsa87: keys.dilithium.expose_as_slice().to_vec(),
    });
    fs::write(path, &bytes)
}
