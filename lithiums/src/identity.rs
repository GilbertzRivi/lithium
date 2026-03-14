use std::{fs, io, path::Path};

use lithium_core::keys::PublicKeys;

/// Magic bytes identifying a Lithium server identity file.
const MAGIC: &[u8; 8] = b"LITHIUPK";
/// Format version.
const VERSION: u8 = 0x01;

/// Write a `server.identity` file containing the server's four public keys in a
/// self-describing binary format:
///
/// ```text
/// [0..8]   magic:         b"LITHIUPK"
/// [8]      version:       0x01
/// [9]      entry_count:   4
/// [10..]   entries, each: [1 byte tag_len][tag_len bytes ASCII tag]
///                         [2 bytes LE data_len][data_len bytes key]
/// ```
///
/// Tags: `x25519`, `ed25519`, `mlkem1024`, `mldsa87`.
pub fn write_server_identity(path: &Path, keys: &PublicKeys) -> io::Result<()> {
    let mut buf = Vec::with_capacity(4400);

    buf.extend_from_slice(MAGIC);
    buf.push(VERSION);
    buf.push(4u8);

    append_entry(&mut buf, "x25519",    keys.x25519.as_slice());
    append_entry(&mut buf, "ed25519",   keys.ed25519.as_slice());
    append_entry(&mut buf, "mlkem1024", keys.kyber.expose_as_slice());
    append_entry(&mut buf, "mldsa87",   keys.dilithium.expose_as_slice());

    fs::write(path, &buf)
}

fn append_entry(buf: &mut Vec<u8>, tag: &str, data: &[u8]) {
    debug_assert!(tag.len() <= u8::MAX as usize);
    debug_assert!(data.len() <= u16::MAX as usize);
    buf.push(tag.len() as u8);
    buf.extend_from_slice(tag.as_bytes());
    buf.extend_from_slice(&(data.len() as u16).to_le_bytes());
    buf.extend_from_slice(data);
}