// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::error::{LithiumError, Result};

const MAGIC: &[u8; 8] = b"LITHIUPK";
const VERSION: u8 = 0x01;

const TAG_X25519: &str = "x25519";
const TAG_ED25519: &str = "ed25519";
const TAG_MLKEM1024: &str = "mlkem1024";
const TAG_MLDSA87: &str = "mldsa87";

const LEN_X25519: usize = 32;
const LEN_ED25519: usize = 32;
const LEN_MLKEM1024: usize = 1568;
const LEN_MLDSA87: usize = 2592;

pub struct ServerIdentityKeys {
    pub x25519: Vec<u8>,
    pub ed25519: Vec<u8>,
    pub mlkem1024: Vec<u8>,
    pub mldsa87: Vec<u8>,
}

pub fn encode(keys: &ServerIdentityKeys) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4400);
    buf.extend_from_slice(MAGIC);
    buf.push(VERSION);
    buf.push(4u8);

    append_entry(&mut buf, TAG_X25519, &keys.x25519);
    append_entry(&mut buf, TAG_ED25519, &keys.ed25519);
    append_entry(&mut buf, TAG_MLKEM1024, &keys.mlkem1024);
    append_entry(&mut buf, TAG_MLDSA87, &keys.mldsa87);

    buf
}

fn append_entry(buf: &mut Vec<u8>, tag: &str, data: &[u8]) {
    debug_assert!(tag.len() <= u8::MAX as usize);
    debug_assert!(data.len() <= u16::MAX as usize);
    buf.push(tag.len() as u8);
    buf.extend_from_slice(tag.as_bytes());
    buf.extend_from_slice(&(data.len() as u16).to_le_bytes());
    buf.extend_from_slice(data);
}

pub fn decode(data: &[u8]) -> Result<ServerIdentityKeys> {
    if data.len() < 10 || &data[0..8] != MAGIC {
        return Err(LithiumError::invalid_credentials(
            "server_identity_bad_magic",
        ));
    }
    if data[8] != VERSION {
        return Err(LithiumError::invalid_credentials(
            "server_identity_unknown_version",
        ));
    }

    let entry_count = data[9] as usize;
    let mut pos = 10;

    let mut x25519: Option<Vec<u8>> = None;
    let mut ed25519: Option<Vec<u8>> = None;
    let mut mlkem: Option<Vec<u8>> = None;
    let mut mldsa: Option<Vec<u8>> = None;

    for _ in 0..entry_count {
        if pos + 3 > data.len() {
            return Err(LithiumError::invalid_credentials(
                "server_identity_truncated",
            ));
        }
        let tag_len = data[pos] as usize;
        pos += 1;

        if pos + tag_len + 2 > data.len() {
            return Err(LithiumError::invalid_credentials(
                "server_identity_truncated",
            ));
        }
        let tag = std::str::from_utf8(&data[pos..pos + tag_len])
            .map_err(|_| LithiumError::invalid_credentials("server_identity_bad_tag"))?;
        pos += tag_len;

        let data_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        if pos + data_len > data.len() {
            return Err(LithiumError::invalid_credentials(
                "server_identity_truncated",
            ));
        }
        let key = data[pos..pos + data_len].to_vec();
        pos += data_len;

        match tag {
            TAG_X25519 => x25519 = Some(key),
            TAG_ED25519 => ed25519 = Some(key),
            TAG_MLKEM1024 => mlkem = Some(key),
            TAG_MLDSA87 => mldsa = Some(key),
            _ => {}
        }
    }

    let x25519 = x25519
        .ok_or_else(|| LithiumError::invalid_credentials("server_identity_missing_x25519"))?;
    let ed25519 = ed25519
        .ok_or_else(|| LithiumError::invalid_credentials("server_identity_missing_ed25519"))?;
    let mlkem1024 = mlkem
        .ok_or_else(|| LithiumError::invalid_credentials("server_identity_missing_mlkem1024"))?;
    let mldsa87 = mldsa
        .ok_or_else(|| LithiumError::invalid_credentials("server_identity_missing_mldsa87"))?;

    check_len(x25519.len(), LEN_X25519)?;
    check_len(ed25519.len(), LEN_ED25519)?;
    check_len(mlkem1024.len(), LEN_MLKEM1024)?;
    check_len(mldsa87.len(), LEN_MLDSA87)?;

    Ok(ServerIdentityKeys {
        x25519,
        ed25519,
        mlkem1024,
        mldsa87,
    })
}

fn check_len(got: usize, expected: usize) -> Result<()> {
    if got != expected {
        return Err(LithiumError::invalid_credentials(
            "server_identity_bad_key_len",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ServerIdentityKeys {
        ServerIdentityKeys {
            x25519: vec![0x11; 32],
            ed25519: vec![0x22; 32],
            mlkem1024: vec![0x33; 1568],
            mldsa87: vec![0x44; 2592],
        }
    }

    #[test]
    fn identity_file_layout_is_pinned() {
        let encoded = encode(&sample());

        assert_eq!(&encoded[0..8], MAGIC);
        assert_eq!(encoded[8], VERSION);
        assert_eq!(encoded[9], 4);
        assert_eq!(encoded[10], 6);
        assert_eq!(&encoded[11..17], TAG_X25519.as_bytes());
        assert_eq!(&encoded[17..19], &32u16.to_le_bytes());
        assert_eq!(&encoded[19..51], &[0x11u8; 32]);
        let overhead = (3 + 6) + (3 + 7) + (3 + 9) + (3 + 7);
        assert_eq!(encoded.len(), 10 + overhead + 32 + 32 + 1568 + 2592);

        let back = decode(&encoded).unwrap();
        assert_eq!(back.x25519, sample().x25519);
        assert_eq!(back.ed25519, sample().ed25519);
        assert_eq!(back.mlkem1024, sample().mlkem1024);
        assert_eq!(back.mldsa87, sample().mldsa87);
    }

    #[test]
    fn unknown_tags_are_ignored() {
        let mut buf = encode(&sample());
        buf[9] = 5;
        append_entry(&mut buf, "future", &[0xFF; 4]);
        assert!(decode(&buf).is_ok());
    }

    #[test]
    fn bad_magic_rejected() {
        let mut buf = encode(&sample());
        buf[0] = 0xFF;
        assert!(decode(&buf).is_err());
    }

    #[test]
    fn truncated_rejected() {
        let buf = encode(&sample());
        assert!(decode(&buf[..buf.len() - 1]).is_err());
    }

    #[test]
    fn wrong_key_length_rejected() {
        let mut keys = sample();
        keys.x25519 = vec![0x11; 31];
        assert!(decode(&encode(&keys)).is_err());
    }
}
