// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use lithium_core::error::{LithiumError, Result};

use crate::labels::{E2E_WIRE_MAGIC, E2E_WIRE_VER};

pub const DEFAULT_WINDOW: u64 = 32;

pub const PREKEY_TARGET: usize = 5;

pub(crate) fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Clone)]
pub struct WireV1 {
    pub to_id: [u8; 32],
    pub from_x_pub: [u8; 32],
    pub kem_ct: Vec<u8>,
    pub enc_headers: Vec<u8>,
    pub enc_body: Vec<u8>,
}

pub fn pack_wire(w: &WireV1) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        3 + 1 + 32 + 32 + 2 + w.kem_ct.len() + 4 + w.enc_headers.len() + 4 + w.enc_body.len(),
    );
    out.extend_from_slice(E2E_WIRE_MAGIC);
    out.push(E2E_WIRE_VER);
    out.extend_from_slice(&w.to_id);
    out.extend_from_slice(&w.from_x_pub);

    out.extend_from_slice(&(w.kem_ct.len() as u16).to_be_bytes());
    out.extend_from_slice(&w.kem_ct);

    out.extend_from_slice(&(w.enc_headers.len() as u32).to_be_bytes());
    out.extend_from_slice(&w.enc_headers);

    out.extend_from_slice(&(w.enc_body.len() as u32).to_be_bytes());
    out.extend_from_slice(&w.enc_body);

    out
}

pub fn unpack_wire(b: &[u8]) -> Result<WireV1> {
    if b.len() < 3 + 1 + 32 + 32 + 2 + 4 + 4 {
        return Err(LithiumError::invalid_credentials("bad_wire"));
    }
    if &b[..3] != E2E_WIRE_MAGIC || b[3] != E2E_WIRE_VER {
        return Err(LithiumError::invalid_credentials("bad_wire"));
    }

    let mut i = 4;

    let to_id_b = take_bytes(b, &mut i, 32)?;
    let mut to_id = [0u8; 32];
    to_id.copy_from_slice(to_id_b);

    let from_x_b = take_bytes(b, &mut i, 32)?;
    let mut from_x_pub = [0u8; 32];
    from_x_pub.copy_from_slice(from_x_b);

    let kem_ct_len = read_u16_be(b, &mut i)?;
    let kem_ct = take_bytes(b, &mut i, kem_ct_len)?.to_vec();

    let hdr_len = read_u32_be(b, &mut i)?;
    let enc_headers = take_bytes(b, &mut i, hdr_len)?.to_vec();

    let body_len = read_u32_be(b, &mut i)?;
    let enc_body = take_bytes(b, &mut i, body_len)?.to_vec();

    Ok(WireV1 {
        to_id,
        from_x_pub,
        kem_ct,
        enc_headers,
        enc_body,
    })
}

fn read_u16_be(b: &[u8], i: &mut usize) -> Result<usize> {
    if *i + 2 > b.len() {
        return Err(LithiumError::invalid_credentials("bad_wire"));
    }
    let v = u16::from_be_bytes([b[*i], b[*i + 1]]) as usize;
    *i += 2;
    Ok(v)
}

fn read_u32_be(b: &[u8], i: &mut usize) -> Result<usize> {
    if *i + 4 > b.len() {
        return Err(LithiumError::invalid_credentials("bad_wire"));
    }
    let v = u32::from_be_bytes([b[*i], b[*i + 1], b[*i + 2], b[*i + 3]]) as usize;
    *i += 4;
    Ok(v)
}

fn take_bytes<'a>(b: &'a [u8], i: &mut usize, n: usize) -> Result<&'a [u8]> {
    if *i + n > b.len() {
        return Err(LithiumError::invalid_credentials("bad_wire"));
    }
    let out = &b[*i..*i + n];
    *i += n;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire_fixture() -> WireV1 {
        WireV1 {
            to_id: [0xBBu8; 32],
            from_x_pub: [0xCCu8; 32],
            kem_ct: vec![0x11u8; 64],
            enc_headers: vec![0x22u8; 128],
            enc_body: vec![0x33u8; 256],
        }
    }

    #[test]
    fn wire_pack_unpack_roundtrip() {
        let orig = wire_fixture();
        let packed = pack_wire(&orig);
        let decoded = unpack_wire(&packed).unwrap();

        assert_eq!(decoded.to_id, orig.to_id);
        assert_eq!(decoded.from_x_pub, orig.from_x_pub);
        assert_eq!(decoded.kem_ct, orig.kem_ct);
        assert_eq!(decoded.enc_headers, orig.enc_headers);
        assert_eq!(decoded.enc_body, orig.enc_body);
    }

    #[test]
    fn wire_packed_starts_with_magic_and_version() {
        let packed = pack_wire(&wire_fixture());
        assert_eq!(&packed[..3], b"LM1");
        assert_eq!(packed[3], 1u8);
    }

    #[test]
    fn wire_unpack_wrong_magic_fails() {
        let mut packed = pack_wire(&wire_fixture());
        packed[0] = 0xFF;
        assert!(unpack_wire(&packed).is_err());
    }

    #[test]
    fn wire_unpack_wrong_version_fails() {
        let mut packed = pack_wire(&wire_fixture());
        packed[3] = 99;
        assert!(unpack_wire(&packed).is_err());
    }

    #[test]
    fn wire_unpack_truncated_fails() {
        let packed = pack_wire(&wire_fixture());
        assert!(unpack_wire(&packed[..10]).is_err());
    }

    #[test]
    fn wire_unpack_empty_fields_roundtrip() {
        let empty = WireV1 {
            to_id: [0u8; 32],
            from_x_pub: [0u8; 32],
            kem_ct: vec![],
            enc_headers: vec![],
            enc_body: vec![],
        };
        let packed = pack_wire(&empty);
        let decoded = unpack_wire(&packed).unwrap();
        assert!(decoded.kem_ct.is_empty());
        assert!(decoded.enc_headers.is_empty());
        assert!(decoded.enc_body.is_empty());
    }

    #[test]
    fn wire_packed_layout_is_pinned() {
        let packed = pack_wire(&wire_fixture());
        let expected = format!(
            "4c4d3101{}{}0040{}00000080{}00000100{}",
            "bb".repeat(32),
            "cc".repeat(32),
            "11".repeat(64),
            "22".repeat(128),
            "33".repeat(256),
        );
        assert_eq!(hex::encode(&packed), expected);

        let decoded = unpack_wire(&packed).unwrap();
        assert_eq!(decoded.kem_ct.len(), 64);
        assert_eq!(decoded.enc_headers.len(), 128);
        assert_eq!(decoded.enc_body.len(), 256);
    }
}
