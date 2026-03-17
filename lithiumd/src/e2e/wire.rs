use lithium_core::{
    error::{LithiumError, Result},
    secrets::SecretJson,
};
use serde_json::{Map, Value};

pub(crate) const MAGIC: &[u8; 3] = b"LM1";
pub(crate) const VER: u8 = 1;

pub(crate) const E2E_LABEL: &str = "lithiumd/e2e-msg/v1";
pub(crate) const E2E_SIG_LABEL: &[u8] = b"lithiumd/e2e-msg-sig/v1";

// How many old receive-key slots to keep for out-of-order delivery.
pub const DEFAULT_WINDOW: u64 = 32;

// How many remote prekeys to keep per peer.
pub const PREKEY_TARGET: usize = 5;

pub(crate) fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub(crate) fn drop_removed_json_key(map: &mut Map<String, Value>, key: &str) {
    if let Some(removed) = map.remove(key) {
        drop(SecretJson::from(removed));
    }
}

/// Binary framing for an E2E message on the wire (LM1 v1 format).
///
/// ```text
/// [LM1:3][VER:1][to_id:32][from_x_pub:32]
/// [seed_len:u16][seed]
/// [hdr_len:u32][enc_headers]
/// [body_len:u32][enc_body]
/// ```
#[derive(Clone)]
pub struct WireV1 {
    pub to_id: [u8; 32],
    pub from_x_pub: [u8; 32],
    pub seed: Vec<u8>,
    pub enc_headers: Vec<u8>,
    pub enc_body: Vec<u8>,
}

pub fn pack_wire(w: &WireV1) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        3 + 1 + 32 + 32 + 2 + w.seed.len() + 4 + w.enc_headers.len() + 4 + w.enc_body.len(),
    );
    out.extend_from_slice(MAGIC);
    out.push(VER);
    out.extend_from_slice(&w.to_id);
    out.extend_from_slice(&w.from_x_pub);

    out.extend_from_slice(&(w.seed.len() as u16).to_be_bytes());
    out.extend_from_slice(&w.seed);

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
    if &b[..3] != MAGIC || b[3] != VER {
        return Err(LithiumError::invalid_credentials("bad_wire"));
    }

    let mut i = 4;

    let to_id_b = take_bytes(b, &mut i, 32)?;
    let mut to_id = [0u8; 32];
    to_id.copy_from_slice(to_id_b);

    let from_x_b = take_bytes(b, &mut i, 32)?;
    let mut from_x_pub = [0u8; 32];
    from_x_pub.copy_from_slice(from_x_b);

    let seed_len = read_u16_be(b, &mut i)?;
    let seed = take_bytes(b, &mut i, seed_len)?.to_vec();

    let hdr_len = read_u32_be(b, &mut i)?;
    let enc_headers = take_bytes(b, &mut i, hdr_len)?.to_vec();

    let body_len = read_u32_be(b, &mut i)?;
    let enc_body = take_bytes(b, &mut i, body_len)?.to_vec();

    Ok(WireV1 { to_id, from_x_pub, seed, enc_headers, enc_body })
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
            seed: vec![0x11u8; 64],
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
        assert_eq!(decoded.seed, orig.seed);
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
            seed: vec![],
            enc_headers: vec![],
            enc_body: vec![],
        };
        let packed = pack_wire(&empty);
        let decoded = unpack_wire(&packed).unwrap();
        assert!(decoded.seed.is_empty());
        assert!(decoded.enc_headers.is_empty());
        assert!(decoded.enc_body.is_empty());
    }
}