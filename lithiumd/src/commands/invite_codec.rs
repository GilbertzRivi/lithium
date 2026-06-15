use serde::Serialize;

use lithium_core::{
    crypto::keys,
    error::{LithiumError, Result},
    secrets::{Byte32, SecretJson, SecretString},
    secrets::bytes::SecretBytes,
};

use crate::labels::{INV_MAGIC, INV_VER};

const MLKEM1024_PUBLIC_KEY_LEN: usize = 1568;
const MLDSA87_PUBLIC_KEY_LEN: usize = 2592;

#[derive(Clone)]
pub struct InvitePublic {
    pub cid_hex: SecretString,
    pub x_pub_hex: SecretString,
    pub k_pub_hex: SecretString,
    pub ed_pub_hex: SecretString,
    pub dili_pub_hex: SecretString,

    pub mbox_in_pub_hex: SecretString,
    pub mbox_out_cur_pub_hex: SecretString,
    pub mbox_out_next_pub_hex: SecretString,
}

#[derive(Serialize)]
struct SelfStateSerde<'a> {
    v: u8,
    cid: &'a str,
    x_priv: &'a str,
    x_pub: &'a str,
    k_priv: &'a str,
    k_pub: &'a str,
    ed_priv: &'a str,
    ed_pub: &'a str,
    dili_priv: &'a str,
    dili_pub: &'a str,

    mbox_in_priv: &'a str,
    mbox_in_pub: &'a str,
    mbox_out_cur_priv: &'a str,
    mbox_out_cur_pub: &'a str,
    mbox_out_next_priv: &'a str,
    mbox_out_next_pub: &'a str,
}

#[inline]
fn invalid_invite_code() -> LithiumError {
    LithiumError::invalid_credentials("invalid_invite_code")
}

pub fn encode_invite_code(p: &InvitePublic) -> Result<SecretString> {
    let cid = Byte32::from_hex(p.cid_hex.expose().trim())?;
    let x_pub = Byte32::from_hex(p.x_pub_hex.expose().trim())?;
    let k_pub = SecretBytes::from_hex(p.k_pub_hex.expose().trim())?;
    let ed_pub = Byte32::from_hex(p.ed_pub_hex.expose().trim())?;
    let dili_pub = SecretBytes::from_hex(p.dili_pub_hex.expose().trim())?;

    let mbox_in_pub = Byte32::from_hex(p.mbox_in_pub_hex.expose().trim())?;
    let mbox_out_cur_pub = Byte32::from_hex(p.mbox_out_cur_pub_hex.expose().trim())?;
    let mbox_out_next_pub = Byte32::from_hex(p.mbox_out_next_pub_hex.expose().trim())?;

    if k_pub.len() != MLKEM1024_PUBLIC_KEY_LEN {
        return Err(invalid_invite_code());
    }
    if dili_pub.len() != MLDSA87_PUBLIC_KEY_LEN {
        return Err(invalid_invite_code());
    }

    let mut out = SecretBytes::new(Vec::with_capacity(
        4 + 1
            + 32
            + 32
            + 2 + k_pub.len()
            + 32
            + 2 + dili_pub.len()
            + 32 + 32 + 32,
    ));

    out.expose_as_mut_vec().extend_from_slice(INV_MAGIC);
    out.expose_as_mut_vec().push(INV_VER);

    out.expose_as_mut_vec().extend_from_slice(cid.as_slice());
    out.expose_as_mut_vec().extend_from_slice(x_pub.as_slice());

    out.expose_as_mut_vec()
        .extend_from_slice(&(k_pub.len() as u16).to_be_bytes());
    out.expose_as_mut_vec().extend_from_slice(k_pub.expose_as_slice());

    out.expose_as_mut_vec().extend_from_slice(ed_pub.as_slice());

    out.expose_as_mut_vec()
        .extend_from_slice(&(dili_pub.len() as u16).to_be_bytes());
    out.expose_as_mut_vec().extend_from_slice(dili_pub.expose_as_slice());

    out.expose_as_mut_vec().extend_from_slice(mbox_in_pub.as_slice());
    out.expose_as_mut_vec().extend_from_slice(mbox_out_cur_pub.as_slice());
    out.expose_as_mut_vec().extend_from_slice(mbox_out_next_pub.as_slice());

    Ok(SecretString::new(format!("lci1:{}", hex::encode(out.expose_as_slice()))))
}

pub fn decode_invite_code(code: &SecretString) -> Result<InvitePublic> {
    let s = code.expose().trim();
    let hex_part = s.strip_prefix("lci1:").unwrap_or(s);
    let blob = SecretBytes::from_hex(hex_part)?;
    let blob = blob.expose_as_slice();

    const MIN_INVITE_LEN: usize =
        4 + 1
            + 32
            + 32
            + 2 + MLKEM1024_PUBLIC_KEY_LEN
            + 32
            + 2 + MLDSA87_PUBLIC_KEY_LEN
            + 32 + 32 + 32;

    if blob.len() < MIN_INVITE_LEN {
        return Err(invalid_invite_code());
    }
    if &blob[0..4] != INV_MAGIC {
        return Err(invalid_invite_code());
    }
    if blob[4] != INV_VER {
        return Err(invalid_invite_code());
    }

    let mut i = 5;

    let cid = &blob[i..i + 32];
    i += 32;

    let x_pub = &blob[i..i + 32];
    i += 32;

    let k_len = u16::from_be_bytes([blob[i], blob[i + 1]]) as usize;
    i += 2;
    if k_len != MLKEM1024_PUBLIC_KEY_LEN {
        return Err(invalid_invite_code());
    }
    if blob.len() < i + k_len + 32 + 2 + MLDSA87_PUBLIC_KEY_LEN + 32 + 32 + 32 {
        return Err(invalid_invite_code());
    }
    let k_pub = &blob[i..i + k_len];
    i += k_len;

    let ed_pub = &blob[i..i + 32];
    i += 32;

    let dili_len = u16::from_be_bytes([blob[i], blob[i + 1]]) as usize;
    i += 2;
    if dili_len != MLDSA87_PUBLIC_KEY_LEN {
        return Err(invalid_invite_code());
    }
    if blob.len() < i + dili_len + 32 + 32 + 32 {
        return Err(invalid_invite_code());
    }
    let dili_pub = &blob[i..i + dili_len];
    i += dili_len;

    let mbox_in_pub = &blob[i..i + 32];
    i += 32;

    let mbox_out_cur_pub = &blob[i..i + 32];
    i += 32;

    let mbox_out_next_pub = &blob[i..i + 32];
    i += 32;

    if i != blob.len() {
        return Err(invalid_invite_code());
    }

    Ok(InvitePublic {
        cid_hex: SecretString::new(hex::encode(cid)),
        x_pub_hex: SecretString::new(hex::encode(x_pub)),
        k_pub_hex: SecretString::new(hex::encode(k_pub)),
        ed_pub_hex: SecretString::new(hex::encode(ed_pub)),
        dili_pub_hex: SecretString::new(hex::encode(dili_pub)),
        mbox_in_pub_hex: SecretString::new(hex::encode(mbox_in_pub)),
        mbox_out_cur_pub_hex: SecretString::new(hex::encode(mbox_out_cur_pub)),
        mbox_out_next_pub_hex: SecretString::new(hex::encode(mbox_out_next_pub)),
    })
}

pub fn decode_contact_id_hex(s: &SecretString) -> Result<Vec<u8>> {
    let b = Byte32::from_hex(s.expose().trim())?;
    Ok(b.as_slice().to_vec())
}

pub fn gen_self_state() -> Result<(Vec<u8>, SecretJson)> {
    let cid: Byte32 = keys::random_32()?;

    let (x_priv, x_pub) = keys::random_x25519_keypair()?;
    let (k_priv, k_pub) = keys::random_kyber_mlkem1024_keypair()?;
    let (ed_priv, ed_pub) = keys::random_ed25519_keypair()?;
    let (dili_priv, dili_pub) = keys::random_dilithium_mldsa87_keypair()?;

    let (mbox_in_priv, mbox_in_pub) = keys::random_x25519_keypair()?;
    let (mbox_out_cur_priv, mbox_out_cur_pub) = keys::random_x25519_keypair()?;
    let (mbox_out_next_priv, mbox_out_next_pub) = keys::random_x25519_keypair()?;

    let cid_hex = cid.to_hex();
    let x_priv_hex = x_priv.to_hex();
    let x_pub_hex = x_pub.to_hex();
    let k_priv_hex = k_priv.to_hex();
    let k_pub_hex = k_pub.to_hex();
    let ed_priv_hex = ed_priv.to_hex();
    let ed_pub_hex = ed_pub.to_hex();
    let dili_priv_hex = dili_priv.to_hex();
    let dili_pub_hex = dili_pub.to_hex();

    let mbox_in_priv_hex = mbox_in_priv.to_hex();
    let mbox_in_pub_hex = mbox_in_pub.to_hex();
    let mbox_out_cur_priv_hex = mbox_out_cur_priv.to_hex();
    let mbox_out_cur_pub_hex = mbox_out_cur_pub.to_hex();
    let mbox_out_next_priv_hex = mbox_out_next_priv.to_hex();
    let mbox_out_next_pub_hex = mbox_out_next_pub.to_hex();

    let state = SelfStateSerde {
        v: 1,
        cid: cid_hex.expose(),
        x_priv: x_priv_hex.expose(),
        x_pub: x_pub_hex.expose(),
        k_priv: k_priv_hex.expose(),
        k_pub: k_pub_hex.expose(),
        ed_priv: ed_priv_hex.expose(),
        ed_pub: ed_pub_hex.expose(),
        dili_priv: dili_priv_hex.expose(),
        dili_pub: dili_pub_hex.expose(),

        mbox_in_priv: mbox_in_priv_hex.expose(),
        mbox_in_pub: mbox_in_pub_hex.expose(),
        mbox_out_cur_priv: mbox_out_cur_priv_hex.expose(),
        mbox_out_cur_pub: mbox_out_cur_pub_hex.expose(),
        mbox_out_next_priv: mbox_out_next_priv_hex.expose(),
        mbox_out_next_pub: mbox_out_next_pub_hex.expose(),
    };

    let mut buf = SecretBytes::new(Vec::new());
    serde_json::to_writer(buf.expose_as_mut_vec(), &state).map_err(LithiumError::json_parse)?;
    let sj = SecretJson::from_bytes(buf.expose_as_slice())?;

    Ok((cid.as_slice().to_vec(), sj))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_fields as sf;
    use lithium_core::{crypto::keys, secrets::SecretString};

    fn hex32() -> SecretString {
        keys::random_32().unwrap().to_hex()
    }

    fn kyber_pk_hex() -> SecretString {
        let (_, pk) = keys::random_kyber_mlkem1024_keypair().unwrap();
        pk.to_hex()
    }

    fn dili_pk_hex() -> SecretString {
        let (_, pk) = keys::random_dilithium_mldsa87_keypair().unwrap();
        pk.to_hex()
    }

    fn make_invite() -> InvitePublic {
        InvitePublic {
            cid_hex: hex32(),
            x_pub_hex: hex32(),
            k_pub_hex: kyber_pk_hex(),
            ed_pub_hex: hex32(),
            dili_pub_hex: dili_pk_hex(),
            mbox_in_pub_hex: hex32(),
            mbox_out_cur_pub_hex: hex32(),
            mbox_out_next_pub_hex: hex32(),
        }
    }

    #[test]
    fn invite_encode_decode_roundtrip() {
        let orig = make_invite();
        let code = encode_invite_code(&orig).unwrap();
        let decoded = decode_invite_code(&code).unwrap();

        assert_eq!(decoded.cid_hex.expose(), orig.cid_hex.expose());
        assert_eq!(decoded.x_pub_hex.expose(), orig.x_pub_hex.expose());
        assert_eq!(decoded.k_pub_hex.expose(), orig.k_pub_hex.expose());
        assert_eq!(decoded.ed_pub_hex.expose(), orig.ed_pub_hex.expose());
        assert_eq!(decoded.dili_pub_hex.expose(), orig.dili_pub_hex.expose());
        assert_eq!(decoded.mbox_in_pub_hex.expose(), orig.mbox_in_pub_hex.expose());
        assert_eq!(decoded.mbox_out_cur_pub_hex.expose(), orig.mbox_out_cur_pub_hex.expose());
        assert_eq!(decoded.mbox_out_next_pub_hex.expose(), orig.mbox_out_next_pub_hex.expose());
    }

    #[test]
    fn invite_code_starts_with_lci1_prefix() {
        let code = encode_invite_code(&make_invite()).unwrap();
        assert!(code.expose().starts_with("lci1:"), "code must start with lci1:");
    }

    #[test]
    fn invite_decode_without_prefix_accepted() {
        let invite = make_invite();
        let code = encode_invite_code(&invite).unwrap();
        let hex_only = code.expose().strip_prefix("lci1:").unwrap().to_owned();
        let code_no_prefix = SecretString::new(hex_only);
        let decoded = decode_invite_code(&code_no_prefix).unwrap();
        assert_eq!(decoded.cid_hex.expose(), invite.cid_hex.expose());
    }

    #[test]
    fn invite_decode_with_whitespace_trimmed() {
        let code = encode_invite_code(&make_invite()).unwrap();
        let padded = SecretString::new(format!("  {}  ", code.expose()));
        assert!(decode_invite_code(&padded).is_ok());
    }

    #[test]
    fn invite_decode_empty_fails() {
        let err = decode_invite_code(&SecretString::new(String::new()));
        assert!(err.is_err());
    }

    #[test]
    fn invite_decode_truncated_fails() {
        let code = encode_invite_code(&make_invite()).unwrap();
        let short = &code.expose()["lci1:".len()..][..40];
        let s = SecretString::new(format!("lci1:{}", short));
        assert!(decode_invite_code(&s).is_err());
    }

    #[test]
    fn invite_decode_wrong_magic_fails() {
        let invite = make_invite();
        let code = encode_invite_code(&invite).unwrap();
        let hex_part = code.expose().strip_prefix("lci1:").unwrap();
        let mut bytes = hex::decode(hex_part).unwrap();
        bytes[0] = 0xFF;
        let bad = SecretString::new(format!("lci1:{}", hex::encode(&bytes)));
        assert!(decode_invite_code(&bad).is_err());
    }

    #[test]
    fn invite_decode_wrong_version_fails() {
        let invite = make_invite();
        let code = encode_invite_code(&invite).unwrap();
        let hex_part = code.expose().strip_prefix("lci1:").unwrap();
        let mut bytes = hex::decode(hex_part).unwrap();
        bytes[4] = bytes[4].wrapping_add(1);
        let bad = SecretString::new(format!("lci1:{}", hex::encode(&bytes)));
        assert!(decode_invite_code(&bad).is_err());
    }

    #[test]
    fn invite_decode_trailing_bytes_fails() {
        let invite = make_invite();
        let code = encode_invite_code(&invite).unwrap();
        let hex_part = code.expose().strip_prefix("lci1:").unwrap();
        let mut bytes = hex::decode(hex_part).unwrap();
        bytes.push(0xAA);
        let bad = SecretString::new(format!("lci1:{}", hex::encode(&bytes)));
        assert!(decode_invite_code(&bad).is_err());
    }

    #[test]
    fn gen_self_state_returns_32_byte_cid() {
        let (cid, _sj) = gen_self_state().unwrap();
        assert_eq!(cid.len(), 32);
    }

    #[test]
    fn gen_self_state_has_all_required_fields() {
        let (_cid, sj) = gen_self_state().unwrap();
        for field in &[
            sf::CID, sf::X_PRIV, sf::X_PUB, sf::K_PRIV, sf::K_PUB,
            sf::ED_PRIV, sf::ED_PUB, sf::DILI_PRIV, sf::DILI_PUB,
            sf::MBOX_IN_PRIV, sf::MBOX_IN_PUB,
            sf::MBOX_OUT_CUR_PRIV, sf::MBOX_OUT_CUR_PUB,
            sf::MBOX_OUT_NEXT_PRIV, sf::MBOX_OUT_NEXT_PUB,
        ] {
            sj.get_string(field).unwrap_or_else(|_| panic!("missing field: {field}"));
        }
    }

    #[test]
    fn gen_self_state_unique_cids() {
        let (cid1, _) = gen_self_state().unwrap();
        let (cid2, _) = gen_self_state().unwrap();
        assert_ne!(cid1, cid2);
    }

    #[test]
    fn gen_self_state_can_encode_as_invite() {
        let (_cid, sj) = gen_self_state().unwrap();
        let invite = InvitePublic {
            cid_hex:              sj.get_string(sf::CID).unwrap(),
            x_pub_hex:            sj.get_string(sf::X_PUB).unwrap(),
            k_pub_hex:            sj.get_string(sf::K_PUB).unwrap(),
            ed_pub_hex:           sj.get_string(sf::ED_PUB).unwrap(),
            dili_pub_hex:         sj.get_string(sf::DILI_PUB).unwrap(),
            mbox_in_pub_hex:      sj.get_string(sf::MBOX_IN_PUB).unwrap(),
            mbox_out_cur_pub_hex: sj.get_string(sf::MBOX_OUT_CUR_PUB).unwrap(),
            mbox_out_next_pub_hex: sj.get_string(sf::MBOX_OUT_NEXT_PUB).unwrap(),
        };
        let code = encode_invite_code(&invite).unwrap();
        let decoded = decode_invite_code(&code).unwrap();
        assert_eq!(decoded.cid_hex.expose(), invite.cid_hex.expose());
    }

    #[test]
    fn decode_contact_id_hex_valid() {
        let hex = SecretString::new("aa".repeat(32));
        let id = decode_contact_id_hex(&hex).unwrap();
        assert_eq!(id, vec![0xAAu8; 32]);
    }

    #[test]
    fn decode_contact_id_hex_wrong_length_fails() {
        let hex = SecretString::new("deadbeef".to_owned());
        assert!(decode_contact_id_hex(&hex).is_err());
    }

    #[test]
    fn decode_contact_id_hex_invalid_chars_fails() {
        let hex = SecretString::new("zz".repeat(32));
        assert!(decode_contact_id_hex(&hex).is_err());
    }

    #[test]
    fn invite_code_layout_is_pinned() {
        let invite = InvitePublic {
            cid_hex: SecretString::new("aa".repeat(32)),
            x_pub_hex: SecretString::new("bb".repeat(32)),
            k_pub_hex: SecretString::new("cc".repeat(MLKEM1024_PUBLIC_KEY_LEN)),
            ed_pub_hex: SecretString::new("dd".repeat(32)),
            dili_pub_hex: SecretString::new("ee".repeat(MLDSA87_PUBLIC_KEY_LEN)),
            mbox_in_pub_hex: SecretString::new("11".repeat(32)),
            mbox_out_cur_pub_hex: SecretString::new("22".repeat(32)),
            mbox_out_next_pub_hex: SecretString::new("33".repeat(32)),
        };

        let code = encode_invite_code(&invite).unwrap();
        let expected = format!(
            "lci1:4c43493101{}{}0620{}{}0a20{}{}{}{}",
            "aa".repeat(32),
            "bb".repeat(32),
            "cc".repeat(MLKEM1024_PUBLIC_KEY_LEN),
            "dd".repeat(32),
            "ee".repeat(MLDSA87_PUBLIC_KEY_LEN),
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
        );
        assert_eq!(code.expose(), expected);

        let decoded = decode_invite_code(&code).unwrap();
        assert_eq!(decoded.cid_hex.expose(), invite.cid_hex.expose());
        assert_eq!(decoded.k_pub_hex.expose(), invite.k_pub_hex.expose());
        assert_eq!(decoded.dili_pub_hex.expose(), invite.dili_pub_hex.expose());
        assert_eq!(decoded.mbox_out_next_pub_hex.expose(), invite.mbox_out_next_pub_hex.expose());
    }
}
