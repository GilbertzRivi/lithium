use serde::Serialize;

use lithium_core::{
    crypto::keys,
    error::{LithiumError, Result},
    secrets::{Byte32, SecretJson, SecretString},
    secrets::bytes::SecretBytes,
};

const INV_MAGIC: &[u8; 4] = b"LCI1";
const INV_VER: u8 = 2;

#[derive(Clone)]
pub struct InvitePublic {
    pub server: SecretString,
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
    server: &'a str,
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

pub fn encode_invite_code(p: &InvitePublic) -> Result<SecretString> {
    let server_b = p.server.expose().as_bytes();
    if server_b.len() > u16::MAX as usize {
        return Err(LithiumError::invalid_len(u16::MAX as usize, server_b.len()));
    }

    let cid = SecretBytes::from_hex(p.cid_hex.expose().trim())?;
    let x_pub = Byte32::from_hex(p.x_pub_hex.expose().trim())?;
    let k_pub = SecretBytes::from_hex(p.k_pub_hex.expose().trim())?;
    let ed_pub = Byte32::from_hex(p.ed_pub_hex.expose().trim())?;
    let dili_pub = SecretBytes::from_hex(p.dili_pub_hex.expose().trim())?;

    let mbox_in_pub = Byte32::from_hex(p.mbox_in_pub_hex.expose().trim())?;
    let mbox_out_cur_pub = Byte32::from_hex(p.mbox_out_cur_pub_hex.expose().trim())?;
    let mbox_out_next_pub = Byte32::from_hex(p.mbox_out_next_pub_hex.expose().trim())?;

    if !(cid.len() == 16 || cid.len() == 32) {
        return Err(LithiumError::invalid_len(32, cid.len()));
    }
    if k_pub.len() > u16::MAX as usize || dili_pub.len() > u16::MAX as usize {
        return Err(LithiumError::internal());
    }

    let mut out = SecretBytes::new(Vec::with_capacity(
        4 + 1 + 2 + server_b.len()
            + 1 + cid.len()
            + 32
            + 2 + k_pub.len()
            + 32
            + 2 + dili_pub.len()
            + 32 + 32 + 32,
    ));

    out.as_mut_vec().extend_from_slice(INV_MAGIC);
    out.as_mut_vec().push(INV_VER);

    out.as_mut_vec()
        .extend_from_slice(&(server_b.len() as u16).to_be_bytes());
    out.as_mut_vec().extend_from_slice(server_b);

    out.as_mut_vec().push(cid.len() as u8);
    out.as_mut_vec().extend_from_slice(cid.as_slice());

    out.as_mut_vec().extend_from_slice(x_pub.as_slice());

    out.as_mut_vec()
        .extend_from_slice(&(k_pub.len() as u16).to_be_bytes());
    out.as_mut_vec().extend_from_slice(k_pub.as_slice());

    out.as_mut_vec().extend_from_slice(ed_pub.as_slice());

    out.as_mut_vec()
        .extend_from_slice(&(dili_pub.len() as u16).to_be_bytes());
    out.as_mut_vec().extend_from_slice(dili_pub.as_slice());

    out.as_mut_vec().extend_from_slice(mbox_in_pub.as_slice());
    out.as_mut_vec().extend_from_slice(mbox_out_cur_pub.as_slice());
    out.as_mut_vec().extend_from_slice(mbox_out_next_pub.as_slice());

    Ok(SecretString::new(format!("lci1:{}", hex::encode(out.as_slice()))))
}

pub fn decode_invite_code(code: &SecretString) -> Result<InvitePublic> {
    let s = code.expose().trim();
    let hex_part = s.strip_prefix("lci1:").unwrap_or(s);
    let blob = SecretBytes::from_hex(hex_part)?;
    let blob = blob.as_slice();

    if blob.len() < 4 + 1 + 2 + 1 + 32 + 2 + 32 + 2 {
        return Err(LithiumError::invalid_credentials("invalid_invite_code"));
    }
    if &blob[0..4] != INV_MAGIC {
        return Err(LithiumError::invalid_credentials("invalid_invite_code"));
    }

    let ver = blob[4];
    if ver != 1 && ver != 2 {
        return Err(LithiumError::invalid_credentials("invalid_invite_code"));
    }

    let mut i = 5;

    let server_len = u16::from_be_bytes([blob[i], blob[i + 1]]) as usize;
    i += 2;
    if blob.len() < i + server_len + 1 {
        return Err(LithiumError::invalid_credentials("invalid_invite_code"));
    }
    let server = String::from_utf8(blob[i..i + server_len].to_vec())
        .map_err(|e| LithiumError::invalid_credentials("invalid_invite_code").with_source(e))?;
    i += server_len;

    let cid_len = blob[i] as usize;
    i += 1;
    if !(cid_len == 16 || cid_len == 32) {
        return Err(LithiumError::invalid_credentials("invalid_invite_code"));
    }
    if blob.len() < i + cid_len + 32 {
        return Err(LithiumError::invalid_credentials("invalid_invite_code"));
    }
    let cid = &blob[i..i + cid_len];
    i += cid_len;

    let x_pub = &blob[i..i + 32];
    i += 32;

    if blob.len() < i + 2 {
        return Err(LithiumError::invalid_credentials("invalid_invite_code"));
    }
    let k_len = u16::from_be_bytes([blob[i], blob[i + 1]]) as usize;
    i += 2;
    if blob.len() < i + k_len + 32 + 2 {
        return Err(LithiumError::invalid_credentials("invalid_invite_code"));
    }
    let k_pub = &blob[i..i + k_len];
    i += k_len;

    let ed_pub = &blob[i..i + 32];
    i += 32;

    let dili_len = u16::from_be_bytes([blob[i], blob[i + 1]]) as usize;
    i += 2;
    if blob.len() < i + dili_len {
        return Err(LithiumError::invalid_credentials("invalid_invite_code"));
    }
    let dili_pub = &blob[i..i + dili_len];
    i += dili_len;

    let (mbox_in_pub, mbox_out_cur_pub, mbox_out_next_pub) = if ver >= 2 {
        if blob.len() < i + 32 + 32 + 32 {
            return Err(LithiumError::invalid_credentials("invalid_invite_code"));
        }
        let mbox_in_pub = &blob[i..i + 32];
        i += 32;
        let mbox_out_cur_pub = &blob[i..i + 32];
        i += 32;
        let mbox_out_next_pub = &blob[i..i + 32];

        (mbox_in_pub, mbox_out_cur_pub, mbox_out_next_pub)
    } else {
        (x_pub, x_pub, x_pub)
    };

    Ok(InvitePublic {
        server: SecretString::new(server),
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
    let b = SecretBytes::from_hex(s.expose().trim())?;
    if !(b.len() == 16 || b.len() == 32) {
        return Err(LithiumError::invalid_len(32, b.len()));
    }
    Ok(b.as_slice().to_vec())
}

pub fn gen_self_state(server: SecretString) -> Result<(Vec<u8>, SecretJson)> {
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
        server: server.expose(),
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
    serde_json::to_writer(buf.as_mut_vec(), &state).map_err(LithiumError::json_parse)?;
    let sj = SecretJson::from_bytes(buf.as_slice())?;

    Ok((cid.as_slice().to_vec(), sj))
}