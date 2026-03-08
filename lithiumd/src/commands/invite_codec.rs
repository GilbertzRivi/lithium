use serde_json::json;
// commands/invite_codec.rs
use lithium_core::{
    error::{LithiumError, Result},
    secrets::SecretString,
};
use lithium_core::crypto::keys;
use lithium_core::secrets::{Byte32, SecretJson};

const INV_MAGIC: &[u8; 4] = b"LCI1";
const INV_VER: u8 = 1;

#[derive(Clone)]
pub struct InvitePublic {
    pub server: SecretString,
    pub cid_hex: SecretString,
    pub x_pub_hex: SecretString,
    pub k_pub_hex: SecretString,
    pub ed_pub_hex: SecretString,
    pub dili_pub_hex: SecretString,
}

pub fn encode_invite_code(p: &InvitePublic) -> Result<SecretString> {
    let server_b = p.server.expose().as_bytes();
    if server_b.len() > u16::MAX as usize {
        return Err(LithiumError::invalid_len(u16::MAX as usize, server_b.len()));
    }

    let cid = hex::decode(p.cid_hex.expose().trim()).map_err(LithiumError::invalid_hex)?;
    let x_pub = hex::decode(p.x_pub_hex.expose().trim()).map_err(LithiumError::invalid_hex)?;
    let k_pub = hex::decode(p.k_pub_hex.expose().trim()).map_err(LithiumError::invalid_hex)?;
    let ed_pub = hex::decode(p.ed_pub_hex.expose().trim()).map_err(LithiumError::invalid_hex)?;
    let dili_pub = hex::decode(p.dili_pub_hex.expose().trim()).map_err(LithiumError::invalid_hex)?;

    if !(cid.len() == 16 || cid.len() == 32) {
        return Err(LithiumError::invalid_len(32, cid.len()));
    }
    if x_pub.len() != 32 || ed_pub.len() != 32 {
        return Err(LithiumError::invalid_len(32, 0));
    }
    if k_pub.len() > u16::MAX as usize || dili_pub.len() > u16::MAX as usize {
        return Err(LithiumError::internal());
    }

    let mut out = Vec::with_capacity(
        4 + 1 + 2 + server_b.len()
            + 1 + cid.len()
            + 32
            + 2 + k_pub.len()
            + 32
            + 2 + dili_pub.len(),
    );

    out.extend_from_slice(INV_MAGIC);
    out.push(INV_VER);

    out.extend_from_slice(&(server_b.len() as u16).to_be_bytes());
    out.extend_from_slice(server_b);

    out.push(cid.len() as u8);
    out.extend_from_slice(&cid);

    out.extend_from_slice(&x_pub);

    out.extend_from_slice(&(k_pub.len() as u16).to_be_bytes());
    out.extend_from_slice(&k_pub);

    out.extend_from_slice(&ed_pub);

    out.extend_from_slice(&(dili_pub.len() as u16).to_be_bytes());
    out.extend_from_slice(&dili_pub);

    Ok(SecretString::new(format!("lci1:{}", hex::encode(out))))
}

pub fn decode_invite_code(code: &SecretString) -> Result<InvitePublic> {
    let s = code.expose().trim();
    let hex_part = s.strip_prefix("lci1:").unwrap_or(s);
    let blob = hex::decode(hex_part).map_err(LithiumError::invalid_hex)?;

    if blob.len() < 4 + 1 + 2 + 1 + 32 + 2 + 32 + 2 {
        return Err(LithiumError::invalid_credentials("invalid_invite_code"));
    }
    if &blob[0..4] != INV_MAGIC || blob[4] != INV_VER {
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

    Ok(InvitePublic {
        server: SecretString::new(server),
        cid_hex: SecretString::new(hex::encode(cid)),
        x_pub_hex: SecretString::new(hex::encode(x_pub)),
        k_pub_hex: SecretString::new(hex::encode(k_pub)),
        ed_pub_hex: SecretString::new(hex::encode(ed_pub)),
        dili_pub_hex: SecretString::new(hex::encode(dili_pub)),
    })
}

pub fn decode_contact_id_hex(s: &SecretString) -> Result<Vec<u8>> {
    let b = hex::decode(s.expose().trim()).map_err(LithiumError::invalid_hex)?;
    if !(b.len() == 16 || b.len() == 32) {
        return Err(LithiumError::invalid_len(32, b.len()));
    }
    Ok(b)
}

pub fn gen_self_state(server: SecretString) -> Result<(Vec<u8>, SecretJson)> {
    let cid: Byte32 = keys::random_32()?;

    let (x_priv, x_pub) = keys::random_x25519_keypair()?;
    let (k_priv, k_pub) = keys::random_kyber_mlkem1024_keypair()?;
    let (ed_priv, ed_pub) = keys::random_ed25519_keypair()?;
    let (dili_priv, dili_pub) = keys::random_dilithium_mldsa87_keypair()?;

    let v = json!({
        "v": 1,
        "server": server.expose(),
        "cid": cid.to_hex().expose(),
        "x_priv": x_priv.to_hex().expose(),
        "x_pub": x_pub.to_hex().expose(),
        "k_priv": k_priv.to_hex().expose(),
        "k_pub": k_pub.to_hex().expose(),
        "ed_priv": ed_priv.to_hex().expose(),
        "ed_pub": ed_pub.to_hex().expose(),
        "dili_priv": dili_priv.to_hex().expose(),
        "dili_pub": dili_pub.to_hex().expose(),
    });

    let bytes = serde_json::to_vec(&v).map_err(LithiumError::json_parse)?;
    let sj = SecretJson::from_vec(bytes)?;
    Ok((cid.as_slice().to_vec(), sj))
}
