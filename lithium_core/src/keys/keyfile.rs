use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::crypto::{aead, keys};
use crate::error::{CryptoErrorKind, LithiumError, Result};
use crate::secrets::bytes::{FixedBytes, SecretBytes};
use crate::secrets::types::{Byte12, Byte32, MasterKey32};

pub const KEYFILE_MAGIC: &[u8; 4] = b"KEYF";
pub const KEYFILE_VERSION: u8 = 1;
pub const ALG_ID_AES256_GCM_SIV: u8 = 1;
pub const DEK_LEN: u16 = 32;

#[inline]
pub fn read_keyfile_bytes(path: &Path) -> Result<SecretBytes> {
    Ok(SecretBytes::from_vec(fs::read(path).map_err(LithiumError::io)?))
}

pub fn write_secure(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(LithiumError::io)?;
    }

    let tmp = path.with_extension("tmp");

    let write_res = (|| -> Result<()> {
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)
            .map_err(LithiumError::io)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(LithiumError::io)?;
        }

        let mut f = f;
        f.write_all(data).map_err(LithiumError::io)?;
        f.sync_all().map_err(LithiumError::io)?;
        Ok(())
    })();

    if let Err(e) = write_res {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    fs::rename(&tmp, path).map_err(LithiumError::io)?;
    Ok(())
}

#[inline]
fn aad_for(version: u8, key_type: &str) -> SecretBytes {
    SecretBytes::from_vec(format!("keyfile:v{}|{}", version, key_type).into_bytes())
}

#[inline]
fn derive_kek(mk: &MasterKey32, salt: &[u8; 32]) -> Result<Byte32> {
    let hk = Hkdf::<Sha256>::new(Some(salt), mk.as_slice());
    let mut out = Byte32::new_zeroed();
    hk.expand(b"kek/v1", out.as_mut_slice())?;
    Ok(out)
}

#[inline]
fn wrap_dek(
    kek: &Byte32,
    dek: &Byte32,
    aad: &SecretBytes,
) -> Result<(Vec<u8>, [u8; 12])> {
    let nonce = keys::random_fixed::<12>()?;
    let ct = aead::encrypt_raw(
        &SecretBytes::from_slice(dek.as_slice()),
        kek,
        &nonce,
        aad,
    )?;

    Ok((ct.as_slice().to_vec(), *nonce.as_array()))
}

#[inline]
fn encrypt_payload(
    dek: &Byte32,
    payload: &[u8],
    aad: &SecretBytes,
) -> Result<(Vec<u8>, [u8; 12])> {
    let nonce = keys::random_fixed::<12>()?;
    let ct = aead::encrypt_raw(
        &SecretBytes::from_slice(payload),
        dek,
        &nonce,
        aad,
    )?;

    Ok((ct.as_slice().to_vec(), *nonce.as_array()))
}

fn build_record(
    version: u8,
    alg_id: u8,
    dek_len: u16,
    salt: &[u8; 32],
    nonce_wrap: &[u8; 12],
    ct_wrap: &[u8],
    nonce_payload: &[u8; 12],
    ct_payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(KEYFILE_MAGIC);
    out.push(version);
    out.push(alg_id);
    out.extend_from_slice(&dek_len.to_be_bytes());

    out.extend_from_slice(&(salt.len() as u16).to_be_bytes());
    out.extend_from_slice(salt);

    out.extend_from_slice(&(nonce_wrap.len() as u16).to_be_bytes());
    out.extend_from_slice(nonce_wrap);

    out.extend_from_slice(&(ct_wrap.len() as u16).to_be_bytes());
    out.extend_from_slice(ct_wrap);

    out.extend_from_slice(&(nonce_payload.len() as u16).to_be_bytes());
    out.extend_from_slice(nonce_payload);

    out.extend_from_slice(&(ct_payload.len() as u32).to_be_bytes());
    out.extend_from_slice(ct_payload);

    out
}

fn read_u16(buf: &[u8], idx: &mut usize) -> Result<u16> {
    if *idx + 2 > buf.len() {
        return Err(LithiumError::new(CryptoErrorKind::InvalidLength {
            expected: *idx + 2,
            got: buf.len(),
        }));
    }
    let v = u16::from_be_bytes([buf[*idx], buf[*idx + 1]]);
    *idx += 2;
    Ok(v)
}

fn read_u32(buf: &[u8], idx: &mut usize) -> Result<u32> {
    if *idx + 4 > buf.len() {
        return Err(LithiumError::new(CryptoErrorKind::InvalidLength {
            expected: *idx + 4,
            got: buf.len(),
        }));
    }
    let v = u32::from_be_bytes([buf[*idx], buf[*idx + 1], buf[*idx + 2], buf[*idx + 3]]);
    *idx += 4;
    Ok(v)
}

fn parse_keyfile(
    buf: &SecretBytes,
) -> Result<(u8, u8, u16, [u8; 32], [u8; 12], Vec<u8>, [u8; 12], Vec<u8>)> {
    let buf = buf.as_slice();
    let mut idx = 0;

    if buf.len() < 8 {
        return Err(LithiumError::invalid_len(8, buf.len()));
    }
    if &buf[0..4] != KEYFILE_MAGIC {
        return Err(LithiumError::internal());
    }

    idx += 4;
    let version = buf[idx];
    idx += 1;
    let alg_id = buf[idx];
    idx += 1;
    let dek_len = u16::from_be_bytes([buf[idx], buf[idx + 1]]);
    idx += 2;

    let len_salt = read_u16(buf, &mut idx)? as usize;
    if len_salt != 32 || idx + 32 > buf.len() {
        return Err(LithiumError::internal());
    }
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&buf[idx..idx + 32]);
    idx += 32;

    let len_nonce_wrap = read_u16(buf, &mut idx)? as usize;
    if len_nonce_wrap != 12 || idx + 12 > buf.len() {
        return Err(LithiumError::internal());
    }
    let mut nonce_wrap = [0u8; 12];
    nonce_wrap.copy_from_slice(&buf[idx..idx + 12]);
    idx += 12;

    let len_ct_wrap = read_u16(buf, &mut idx)? as usize;
    if idx + len_ct_wrap > buf.len() {
        return Err(LithiumError::internal());
    }
    let ct_wrap = buf[idx..idx + len_ct_wrap].to_vec();
    idx += len_ct_wrap;

    let len_nonce_payload = read_u16(buf, &mut idx)? as usize;
    if len_nonce_payload != 12 || idx + 12 > buf.len() {
        return Err(LithiumError::internal());
    }
    let mut nonce_payload = [0u8; 12];
    nonce_payload.copy_from_slice(&buf[idx..idx + 12]);
    idx += 12;

    let len_ct_payload = read_u32(buf, &mut idx)? as usize;
    if idx + len_ct_payload > buf.len() {
        return Err(LithiumError::internal());
    }
    let ct_payload = buf[idx..idx + len_ct_payload].to_vec();

    Ok((
        version,
        alg_id,
        dek_len,
        salt,
        nonce_wrap,
        ct_wrap,
        nonce_payload,
        ct_payload,
    ))
}

fn unwrap_dek(
    mk: &MasterKey32,
    salt: &[u8; 32],
    nonce_wrap: &[u8; 12],
    ct_wrap: &[u8],
    aad: &SecretBytes,
) -> Result<Byte32> {
    let kek = derive_kek(mk, salt)?;
    let nonce = Byte12::from_slice(nonce_wrap)?;
    let dek_bytes = aead::decrypt_raw(
        &SecretBytes::from_slice(ct_wrap),
        &kek,
        &nonce,
        aad,
    )?;
    Byte32::from_slice(dek_bytes.as_slice())
}

fn decrypt_payload_bytes(
    dek: &Byte32,
    nonce_payload: &[u8; 12],
    ct_payload: &[u8],
    aad: &SecretBytes,
) -> Result<SecretBytes> {
    let nonce = Byte12::from_slice(nonce_payload)?;
    aead::decrypt_raw(
        &SecretBytes::from_slice(ct_payload),
        dek,
        &nonce,
        aad,
    )
}

fn decrypt_payload_32(
    dek: &Byte32,
    nonce_payload: &[u8; 12],
    ct_payload: &[u8],
    aad: &SecretBytes,
) -> Result<FixedBytes<32>> {
    let pt = decrypt_payload_bytes(dek, nonce_payload, ct_payload, aad)?;
    FixedBytes::<32>::from_slice(pt.as_slice())
}

pub fn save_secret32_encrypted(
    path: &Path,
    mk: &MasterKey32,
    payload: &FixedBytes<32>,
    key_type: &str,
) -> Result<()> {
    let dek = keys::random_fixed::<32>()?;
    let salt = keys::random_fixed::<32>()?;
    let kek = derive_kek(mk, salt.as_array())?;
    let aad = aad_for(KEYFILE_VERSION, key_type);

    let (ct_wrap, nonce_wrap) = wrap_dek(&kek, &dek, &aad)?;
    let (ct_payload, nonce_payload) = encrypt_payload(&dek, payload.as_slice(), &aad)?;

    let out = build_record(
        KEYFILE_VERSION,
        ALG_ID_AES256_GCM_SIV,
        DEK_LEN,
        salt.as_array(),
        &nonce_wrap,
        &ct_wrap,
        &nonce_payload,
        &ct_payload,
    );

    write_secure(path, &out)?;
    Ok(())
}

pub fn save_bytes_encrypted(
    path: &Path,
    mk: &MasterKey32,
    payload: &[u8],
    key_type: &str,
) -> Result<()> {
    let dek = keys::random_fixed::<32>()?;
    let salt = keys::random_fixed::<32>()?;
    let kek = derive_kek(mk, salt.as_array())?;
    let aad = aad_for(KEYFILE_VERSION, key_type);

    let (ct_wrap, nonce_wrap) = wrap_dek(&kek, &dek, &aad)?;
    let (ct_payload, nonce_payload) = encrypt_payload(&dek, payload, &aad)?;

    let out = build_record(
        KEYFILE_VERSION,
        ALG_ID_AES256_GCM_SIV,
        DEK_LEN,
        salt.as_array(),
        &nonce_wrap,
        &ct_wrap,
        &nonce_payload,
        &ct_payload,
    );

    write_secure(path, &out)?;
    Ok(())
}

pub fn load_secret32_decrypted(
    path: &Path,
    mk: &MasterKey32,
    key_type: &str,
) -> Result<FixedBytes<32>> {
    let buf = read_keyfile_bytes(path)?;
    let (version, alg_id, dek_len, salt, nonce_wrap, ct_wrap, nonce_payload, ct_payload) =
        parse_keyfile(&buf)?;

    if version != KEYFILE_VERSION || alg_id != ALG_ID_AES256_GCM_SIV || dek_len != DEK_LEN {
        return Err(LithiumError::internal());
    }

    let aad = aad_for(version, key_type);
    let dek = unwrap_dek(mk, &salt, &nonce_wrap, &ct_wrap, &aad)?;
    decrypt_payload_32(&dek, &nonce_payload, &ct_payload, &aad)
}

pub fn load_bytes_decrypted(
    path: &Path,
    mk: &MasterKey32,
    key_type: &str,
) -> Result<SecretBytes> {
    let buf = read_keyfile_bytes(path)?;
    let (version, alg_id, dek_len, salt, nonce_wrap, ct_wrap, nonce_payload, ct_payload) =
        parse_keyfile(&buf)?;

    if version != KEYFILE_VERSION || alg_id != ALG_ID_AES256_GCM_SIV || dek_len != DEK_LEN {
        return Err(LithiumError::internal());
    }

    let aad = aad_for(version, key_type);
    let dek = unwrap_dek(mk, &salt, &nonce_wrap, &ct_wrap, &aad)?;
    decrypt_payload_bytes(&dek, &nonce_payload, &ct_payload, &aad)
}

pub fn rewrap_keyfile_dek(
    path: &Path,
    old_mk: &MasterKey32,
    new_mk: &MasterKey32,
    key_type: &str,
) -> Result<()> {
    let buf = read_keyfile_bytes(path)?;
    let (
        version,
        alg_id,
        dek_len,
        mut salt_old,
        mut nonce_wrap_old,
        mut ct_wrap_old,
        nonce_payload,
        ct_payload,
    ) = parse_keyfile(&buf)?;

    if version != KEYFILE_VERSION || alg_id != ALG_ID_AES256_GCM_SIV || dek_len != DEK_LEN {
        return Err(LithiumError::internal());
    }

    let aad = aad_for(version, key_type);
    let dek = unwrap_dek(old_mk, &salt_old, &nonce_wrap_old, &ct_wrap_old, &aad)?;

    let salt_new = keys::random_fixed::<32>()?;
    let kek_new = derive_kek(new_mk, salt_new.as_array())?;
    let (ct_wrap_new, nonce_wrap_new) = wrap_dek(&kek_new, &dek, &aad)?;

    let out = build_record(
        version,
        alg_id,
        dek_len,
        salt_new.as_array(),
        &nonce_wrap_new,
        &ct_wrap_new,
        &nonce_payload,
        &ct_payload,
    );

    write_secure(path, &out)?;

    salt_old.zeroize();
    nonce_wrap_old.zeroize();
    ct_wrap_old.zeroize();

    Ok(())
}