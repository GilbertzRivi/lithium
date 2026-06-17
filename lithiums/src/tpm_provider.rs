// Requires tss-esapi 7.x and libtss2-esys at link time.
// Container must expose /dev/tpmrm0 (resource manager) or /dev/tpm0.
use std::path::PathBuf;

use tss_esapi::{
    Context, TctiNameConf,
    attributes::ObjectAttributesBuilder,
    interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm},
    interface_types::{ecc::EccCurve, resource_handles::Hierarchy, session_handles::AuthSession},
    structures::{
        Digest, EccPoint, KeyedHashScheme, Private, Public, PublicBuilder,
        PublicEccParametersBuilder, PublicKeyedHashParameters, SensitiveData,
        SymmetricDefinitionObject,
    },
    traits::{Marshall, UnMarshall},
};
use zeroize::Zeroizing;

use lithium_core::{
    error::{LithiumError, Result},
    keys::{MkProvider, keyfile},
    secrets::Byte32,
};

const BLOB_MAGIC: &[u8; 8] = b"LTHMTPMS";

pub struct TpmMkProvider {
    sealed_path: PathBuf,
}

impl TpmMkProvider {
    pub fn new(sealed_path: PathBuf) -> Self {
        Self { sealed_path }
    }
}

fn tpm_err(e: tss_esapi::Error) -> LithiumError {
    LithiumError::internal().with_source(e)
}

fn open_ctx() -> Result<Context> {
    let tcti_str =
        std::env::var("LITHIUM_TPM_TCTI").unwrap_or_else(|_| "device:/dev/tpmrm0".to_string());
    let tcti: TctiNameConf = tcti_str.parse().map_err(|_| LithiumError::internal())?;
    Context::new(tcti).map_err(tpm_err)
}

// ECC P-256 restricted decryption key used as sealing parent.
// TPM recreates this key deterministically from the owner seed + this template,
// so we never need to persist it.
fn primary_pub() -> std::result::Result<Public, tss_esapi::Error> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_restricted_decryption_key(
                SymmetricDefinitionObject::AES_128_CFB,
                EccCurve::NistP256,
            )
            .build()?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
}

// KEYEDHASH object with no scheme — stores the 32-byte MK as opaque sealed data.
fn sealing_pub() -> std::result::Result<Public, tss_esapi::Error> {
    let attrs = ObjectAttributesBuilder::new()
        .with_user_with_auth(true)
        .with_no_da(true)
        .build()?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
}

fn tpm_seal(ctx: &mut Context, mk: &Byte32) -> Result<(Vec<u8>, Vec<u8>)> {
    ctx.set_sessions((Some(AuthSession::Password), None, None));

    let primary = ctx
        .create_primary(
            Hierarchy::Owner,
            primary_pub().map_err(tpm_err)?,
            None,
            None,
            None,
            None,
        )
        .map_err(tpm_err)?;

    let sensitive = SensitiveData::try_from(mk.as_slice().to_vec()).map_err(tpm_err)?;
    let result = ctx
        .create(
            primary.key_handle,
            sealing_pub().map_err(tpm_err)?,
            None,
            Some(sensitive),
            None,
            None,
        )
        .map_err(tpm_err)?;

    let pub_bytes = result.out_public.marshall().map_err(tpm_err)?;
    let priv_bytes = result.out_private.value().to_vec();

    Ok((pub_bytes, priv_bytes))
}

fn tpm_unseal(ctx: &mut Context, pub_bytes: &[u8], priv_bytes: &[u8]) -> Result<Byte32> {
    let sealed_pub = Public::unmarshall(pub_bytes).map_err(tpm_err)?;
    let sealed_priv = Private::try_from(priv_bytes.to_vec()).map_err(tpm_err)?;

    ctx.set_sessions((Some(AuthSession::Password), None, None));

    let primary = ctx
        .create_primary(
            Hierarchy::Owner,
            primary_pub().map_err(tpm_err)?,
            None,
            None,
            None,
            None,
        )
        .map_err(tpm_err)?;

    let loaded = ctx
        .load(primary.key_handle, sealed_priv, sealed_pub)
        .map_err(tpm_err)?;

    ctx.set_sessions((Some(AuthSession::Password), None, None));

    let sensitive = ctx.unseal(loaded.into()).map_err(tpm_err)?;

    // Context drops here; transient TPM objects are flushed automatically.
    let mk_bytes = Zeroizing::new(sensitive.value().to_vec());
    Byte32::from_slice(&mk_bytes)
}

fn write_blob(path: &std::path::Path, pub_bytes: &[u8], priv_bytes: &[u8]) -> Result<()> {
    let mut buf = Vec::with_capacity(8 + 4 + pub_bytes.len() + 4 + priv_bytes.len());
    buf.extend_from_slice(BLOB_MAGIC);
    buf.extend_from_slice(&(pub_bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(pub_bytes);
    buf.extend_from_slice(&(priv_bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(priv_bytes);
    keyfile::write_secure(path, &buf)
}

fn read_blob(path: &std::path::Path) -> Result<(Vec<u8>, Vec<u8>)> {
    let data = std::fs::read(path).map_err(LithiumError::io)?;

    if data.len() < 16 || &data[..8] != BLOB_MAGIC {
        return Err(LithiumError::internal());
    }

    let mut i = 8usize;

    if i + 4 > data.len() {
        return Err(LithiumError::internal());
    }
    let pub_len = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize;
    i += 4;

    if i + pub_len > data.len() {
        return Err(LithiumError::internal());
    }
    let pub_bytes = data[i..i + pub_len].to_vec();
    i += pub_len;

    if i + 4 > data.len() {
        return Err(LithiumError::internal());
    }
    let priv_len = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize;
    i += 4;

    if i + priv_len > data.len() {
        return Err(LithiumError::internal());
    }
    let priv_bytes = data[i..i + priv_len].to_vec();

    Ok((pub_bytes, priv_bytes))
}

impl MkProvider for TpmMkProvider {
    fn load_mk(&self) -> Result<Byte32> {
        let (pub_bytes, priv_bytes) = read_blob(&self.sealed_path)?;
        let mut ctx = open_ctx()?;
        tpm_unseal(&mut ctx, &pub_bytes, &priv_bytes)
    }

    fn store_mk(&self, mk: &Byte32) -> Result<()> {
        let mut ctx = open_ctx()?;
        let (pub_bytes, priv_bytes) = tpm_seal(&mut ctx, mk)?;
        write_blob(&self.sealed_path, &pub_bytes, &priv_bytes)
    }
}
